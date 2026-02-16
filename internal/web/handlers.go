package web

import (
	"fmt"
	"html/template"
	"math"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/capture"
	"github.com/darkace1998/FlowLens/internal/geo"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// --- Template helpers ---

var funcMap = template.FuncMap{
	"formatBytes":   formatBytes,
	"formatPkts":    formatPkts,
	"formatBPS":     formatBPS,
	"formatPPS":     formatPPS,
	"protoName":     model.ProtocolName,
	"appProto":      model.AppProtocol,
	"appCategory":   model.AppCategory,
	"asName":        model.ASName,
	"timeAgo":       timeAgo,
	"formatTime":    formatTime,
	"seq":           seq,
	"pageWindow":    pageWindow,
	"add":           func(a, b int) int { return a + b },
	"sub":           func(a, b int) int { return a - b },
	"pctOf":         pctOf,
	"severityClass": severityClass,
	"formatAS":      formatAS,
	"formatJitter":  formatJitter,
	"formatMOS":     formatMOS,
	"int":           func(v interface{}) int {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case uint64:
			return int(n)
		case float64:
			return int(n)
		default:
			return 0
		}
	},
	"uint64": func(v interface{}) uint64 {
		switch n := v.(type) {
		case int:
			return uint64(n)
		case int64:
			return uint64(n)
		case uint64:
			return n
		case float64:
			return uint64(n)
		default:
			return 0
		}
	},
	"gt": func(a, b int) bool { return a > b },
}

func severityClass(sev analysis.Severity) string {
	switch sev {
	case analysis.CRITICAL:
		return "critical"
	case analysis.WARNING:
		return "warning"
	default:
		return "info"
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatPkts(p uint64) string {
	if p < 1000 {
		return fmt.Sprintf("%d", p)
	}
	if p < 1000000 {
		return fmt.Sprintf("%.1fK", float64(p)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(p)/1000000)
}

func formatBPS(bytesTotal uint64, duration time.Duration) string {
	if duration == 0 {
		return "0 bps"
	}
	bps := float64(bytesTotal*8) / duration.Seconds()
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func formatPPS(pktsTotal uint64, duration time.Duration) string {
	if duration == 0 {
		return "0 pps"
	}
	pps := float64(pktsTotal) / duration.Seconds()
	switch {
	case pps >= 1e6:
		return fmt.Sprintf("%.2f Mpps", pps/1e6)
	case pps >= 1e3:
		return fmt.Sprintf("%.2f Kpps", pps/1e3)
	default:
		return fmt.Sprintf("%.0f pps", pps)
	}
}

func formatThroughput(bps float64) string {
	if bps <= 0 {
		return "—"
	}
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func formatRTT(us int64) string {
	if us <= 0 {
		return "—"
	}
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	}
	ms := float64(us) / 1000
	if ms < 1000 {
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.2fs", ms/1000)
}

func formatJitter(us int64) string {
	if us <= 0 {
		return "—"
	}
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	}
	return fmt.Sprintf("%.1fms", float64(us)/1000)
}

func formatMOS(mos float32) string {
	if mos <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f", mos)
}

func mosQuality(mos float32) string {
	switch {
	case mos >= 4.0:
		return "good"
	case mos >= 3.5:
		return "fair"
	case mos >= 3.0:
		return "poor"
	default:
		return "bad"
	}
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

func seq(start, end int) []int {
	var s []int
	for i := start; i <= end; i++ {
		s = append(s, i)
	}
	return s
}

// pageWindow returns a sliding window of page numbers around the current page,
// showing at most 5 pages centered on the current page.
func pageWindow(currentPage, totalPages int) []int {
	const windowSize = 5
	start := currentPage - windowSize/2
	end := start + windowSize - 1

	if start < 1 {
		start = 1
		end = start + windowSize - 1
	}
	if end > totalPages {
		end = totalPages
		start = end - windowSize + 1
		if start < 1 {
			start = 1
		}
	}

	var pages []int
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}
	return pages
}

func pctOf(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(part) / float64(total) * 1000) / 10
}

func formatAS(asn uint32) string {
	name := model.ASName(asn)
	if asn == 0 {
		return name
	}
	return fmt.Sprintf("AS%d (%s)", asn, name)
}

// --- Dashboard data structures ---

// TalkerEntry represents a top talker (source or destination IP).
type TalkerEntry struct {
	IP      string
	Bytes   uint64
	Packets uint64
	Pct     float64
}

// ProtocolEntry represents a protocol's share of traffic.
type ProtocolEntry struct {
	Name    string
	Proto   uint8
	Bytes   uint64
	Packets uint64
	Pct     float64
}

// ASEntry represents an Autonomous System's share of traffic.
type ASEntry struct {
	ASN     uint32
	Name    string
	Bytes   uint64
	Packets uint64
	Pct     float64
}

// AppProtoEntry represents an L7 application protocol's share of traffic.
type AppProtoEntry struct {
	Name    string
	Bytes   uint64
	Packets uint64
	Flows   int
	Pct     float64
}

// CategoryEntry represents a traffic category's share of traffic.
type CategoryEntry struct {
	Name    string
	Bytes   uint64
	Packets uint64
	Flows   int
	Pct     float64
}

// LatencyStats holds percentile-based latency/throughput statistics.
type LatencyStats struct {
	AvgRTT     string
	P50RTT     string
	P95RTT     string
	P99RTT     string
	AvgThru    string
	P50Thru    string
	P95Thru    string
	P99Thru    string
	FlowsWithRTT int
	FlowsWithThru int
}

// TCPHealthStats holds aggregate TCP quality metrics for the dashboard.
type TCPHealthStats struct {
	TotalTCPFlows      int
	FlowsWithRetrans   int
	FlowsWithOOO       int
	FlowsWithLoss      int
	TotalRetrans       uint64
	TotalOOO           uint64
	TotalLoss          uint64
	TotalTCPPackets    uint64
	RetransRate        float64 // percentage of TCP packets that are retransmissions
	OOORate            float64 // percentage of TCP packets that are out-of-order
	LossRate           float64 // percentage of packets lost
	TopRetransFlows    []TCPFlowEntry
}

// TCPFlowEntry is a flow with TCP quality information for the dashboard.
type TCPFlowEntry struct {
	SrcAddr      string
	DstAddr      string
	SrcPort      uint16
	DstPort      uint16
	Retrans      uint32
	OOO          uint32
	Loss         uint32
	Packets      uint64
	RetransRate  float64
}

// VoIPStats holds aggregate VoIP quality metrics for the dashboard.
type VoIPStats struct {
	TotalVoIPFlows int
	FlowsWithJitter int
	FlowsWithMOS    int
	AvgJitter       string
	P50Jitter       string
	P95Jitter       string
	AvgMOS          string
	MinMOS          string
	FlowsBelowMOS35 int     // MOS < 3.5 (poor quality)
	TopVoIPFlows    []VoIPFlowEntry
}

// VoIPFlowEntry is a VoIP flow with quality metrics for the dashboard.
type VoIPFlowEntry struct {
	SrcAddr  string
	DstAddr  string
	SrcPort  uint16
	DstPort  uint16
	Jitter   string
	MOS      string
	MOSVal   float32 // numeric MOS for sorting
	MOSClass string  // "good", "fair", "poor", "bad"
	Loss     uint32
	Packets  uint64
}

// InterfaceEntry represents a network interface's share of traffic.
type InterfaceEntry struct {
	Index   uint32
	Name    string
	Bytes   uint64
	Packets uint64
	Flows   int
	Pct     float64
}

// DashboardData holds all data for the dashboard template.
type DashboardData struct {
	TotalBytes   uint64
	TotalPackets uint64
	BPS          string
	PPS          string
	FlowCount    int
	ActiveFlows  int
	ActiveHosts  int
	Window       time.Duration
	TopSrc       []TalkerEntry
	TopDst       []TalkerEntry
	Protocols    []ProtocolEntry
	TopAS        []ASEntry
	AppProtocols []AppProtoEntry
	Categories   []CategoryEntry
	Latency      LatencyStats
	TCPHealth    TCPHealthStats
	VoIP         VoIPStats
	Interfaces   []InterfaceEntry
	IfaceFilter  string // current interface filter value (from query param)
}

// --- Active Hosts data structures ---

// HostEntry represents a unique host with aggregate traffic statistics.
type HostEntry struct {
	IP        string
	Bytes     uint64
	Packets   uint64
	FlowCount int
	FirstSeen time.Time
	LastSeen  time.Time
	Pct       float64
	Country   string
	City      string
	Lat       float64
	Lon       float64
}

// HostsPageData holds all data for the active hosts template.
type HostsPageData struct {
	Hosts      []HostEntry
	TotalHosts int
	TotalBytes uint64
	Window     time.Duration
}

// --- Dashboard handler ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	flows, err := s.ringBuf.Recent(window, 0)
	if err != nil {
		http.Error(w, "Failed to query flows", http.StatusInternalServerError)
		logging.Default().Error("Dashboard query error: %v", err)
		return
	}

	// Stitch bidirectional flows to compute RTT estimates.
	model.StitchFlows(flows)

	// Apply interface filter if specified.
	ifaceFilter := r.URL.Query().Get("iface")
	if ifaceFilter != "" {
		var filtered []model.Flow
		ifVal, err := strconv.ParseUint(ifaceFilter, 10, 32)
		if err == nil {
			for _, f := range flows {
				if f.InputIface == uint32(ifVal) || f.OutputIface == uint32(ifVal) {
					filtered = append(filtered, f)
				}
			}
			flows = filtered
		} else {
			logging.Default().Warn("Invalid interface filter %q: %v", ifaceFilter, err)
		}
	}

	data := buildDashboardData(flows, window, s.fullCfg.Collector.InterfaceNames)
	data.IfaceFilter = ifaceFilter

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplDashboard.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func buildDashboardData(flows []model.Flow, window time.Duration, ifaceNames map[string]string) DashboardData {
	var totalBytes, totalPkts uint64
	srcMap := make(map[string]*TalkerEntry)
	dstMap := make(map[string]*TalkerEntry)
	protoMap := make(map[uint8]*ProtocolEntry)
	uniqueHosts := make(map[string]struct{})
	asMap := make(map[uint32]*ASEntry)
	appProtoMap := make(map[string]*AppProtoEntry)
	categoryMap := make(map[string]*CategoryEntry)
	ifaceMap := make(map[uint32]*InterfaceEntry)

	now := time.Now()
	activeFlows := 0

	for _, f := range flows {
		totalBytes += f.Bytes
		totalPkts += f.Packets

		src := model.SafeIPString(f.SrcAddr)
		if e, ok := srcMap[src]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			srcMap[src] = &TalkerEntry{IP: src, Bytes: f.Bytes, Packets: f.Packets}
		}

		dst := model.SafeIPString(f.DstAddr)
		if e, ok := dstMap[dst]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			dstMap[dst] = &TalkerEntry{IP: dst, Bytes: f.Bytes, Packets: f.Packets}
		}

		if e, ok := protoMap[f.Protocol]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			protoMap[f.Protocol] = &ProtocolEntry{
				Name:    model.ProtocolName(f.Protocol),
				Proto:   f.Protocol,
				Bytes:   f.Bytes,
				Packets: f.Packets,
			}
		}

		uniqueHosts[src] = struct{}{}
		uniqueHosts[dst] = struct{}{}

		// A flow is "active" if it was seen in the last 60 seconds.
		if now.Sub(f.Timestamp) <= 60*time.Second {
			activeFlows++
		}

		// Aggregate by AS — use destination AS (the target service).
		asn := f.DstAS
		if asn == 0 {
			asn = f.SrcAS
		}
		if e, ok := asMap[asn]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			asMap[asn] = &ASEntry{
				ASN:     asn,
				Name:    model.ASName(asn),
				Bytes:   f.Bytes,
				Packets: f.Packets,
			}
		}

		// Aggregate by L7 application protocol.
		appName := f.AppProto
		if appName == "" {
			appName = model.AppProtocol(f.Protocol, f.SrcPort, f.DstPort)
		}
		if e, ok := appProtoMap[appName]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
			e.Flows++
		} else {
			appProtoMap[appName] = &AppProtoEntry{
				Name:    appName,
				Bytes:   f.Bytes,
				Packets: f.Packets,
				Flows:   1,
			}
		}

		// Aggregate by category.
		catName := f.AppCat
		if catName == "" {
			catName = model.AppCategory(appName)
		}
		if e, ok := categoryMap[catName]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
			e.Flows++
		} else {
			categoryMap[catName] = &CategoryEntry{
				Name:    catName,
				Bytes:   f.Bytes,
				Packets: f.Packets,
				Flows:   1,
			}
		}

		// Aggregate by interface (input and output).
		for _, ifIdx := range []uint32{f.InputIface, f.OutputIface} {
			if ifIdx == 0 {
				continue
			}
			if e, ok := ifaceMap[ifIdx]; ok {
				e.Bytes += f.Bytes
				e.Packets += f.Packets
				e.Flows++
			} else {
				ifaceMap[ifIdx] = &InterfaceEntry{
					Index:   ifIdx,
					Name:    model.InterfaceName(ifIdx, ifaceNames),
					Bytes:   f.Bytes,
					Packets: f.Packets,
					Flows:   1,
				}
			}
		}
	}

	topSrc := topN(srcMap, totalBytes, 10)
	topDst := topN(dstMap, totalBytes, 10)

	var protocols []ProtocolEntry
	for _, e := range protoMap {
		e.Pct = pctOf(e.Bytes, totalBytes)
		protocols = append(protocols, *e)
	}
	sortProtocols(protocols)

	// Build Top AS list (top 10 by bytes).
	topAS := make([]ASEntry, 0, len(asMap))
	for _, e := range asMap {
		e.Pct = pctOf(e.Bytes, totalBytes)
		topAS = append(topAS, *e)
	}
	sort.Slice(topAS, func(i, j int) bool { return topAS[i].Bytes > topAS[j].Bytes })
	if len(topAS) > 10 {
		topAS = topAS[:10]
	}

	// Build L7 application protocol list (sorted by bytes).
	appProtocols := make([]AppProtoEntry, 0, len(appProtoMap))
	for _, e := range appProtoMap {
		e.Pct = pctOf(e.Bytes, totalBytes)
		appProtocols = append(appProtocols, *e)
	}
	sort.Slice(appProtocols, func(i, j int) bool { return appProtocols[i].Bytes > appProtocols[j].Bytes })

	// Build category list (sorted by bytes).
	categories := make([]CategoryEntry, 0, len(categoryMap))
	for _, e := range categoryMap {
		e.Pct = pctOf(e.Bytes, totalBytes)
		categories = append(categories, *e)
	}
	sort.Slice(categories, func(i, j int) bool { return categories[i].Bytes > categories[j].Bytes })

	// Build interface list (sorted by bytes).
	interfaces := make([]InterfaceEntry, 0, len(ifaceMap))
	for _, e := range ifaceMap {
		e.Pct = pctOf(e.Bytes, totalBytes)
		interfaces = append(interfaces, *e)
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Bytes > interfaces[j].Bytes })

	// Compute latency and throughput percentiles.
	latencyStats := computeLatencyStats(flows)

	// Compute TCP quality metrics.
	tcpHealth := computeTCPHealthStats(flows)

	// Compute VoIP quality metrics.
	voipStats := computeVoIPStats(flows)

	return DashboardData{
		TotalBytes:   totalBytes,
		TotalPackets: totalPkts,
		BPS:          formatBPS(totalBytes, window),
		PPS:          formatPPS(totalPkts, window),
		FlowCount:    len(flows),
		ActiveFlows:  activeFlows,
		ActiveHosts:  len(uniqueHosts),
		Window:       window,
		TopSrc:       topSrc,
		TopDst:       topDst,
		Protocols:    protocols,
		TopAS:        topAS,
		AppProtocols: appProtocols,
		Categories:   categories,
		Latency:      latencyStats,
		TCPHealth:    tcpHealth,
		VoIP:         voipStats,
		Interfaces:   interfaces,
	}
}

// computeLatencyStats calculates percentile-based latency/throughput statistics.
func computeLatencyStats(flows []model.Flow) LatencyStats {
	var rttValues []int64
	var thruValues []float64

	for _, f := range flows {
		if f.RTTMicros > 0 {
			rttValues = append(rttValues, f.RTTMicros)
		}
		if f.ThroughputBPS > 0 {
			thruValues = append(thruValues, f.ThroughputBPS)
		}
	}

	stats := LatencyStats{
		FlowsWithRTT:  len(rttValues),
		FlowsWithThru: len(thruValues),
	}

	if len(rttValues) > 0 {
		sort.Slice(rttValues, func(i, j int) bool { return rttValues[i] < rttValues[j] })
		var sum int64
		for _, v := range rttValues {
			sum += v
		}
		stats.AvgRTT = formatRTT(sum / int64(len(rttValues)))
		stats.P50RTT = formatRTT(percentileInt64(rttValues, 50))
		stats.P95RTT = formatRTT(percentileInt64(rttValues, 95))
		stats.P99RTT = formatRTT(percentileInt64(rttValues, 99))
	}

	if len(thruValues) > 0 {
		sort.Float64s(thruValues)
		var sum float64
		for _, v := range thruValues {
			sum += v
		}
		stats.AvgThru = formatThroughput(sum / float64(len(thruValues)))
		stats.P50Thru = formatThroughput(percentileFloat64(thruValues, 50))
		stats.P95Thru = formatThroughput(percentileFloat64(thruValues, 95))
		stats.P99Thru = formatThroughput(percentileFloat64(thruValues, 99))
	}

	return stats
}

func percentileInt64(sorted []int64, pct int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(pct)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func percentileFloat64(sorted []float64, pct int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(pct)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// computeTCPHealthStats computes aggregate TCP quality metrics from flows.
func computeTCPHealthStats(flows []model.Flow) TCPHealthStats {
	stats := TCPHealthStats{}

	type tcpFlowKey struct {
		src, dst         string
		srcPort, dstPort uint16
	}
	type aggStats struct {
		retrans uint32
		ooo     uint32
		loss    uint32
		packets uint64
	}
	agg := make(map[tcpFlowKey]*aggStats)

	for _, f := range flows {
		if f.Protocol != 6 { // TCP only
			continue
		}
		stats.TotalTCPFlows++
		stats.TotalTCPPackets += f.Packets
		stats.TotalRetrans += uint64(f.Retransmissions)
		stats.TotalOOO += uint64(f.OutOfOrder)
		stats.TotalLoss += uint64(f.PacketLoss)

		if f.Retransmissions > 0 {
			stats.FlowsWithRetrans++
		}
		if f.OutOfOrder > 0 {
			stats.FlowsWithOOO++
		}
		if f.PacketLoss > 0 {
			stats.FlowsWithLoss++
		}

		// Aggregate for top-affected flows.
		key := tcpFlowKey{
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
			srcPort: f.SrcPort, dstPort: f.DstPort,
		}
		if a, ok := agg[key]; ok {
			a.retrans += f.Retransmissions
			a.ooo += f.OutOfOrder
			a.loss += f.PacketLoss
			a.packets += f.Packets
		} else {
			agg[key] = &aggStats{
				retrans: f.Retransmissions, ooo: f.OutOfOrder,
				loss: f.PacketLoss, packets: f.Packets,
			}
		}
	}

	if stats.TotalTCPPackets > 0 {
		stats.RetransRate = math.Round(float64(stats.TotalRetrans)/float64(stats.TotalTCPPackets)*10000) / 100
		stats.OOORate = math.Round(float64(stats.TotalOOO)/float64(stats.TotalTCPPackets)*10000) / 100
		total := stats.TotalTCPPackets + uint64(stats.TotalLoss)
		stats.LossRate = math.Round(float64(stats.TotalLoss)/float64(total)*10000) / 100
	}

	// Build top retransmission flows.
	var topFlows []TCPFlowEntry
	for key, a := range agg {
		if a.retrans > 0 || a.ooo > 0 || a.loss > 0 {
			var rr float64
			if a.packets > 0 {
				rr = math.Round(float64(a.retrans)/float64(a.packets)*10000) / 100
			}
			topFlows = append(topFlows, TCPFlowEntry{
				SrcAddr: key.src, DstAddr: key.dst,
				SrcPort: key.srcPort, DstPort: key.dstPort,
				Retrans: a.retrans, OOO: a.ooo, Loss: a.loss,
				Packets: a.packets, RetransRate: rr,
			})
		}
	}
	sort.Slice(topFlows, func(i, j int) bool {
		return topFlows[i].Retrans+topFlows[i].OOO+topFlows[i].Loss >
			topFlows[j].Retrans+topFlows[j].OOO+topFlows[j].Loss
	})
	if len(topFlows) > 10 {
		topFlows = topFlows[:10]
	}
	stats.TopRetransFlows = topFlows

	return stats
}

// computeVoIPStats computes VoIP quality metrics from flows.
func computeVoIPStats(flows []model.Flow) VoIPStats {
	var stats VoIPStats
	var jitterValues []int64
	var mosValues []float32

	type voipKey struct {
		src, dst         string
		srcPort, dstPort uint16
	}
	type voipAgg struct {
		jitterSum   int64
		mosSum      float32
		count       int
		loss        uint32
		packets     uint64
		worstJitter int64
		worstMOS    float32
	}
	agg := make(map[voipKey]*voipAgg)

	for _, f := range flows {
		if !f.IsVoIP() {
			continue
		}
		stats.TotalVoIPFlows++

		mos := f.MOS
		jitter := f.JitterMicros

		// Compute MOS if not already set but we have metrics.
		if mos == 0 && (jitter > 0 || f.RTTMicros > 0 || f.PacketLoss > 0) {
			mos = model.CalcMOS(jitter, f.RTTMicros, f.PacketLossRate())
		}

		if jitter > 0 {
			stats.FlowsWithJitter++
			jitterValues = append(jitterValues, jitter)
		}
		if mos > 0 {
			stats.FlowsWithMOS++
			mosValues = append(mosValues, mos)
			if mos < 3.5 {
				stats.FlowsBelowMOS35++
			}
		}

		key := voipKey{
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
			srcPort: f.SrcPort, dstPort: f.DstPort,
		}
		if a, ok := agg[key]; ok {
			a.jitterSum += jitter
			a.mosSum += mos
			a.count++
			a.loss += f.PacketLoss
			a.packets += f.Packets
			if mos > 0 && (a.worstMOS == 0 || mos < a.worstMOS) {
				a.worstMOS = mos
			}
			if jitter > a.worstJitter {
				a.worstJitter = jitter
			}
		} else {
			agg[key] = &voipAgg{
				jitterSum: jitter, mosSum: mos, count: 1,
				loss: f.PacketLoss, packets: f.Packets,
				worstJitter: jitter, worstMOS: mos,
			}
		}
	}

	// Compute jitter percentiles.
	if len(jitterValues) > 0 {
		sort.Slice(jitterValues, func(i, j int) bool { return jitterValues[i] < jitterValues[j] })
		var sum int64
		for _, v := range jitterValues {
			sum += v
		}
		stats.AvgJitter = formatJitter(sum / int64(len(jitterValues)))
		stats.P50Jitter = formatJitter(percentileInt64(jitterValues, 50))
		stats.P95Jitter = formatJitter(percentileInt64(jitterValues, 95))
	}

	// Compute MOS summary.
	if len(mosValues) > 0 {
		sort.Slice(mosValues, func(i, j int) bool { return mosValues[i] < mosValues[j] })
		var sum float32
		for _, v := range mosValues {
			sum += v
		}
		stats.AvgMOS = formatMOS(sum / float32(len(mosValues)))
		stats.MinMOS = formatMOS(mosValues[0])
	}

	// Build top VoIP flows (sorted by worst MOS first).
	var topFlows []VoIPFlowEntry
	for key, a := range agg {
		avgMOS := float32(0)
		if a.count > 0 && a.mosSum > 0 {
			avgMOS = a.mosSum / float32(a.count)
		}
		avgJitter := int64(0)
		if a.count > 0 && a.jitterSum > 0 {
			avgJitter = a.jitterSum / int64(a.count)
		}
		topFlows = append(topFlows, VoIPFlowEntry{
			SrcAddr:  key.src, DstAddr: key.dst,
			SrcPort:  key.srcPort, DstPort: key.dstPort,
			Jitter:   formatJitter(avgJitter),
			MOS:      formatMOS(avgMOS),
			MOSVal:   avgMOS,
			MOSClass: mosQuality(avgMOS),
			Loss:     a.loss,
			Packets:  a.packets,
		})
	}
	sort.Slice(topFlows, func(i, j int) bool {
		// Worst MOS first; flows without MOS (MOSVal=0) go last.
		if topFlows[i].MOSVal == 0 && topFlows[j].MOSVal > 0 {
			return false
		}
		if topFlows[i].MOSVal > 0 && topFlows[j].MOSVal == 0 {
			return true
		}
		return topFlows[i].MOSVal < topFlows[j].MOSVal
	})
	if len(topFlows) > 10 {
		topFlows = topFlows[:10]
	}
	stats.TopVoIPFlows = topFlows

	return stats
}

func topN(m map[string]*TalkerEntry, totalBytes uint64, n int) []TalkerEntry {
	entries := make([]TalkerEntry, 0, len(m))
	for _, e := range m {
		e.Pct = pctOf(e.Bytes, totalBytes)
		entries = append(entries, *e)
	}
	// Sort descending by bytes.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Bytes > entries[j].Bytes
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func sortProtocols(p []ProtocolEntry) {
	sort.Slice(p, func(i, j int) bool {
		return p[i].Bytes > p[j].Bytes
	})
}

// --- Flow Explorer data structures ---

// FlowRow is a display-friendly representation of a flow record.
type FlowRow struct {
	Timestamp   string
	SrcAddr     string
	DstAddr     string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Bytes       string
	Packets     string
	Duration    string
	TimeAgo     string
	AppProto    string
	AppCategory string
	Throughput  string
	RTT         string
	Retrans     uint32
	OOO         uint32
	Loss        uint32
	Jitter      string
	MOS         string
	MOSClass    string
	SrcCountry  string
	DstCountry  string
}

// FlowsPageData holds all data for the flows explorer template.
type FlowsPageData struct {
	Flows      []FlowRow
	Page       int
	PageSize   int
	TotalFlows int
	TotalPages int
	HasPrev    bool
	HasNext    bool
	// Filter values for form persistence.
	FilterSrcIP    string
	FilterDstIP    string
	FilterPort     string
	FilterProtocol string
}

// --- Flow Explorer handler ---

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize := s.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}

	filterSrcIP := strings.TrimSpace(r.URL.Query().Get("src_ip"))
	filterDstIP := strings.TrimSpace(r.URL.Query().Get("dst_ip"))
	filterPort := strings.TrimSpace(r.URL.Query().Get("port"))
	filterProto := strings.TrimSpace(r.URL.Query().Get("protocol"))

	// Fetch all recent flows from the ring buffer using the configured window.
	recentWindow := s.fullCfg.Storage.RingBufferDuration
	if recentWindow <= 0 {
		recentWindow = 10 * time.Minute
	}
	allFlows, err := s.ringBuf.Recent(recentWindow, 0)
	if err != nil {
		http.Error(w, "Failed to query flows", http.StatusInternalServerError)
		logging.Default().Error("Flows query error: %v", err)
		return
	}

	// Stitch bidirectional flows to compute RTT estimates and throughput.
	model.StitchFlows(allFlows)

	// Apply filters.
	filtered := filterFlows(allFlows, filterSrcIP, filterDstIP, filterPort, filterProto)

	totalFlows := len(filtered)
	totalPages := (totalFlows + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > totalFlows {
		end = totalFlows
	}

	var pageFlows []FlowRow
	for _, f := range filtered[start:end] {
		appProto := f.AppProto
		appCat := f.AppCat
		// Fallback for flows without pre-computed classification.
		if appProto == "" {
			appProto = model.AppProtocol(f.Protocol, f.SrcPort, f.DstPort)
			appCat = model.AppCategory(appProto)
		}
		srcAddr := model.SafeIPString(f.SrcAddr)
		dstAddr := model.SafeIPString(f.DstAddr)
		var srcCountry, dstCountry string
		if s.geoLookup != nil {
			srcCountry = s.geoLookup.Find(srcAddr).Country
			dstCountry = s.geoLookup.Find(dstAddr).Country
		}
		pageFlows = append(pageFlows, FlowRow{
			Timestamp:   f.Timestamp.Format("15:04:05"),
			SrcAddr:     srcAddr,
			DstAddr:     dstAddr,
			SrcPort:     f.SrcPort,
			DstPort:     f.DstPort,
			Protocol:    model.ProtocolName(f.Protocol),
			Bytes:       formatBytes(f.Bytes),
			Packets:     formatPkts(f.Packets),
			Duration:    f.Duration.String(),
			TimeAgo:     timeAgo(f.Timestamp),
			AppProto:    appProto,
			AppCategory: appCat,
			Throughput:  formatThroughput(f.ThroughputBPS),
			RTT:         formatRTT(f.RTTMicros),
			Retrans:     f.Retransmissions,
			OOO:         f.OutOfOrder,
			Loss:        f.PacketLoss,
			Jitter:      formatJitter(f.JitterMicros),
			MOS:         formatMOS(f.MOS),
			MOSClass:    mosQuality(f.MOS),
			SrcCountry:  srcCountry,
			DstCountry:  dstCountry,
		})
	}

	data := FlowsPageData{
		Flows:          pageFlows,
		Page:           page,
		PageSize:       pageSize,
		TotalFlows:     totalFlows,
		TotalPages:     totalPages,
		HasPrev:        page > 1,
		HasNext:        page < totalPages,
		FilterSrcIP:    filterSrcIP,
		FilterDstIP:    filterDstIP,
		FilterPort:     filterPort,
		FilterProtocol: filterProto,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplFlows.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func filterFlows(flows []model.Flow, srcIP, dstIP, port, proto string) []model.Flow {
	if srcIP == "" && dstIP == "" && port == "" && proto == "" {
		return flows
	}

	var portNum uint16
	if port != "" {
		p, err := strconv.ParseUint(port, 10, 16)
		if err == nil {
			portNum = uint16(p)
		}
	}

	var protoNum uint8
	if proto != "" {
		switch strings.ToLower(proto) {
		case "tcp", "6":
			protoNum = 6
		case "udp", "17":
			protoNum = 17
		case "icmp", "1":
			protoNum = 1
		default:
			p, err := strconv.ParseUint(proto, 10, 8)
			if err == nil {
				protoNum = uint8(p)
			}
		}
	}

	var result []model.Flow
	for _, f := range flows {
		if srcIP != "" && !matchIP(f.SrcAddr, srcIP) {
			continue
		}
		if dstIP != "" && !matchIP(f.DstAddr, dstIP) {
			continue
		}
		if port != "" && f.SrcPort != portNum && f.DstPort != portNum {
			continue
		}
		if proto != "" && f.Protocol != protoNum {
			continue
		}
		result = append(result, f)
	}
	return result
}

func matchIP(ip net.IP, filter string) bool {
	if ip == nil {
		return false
	}
	// Support prefix matching (e.g. "10.0.1")
	return strings.HasPrefix(ip.String(), filter)
}

// --- Active Hosts handler ---

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	flows, err := s.ringBuf.Recent(window, 0)
	if err != nil {
		http.Error(w, "Failed to query flows", http.StatusInternalServerError)
		logging.Default().Error("Hosts query error: %v", err)
		return
	}

	data := buildHostsData(flows, window, s.geoLookup)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplHosts.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func buildHostsData(flows []model.Flow, window time.Duration, geoLookup *geo.Lookup) HostsPageData {
	type hostAccum struct {
		Bytes     uint64
		Packets   uint64
		FlowCount int
		FirstSeen time.Time
		LastSeen  time.Time
	}

	hostMap := make(map[string]*hostAccum)
	var totalBytes uint64

	for _, f := range flows {
		totalBytes += f.Bytes

		// Track both source and destination as active hosts.
		for _, ip := range []string{model.SafeIPString(f.SrcAddr), model.SafeIPString(f.DstAddr)} {
			if h, ok := hostMap[ip]; ok {
				h.Bytes += f.Bytes
				h.Packets += f.Packets
				h.FlowCount++
				if f.Timestamp.Before(h.FirstSeen) {
					h.FirstSeen = f.Timestamp
				}
				if f.Timestamp.After(h.LastSeen) {
					h.LastSeen = f.Timestamp
				}
			} else {
				hostMap[ip] = &hostAccum{
					Bytes:     f.Bytes,
					Packets:   f.Packets,
					FlowCount: 1,
					FirstSeen: f.Timestamp,
					LastSeen:  f.Timestamp,
				}
			}
		}
	}

	hosts := make([]HostEntry, 0, len(hostMap))
	var totalHostBytes uint64
	for _, h := range hostMap {
		totalHostBytes += h.Bytes
	}
	for ip, h := range hostMap {
		entry := HostEntry{
			IP:        ip,
			Bytes:     h.Bytes,
			Packets:   h.Packets,
			FlowCount: h.FlowCount,
			FirstSeen: h.FirstSeen,
			LastSeen:  h.LastSeen,
			Pct:       pctOf(h.Bytes, totalHostBytes),
		}
		if geoLookup != nil {
			info := geoLookup.Find(ip)
			entry.Country = info.Country
			entry.City = info.City
			entry.Lat = info.Latitude
			entry.Lon = info.Longitude
		}
		hosts = append(hosts, entry)
	}

	// Sort descending by bytes.
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Bytes > hosts[j].Bytes
	})

	return HostsPageData{
		Hosts:      hosts,
		TotalHosts: len(hosts),
		TotalBytes: totalBytes,
		Window:     window,
	}
}

// --- Geo Map page ---

// MapMarker represents a host marker on the geo map.
type MapMarker struct {
	IP      string  `json:"ip"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	Bytes   uint64  `json:"bytes"`
	Label   string  `json:"label"`
}

// MapPageData holds all data for the geo map template.
type MapPageData struct {
	Markers     []MapMarker
	TotalHosts  int
	MappedHosts int
}

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	flows, err := s.ringBuf.Recent(window, 0)
	if err != nil {
		http.Error(w, "Failed to query flows", http.StatusInternalServerError)
		logging.Default().Error("Map query error: %v", err)
		return
	}

	data := s.buildMapData(flows)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplMap.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func (s *Server) buildMapData(flows []model.Flow) MapPageData {
	// Collect unique hosts with byte counts.
	hostBytes := make(map[string]uint64)
	for _, f := range flows {
		for _, ip := range []string{model.SafeIPString(f.SrcAddr), model.SafeIPString(f.DstAddr)} {
			hostBytes[ip] += f.Bytes
		}
	}

	var markers []MapMarker
	for ip, bytes := range hostBytes {
		if s.geoLookup == nil {
			continue
		}
		info := s.geoLookup.Find(ip)
		if info.Country == "" || info.Country == "LAN" || (info.Latitude == 0 && info.Longitude == 0) {
			continue
		}
		markers = append(markers, MapMarker{
			IP:      ip,
			Lat:     info.Latitude,
			Lon:     info.Longitude,
			Country: info.Country,
			City:    info.City,
			Bytes:   bytes,
			Label:   fmt.Sprintf("%s (%s, %s) — %s", ip, info.City, info.Country, formatBytes(bytes)),
		})
	}

	// Sort by bytes descending.
	sort.Slice(markers, func(i, j int) bool {
		return markers[i].Bytes > markers[j].Bytes
	})

	return MapPageData{
		Markers:     markers,
		TotalHosts:  len(hostBytes),
		MappedHosts: len(markers),
	}
}

// --- Reports page ---

// ReportPageData holds all data for the reports template.
type ReportPageData struct {
	// Form values for persistence.
	StartTime  string
	EndTime    string
	GroupBy    string
	Metric     string

	// Results.
	Rows       []storage.ReportRow
	TimeSeries []storage.TimeSeriesPoint
	HasResults bool
	TotalBytes uint64
	TotalPkts  uint64
	TotalFlows int64
	Error      string
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	defaultStart := now.Add(-1 * time.Hour).Format("2006-01-02T15:04")
	defaultEnd := now.Format("2006-01-02T15:04")

	data := ReportPageData{
		StartTime: defaultStart,
		EndTime:   defaultEnd,
		GroupBy:   "app_proto",
		Metric:    "bytes",
	}

	// If no query parameters, just show the form.
	q := r.URL.Query()
	if q.Get("start") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.tmplReports.ExecuteTemplate(w, "layout", data); err != nil {
			logging.Default().Error("Template execute error: %v", err)
		}
		return
	}

	// Parse form inputs.
	data.StartTime = q.Get("start")
	data.EndTime = q.Get("end")
	data.GroupBy = q.Get("group_by")
	data.Metric = q.Get("metric")

	if data.GroupBy == "" {
		data.GroupBy = "app_proto"
	}
	if data.Metric == "" {
		data.Metric = "bytes"
	}

	startTime, err := time.Parse("2006-01-02T15:04", data.StartTime)
	if err != nil {
		data.Error = "Invalid start time format"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.tmplReports.ExecuteTemplate(w, "layout", data)
		return
	}
	endTime, err := time.Parse("2006-01-02T15:04", data.EndTime)
	if err != nil {
		data.Error = "Invalid end time format"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.tmplReports.ExecuteTemplate(w, "layout", data)
		return
	}

	if s.sqlStore == nil {
		data.Error = "SQLite store not configured"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.tmplReports.ExecuteTemplate(w, "layout", data)
		return
	}

	// Run aggregate query.
	rows, err := s.sqlStore.QueryReport(startTime, endTime, data.GroupBy)
	if err != nil {
		data.Error = fmt.Sprintf("Report query failed: %v", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.tmplReports.ExecuteTemplate(w, "layout", data)
		return
	}

	// Run time-series query — auto-select bucket size.
	dur := endTime.Sub(startTime)
	bucketSec := chooseBucket(dur)
	ts, err := s.sqlStore.QueryTimeSeries(startTime, endTime, bucketSec)
	if err != nil {
		logging.Default().Warn("Time-series query failed: %v", err)
	}

	var totalB, totalP uint64
	var totalF int64
	for _, row := range rows {
		totalB += row.TotalBytes
		totalP += row.TotalPackets
		totalF += row.FlowCount
	}

	data.Rows = rows
	data.TimeSeries = ts
	data.HasResults = len(rows) > 0
	data.TotalBytes = totalB
	data.TotalPkts = totalP
	data.TotalFlows = totalF

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplReports.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

// chooseBucket picks an appropriate time-series bucket width based on the range.
func chooseBucket(d time.Duration) int {
	switch {
	case d <= 1*time.Hour:
		return 60 // 1-minute buckets
	case d <= 6*time.Hour:
		return 300 // 5-minute buckets
	case d <= 24*time.Hour:
		return 900 // 15-minute buckets
	case d <= 7*24*time.Hour:
		return 3600 // 1-hour buckets
	default:
		return 86400 // 1-day buckets
	}
}

// --- Reports export (CSV / JSON) ---

func (s *Server) handleReportsExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}

	startTime, err := time.Parse("2006-01-02T15:04", q.Get("start"))
	if err != nil {
		http.Error(w, "Invalid start time", http.StatusBadRequest)
		return
	}
	endTime, err := time.Parse("2006-01-02T15:04", q.Get("end"))
	if err != nil {
		http.Error(w, "Invalid end time", http.StatusBadRequest)
		return
	}

	groupBy := q.Get("group_by")
	if groupBy == "" {
		groupBy = "app_proto"
	}

	if s.sqlStore == nil {
		http.Error(w, "SQLite store not configured", http.StatusInternalServerError)
		return
	}

	rows, err := s.sqlStore.QueryReport(startTime, endTime, groupBy)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query failed: %v", err), http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=flowlens-report.json")
		fmt.Fprint(w, "[")
		for i, row := range rows {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"group":%q,"bytes":%d,"packets":%d,"flows":%d,"avg_bytes":%.1f}`,
				row.GroupKey, row.TotalBytes, row.TotalPackets, row.FlowCount, row.AvgBytes)
		}
		fmt.Fprint(w, "]")
	default: // CSV
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=flowlens-report.csv")
		fmt.Fprintf(w, "%s,bytes,packets,flows,avg_bytes\n", groupBy)
		for _, row := range rows {
			fmt.Fprintf(w, "%s,%d,%d,%d,%.1f\n",
				row.GroupKey, row.TotalBytes, row.TotalPackets, row.FlowCount, row.AvgBytes)
		}
	}
}

// --- Advisories page ---

// AdvisoriesPageData holds data for the advisories template.
type AdvisoriesPageData struct {
	Advisories []analysis.Advisory
}

func (s *Server) handleAdvisories(w http.ResponseWriter, r *http.Request) {
	var advisories []analysis.Advisory
	if s.engine != nil {
		advisories = s.engine.Advisories()
	}

	data := AdvisoriesPageData{
		Advisories: advisories,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplAdvisories.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

// --- About / Status page ---

// AboutPageData holds data for the About/Status page template.
type AboutPageData struct {
	Version       string
	Uptime        string
	GoVersion     string
	NumGoroutines int
	MemAllocMB    float64
	MemSysMB      float64
	NumCPU        int

	// Config values
	NetFlowPort      int
	IPFIXPort        int
	BufferSize       int
	RingBufferDur    string
	SQLitePath       string
	SQLiteRetention  string
	PruneInterval    string
	AnalysisInterval string
	TopTalkersCount  int
	BaselineWindow   string
	ScanThreshold    int
	WebListen        string
	PageSize         int
	FlowCount        int
}

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(s.startTime)
	uptimeStr := formatUptime(uptime)

	data := AboutPageData{
		Version:       s.version,
		Uptime:        uptimeStr,
		GoVersion:     runtime.Version(),
		NumGoroutines: runtime.NumGoroutine(),
		MemAllocMB:    float64(memStats.Alloc) / 1024 / 1024,
		MemSysMB:      float64(memStats.Sys) / 1024 / 1024,
		NumCPU:        runtime.NumCPU(),

		NetFlowPort:      s.fullCfg.Collector.NetFlowPort,
		IPFIXPort:        s.fullCfg.Collector.IPFIXPort,
		BufferSize:       s.fullCfg.Collector.BufferSize,
		RingBufferDur:    s.fullCfg.Storage.RingBufferDuration.String(),
		SQLitePath:       s.fullCfg.Storage.SQLitePath,
		SQLiteRetention:  s.fullCfg.Storage.SQLiteRetention.String(),
		PruneInterval:    s.fullCfg.Storage.PruneInterval.String(),
		AnalysisInterval: s.fullCfg.Analysis.Interval.String(),
		TopTalkersCount:  s.fullCfg.Analysis.TopTalkersCount,
		BaselineWindow:   s.fullCfg.Analysis.AnomalyBaselineWindow.String(),
		ScanThreshold:    s.fullCfg.Analysis.ScanThreshold,
		WebListen:        s.fullCfg.Web.Listen,
		PageSize:         s.fullCfg.Web.PageSize,
		FlowCount:        s.ringBuf.Len(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplAbout.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, mins, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

// --- Capture handlers ---

// CapturePageData holds data for the capture page template.
type CapturePageData struct {
	Interfaces []string
	Sessions   []capture.Session
	Files      []capture.PcapFileInfo
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	data := CapturePageData{}

	if s.captureMgr != nil {
		data.Interfaces = s.captureMgr.Interfaces()
		data.Sessions = s.captureMgr.Sessions()
		files, err := s.captureMgr.PcapFiles()
		if err != nil {
			logging.Default().Warn("Failed to list PCAP files: %v", err)
		}
		data.Files = files
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplCapture.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.captureMgr == nil {
		http.Error(w, "Capture not configured", http.StatusServiceUnavailable)
		return
	}

	device := r.FormValue("device")
	bpf := r.FormValue("bpf")

	if device == "" {
		http.Error(w, "Device is required", http.StatusBadRequest)
		return
	}

	_, err := s.captureMgr.Start(device, bpf)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to start capture: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/capture", http.StatusSeeOther)
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.captureMgr == nil {
		http.Error(w, "Capture not configured", http.StatusServiceUnavailable)
		return
	}

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "Session ID is required", http.StatusBadRequest)
		return
	}

	if err := s.captureMgr.Stop(id); err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop capture: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/capture", http.StatusSeeOther)
}

func (s *Server) handleCaptureDownload(w http.ResponseWriter, r *http.Request) {
	if s.captureMgr == nil {
		http.Error(w, "Capture not configured", http.StatusServiceUnavailable)
		return
	}

	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "File parameter is required", http.StatusBadRequest)
		return
	}

	path, err := s.captureMgr.PcapFilePath(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeFile(w, r, path)
}
