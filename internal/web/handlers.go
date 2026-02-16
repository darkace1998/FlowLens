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
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
)

// --- Template helpers ---

var funcMap = template.FuncMap{
	"formatBytes":   formatBytes,
	"formatPkts":    formatPkts,
	"formatBPS":     formatBPS,
	"formatPPS":     formatPPS,
	"protoName":     model.ProtocolName,
	"timeAgo":       timeAgo,
	"formatTime":    formatTime,
	"seq":           seq,
	"pageWindow":    pageWindow,
	"add":           func(a, b int) int { return a + b },
	"sub":           func(a, b int) int { return a - b },
	"pctOf":         pctOf,
	"severityClass": severityClass,
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

	data := buildDashboardData(flows, window)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplDashboard.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func buildDashboardData(flows []model.Flow, window time.Duration) DashboardData {
	var totalBytes, totalPkts uint64
	srcMap := make(map[string]*TalkerEntry)
	dstMap := make(map[string]*TalkerEntry)
	protoMap := make(map[uint8]*ProtocolEntry)
	uniqueHosts := make(map[string]struct{})

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
	}

	topSrc := topN(srcMap, totalBytes, 10)
	topDst := topN(dstMap, totalBytes, 10)

	var protocols []ProtocolEntry
	for _, e := range protoMap {
		e.Pct = pctOf(e.Bytes, totalBytes)
		protocols = append(protocols, *e)
	}
	sortProtocols(protocols)

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
	}
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
	Timestamp string
	SrcAddr   string
	DstAddr   string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Bytes     string
	Packets   string
	Duration  string
	TimeAgo   string
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
		pageFlows = append(pageFlows, FlowRow{
			Timestamp: f.Timestamp.Format("15:04:05"),
			SrcAddr:   model.SafeIPString(f.SrcAddr),
			DstAddr:   model.SafeIPString(f.DstAddr),
			SrcPort:   f.SrcPort,
			DstPort:   f.DstPort,
			Protocol:  model.ProtocolName(f.Protocol),
			Bytes:     formatBytes(f.Bytes),
			Packets:   formatPkts(f.Packets),
			Duration:  f.Duration.String(),
			TimeAgo:   timeAgo(f.Timestamp),
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

	data := buildHostsData(flows, window)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplHosts.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func buildHostsData(flows []model.Flow, window time.Duration) HostsPageData {
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
		hosts = append(hosts, HostEntry{
			IP:        ip,
			Bytes:     h.Bytes,
			Packets:   h.Packets,
			FlowCount: h.FlowCount,
			FirstSeen: h.FirstSeen,
			LastSeen:  h.LastSeen,
			Pct:       pctOf(h.Bytes, totalHostBytes),
		})
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
