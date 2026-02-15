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
	Window       time.Duration
	TopSrc       []TalkerEntry
	TopDst       []TalkerEntry
	Protocols    []ProtocolEntry
}

// --- Dashboard handler ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	window := 10 * time.Minute
	flows, err := s.ringBuf.Recent(window, 0)
	if err != nil {
		http.Error(w, "Failed to query flows", http.StatusInternalServerError)
		logging.Default().Error("Dashboard query error: %v", err)
		return
	}

	data := buildDashboardData(flows, window)

	tmpl, err := template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/dashboard.xhtml")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		logging.Default().Error("Template parse error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		logging.Default().Error("Template execute error: %v", err)
	}
}

func buildDashboardData(flows []model.Flow, window time.Duration) DashboardData {
	var totalBytes, totalPkts uint64
	srcMap := make(map[string]*TalkerEntry)
	dstMap := make(map[string]*TalkerEntry)
	protoMap := make(map[uint8]*ProtocolEntry)

	for _, f := range flows {
		totalBytes += f.Bytes
		totalPkts += f.Packets

		src := f.SrcAddr.String()
		if e, ok := srcMap[src]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			srcMap[src] = &TalkerEntry{IP: src, Bytes: f.Bytes, Packets: f.Packets}
		}

		dst := f.DstAddr.String()
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

	// Fetch all recent flows from the ring buffer (last 10 minutes).
	allFlows, err := s.ringBuf.Recent(10*time.Minute, 0)
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
			SrcAddr:   f.SrcAddr.String(),
			DstAddr:   f.DstAddr.String(),
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

	tmpl, err := template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/flows.xhtml")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		logging.Default().Error("Template parse error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
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
	// Support prefix matching (e.g. "10.0.1")
	return strings.HasPrefix(ip.String(), filter)
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

	tmpl, err := template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/advisories.xhtml")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		logging.Default().Error("Template parse error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
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

	tmpl, err := template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/about.xhtml")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		logging.Default().Error("Template parse error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
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
