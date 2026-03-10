package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
)

// --- JSON API response types ---

// APIFlowsResponse is the JSON response for GET /api/flows.
type APIFlowsResponse struct {
	Page       int        `json:"page"`
	TotalPages int        `json:"total_pages"`
	TotalFlows int        `json:"total_flows"`
	Flows      []APIFlow  `json:"flows"`
}

// APIFlow is a single flow record in the JSON API.
type APIFlow struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcAddr     string    `json:"src_addr"`
	DstAddr     string    `json:"dst_addr"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	Bytes       uint64    `json:"bytes"`
	Packets     uint64    `json:"packets"`
	Duration    string    `json:"duration"`
	AppProto    string    `json:"app_proto"`
	AppCategory string    `json:"app_category"`
}

// APIHostsResponse is the JSON response for GET /api/hosts.
type APIHostsResponse struct {
	TotalHosts int        `json:"total_hosts"`
	TotalBytes uint64     `json:"total_bytes"`
	Hosts      []APIHost  `json:"hosts"`
}

// APIHost is a single host record in the JSON API.
type APIHost struct {
	IP        string    `json:"ip"`
	Bytes     uint64    `json:"bytes"`
	Packets   uint64    `json:"packets"`
	FlowCount int       `json:"flow_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Pct       float64   `json:"pct"`
	Country   string    `json:"country"`
}

// APISessionsResponse is the JSON response for GET /api/sessions.
type APISessionsResponse struct {
	TotalSessions int          `json:"total_sessions"`
	TotalBytes    uint64       `json:"total_bytes"`
	TotalPackets  uint64       `json:"total_packets"`
	Sessions      []APISession `json:"sessions"`
}

// APISession is a single bidirectional session in the JSON API.
type APISession struct {
	SrcAddr    string    `json:"src_addr"`
	DstAddr    string    `json:"dst_addr"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	Bytes      uint64    `json:"bytes"`
	Packets    uint64    `json:"packets"`
	FlowCount  int       `json:"flow_count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Duration   string    `json:"duration"`
	Throughput string    `json:"throughput"`
	AppProto   string    `json:"app_proto"`
	Retrans    uint32    `json:"retrans"`
	OOO        uint32    `json:"ooo"`
	Loss       uint32    `json:"loss"`
	TCPFlags   string    `json:"tcp_flags"`
}

// APIAdvisoriesResponse is the JSON response for GET /api/advisories.
type APIAdvisoriesResponse struct {
	Advisories []APIAdvisory `json:"advisories"`
}

// APIAdvisory is a single advisory in the JSON API.
type APIAdvisory struct {
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Action      string    `json:"action"`
	Resolved    bool      `json:"resolved"`
}

// APIDashboardResponse is the JSON response for GET /api/dashboard.
type APIDashboardResponse struct {
	TotalBytes   uint64             `json:"total_bytes"`
	TotalPackets uint64             `json:"total_packets"`
	BPS          string             `json:"bps"`
	PPS          string             `json:"pps"`
	FlowCount    int                `json:"flow_count"`
	ActiveFlows  int                `json:"active_flows"`
	ActiveHosts  int                `json:"active_hosts"`
	Window       string             `json:"window"`
	TopSrc       []APITalkerEntry   `json:"top_src"`
	TopDst       []APITalkerEntry   `json:"top_dst"`
	Protocols    []APIProtocolEntry `json:"protocols"`
}

// APITalkerEntry is a top-talker entry in the dashboard API.
type APITalkerEntry struct {
	IP      string  `json:"ip"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Pct     float64 `json:"pct"`
}

// APIProtocolEntry is a protocol breakdown entry in the dashboard API.
type APIProtocolEntry struct {
	Name    string  `json:"name"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Pct     float64 `json:"pct"`
}

// --- JSON helper ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logging.Default().Error("JSON encode error: %v", err)
	}
}

// --- API Handlers ---

func (s *Server) handleAPIFlows(w http.ResponseWriter, r *http.Request) {
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
	filterIP := strings.TrimSpace(r.URL.Query().Get("ip"))

	recentWindow := s.fullCfg.Storage.RingBufferDuration
	if recentWindow <= 0 {
		recentWindow = 10 * time.Minute
	}
	allFlows, err := s.flowSvc.RecentFlows(recentWindow, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Error("API flows query error: %v", err)
		return
	}

	model.StitchFlows(allFlows)
	filtered := filterFlows(allFlows, filterSrcIP, filterDstIP, filterPort, filterProto, filterIP)

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

	flows := make([]APIFlow, 0, end-start)
	for _, f := range filtered[start:end] {
		appProto := f.AppProto
		appCat := f.AppCat
		if appProto == "" {
			appProto = model.AppProtocol(f.Protocol, f.SrcPort, f.DstPort)
			appCat = model.AppCategory(appProto)
		}
		flows = append(flows, APIFlow{
			Timestamp:   f.Timestamp,
			SrcAddr:     model.SafeIPString(f.SrcAddr),
			DstAddr:     model.SafeIPString(f.DstAddr),
			SrcPort:     f.SrcPort,
			DstPort:     f.DstPort,
			Protocol:    model.ProtocolName(f.Protocol),
			Bytes:       f.Bytes,
			Packets:     f.Packets,
			Duration:    f.Duration.String(),
			AppProto:    appProto,
			AppCategory: appCat,
		})
	}

	writeJSON(w, http.StatusOK, APIFlowsResponse{
		Page:       page,
		TotalPages: totalPages,
		TotalFlows: totalFlows,
		Flows:      flows,
	})
}

func (s *Server) handleAPIHosts(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	flows, err := s.flowSvc.RecentFlows(window, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Error("API hosts query error: %v", err)
		return
	}

	data := buildHostsData(flows, window, s.geoLookup)

	hosts := make([]APIHost, 0, len(data.Hosts))
	for _, h := range data.Hosts {
		hosts = append(hosts, APIHost{
			IP:        h.IP,
			Bytes:     h.Bytes,
			Packets:   h.Packets,
			FlowCount: h.FlowCount,
			FirstSeen: h.FirstSeen,
			LastSeen:  h.LastSeen,
			Pct:       h.Pct,
			Country:   h.Country,
		})
	}

	writeJSON(w, http.StatusOK, APIHostsResponse{
		TotalHosts: data.TotalHosts,
		TotalBytes: data.TotalBytes,
		Hosts:      hosts,
	})
}

func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = time.Hour
	}

	all, err := s.flowSvc.RecentFlows(window, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Warn("API sessions: ring buffer query error: %v", err)
		return
	}

	// Aggregate bidirectional sessions using the same logic as handleSessions.
	type sessKey struct {
		lo, hi         string
		loPort, hiPort uint16
		proto          uint8
	}
	type sessAgg struct {
		srcAddr, dstAddr string
		srcPort, dstPort uint16
		proto            uint8
		bytes, packets   uint64
		flowCount        int
		first, last      time.Time
		retrans, ooo, loss uint32
		appProto         string
		tcpFlags         uint8
	}

	agg := make(map[sessKey]*sessAgg)

	for _, f := range all {
		src := model.SafeIPString(f.SrcAddr)
		dst := model.SafeIPString(f.DstAddr)
		lo, hi := src, dst
		loPort, hiPort := f.SrcPort, f.DstPort
		if lo > hi || (lo == hi && loPort > hiPort) {
			lo, hi = hi, lo
			loPort, hiPort = hiPort, loPort
		}
		k := sessKey{lo: lo, hi: hi, loPort: loPort, hiPort: hiPort, proto: f.Protocol}

		if a, ok := agg[k]; ok {
			a.bytes += f.Bytes
			a.packets += f.Packets
			a.flowCount++
			a.retrans += f.Retransmissions
			a.ooo += f.OutOfOrder
			a.loss += f.PacketLoss
			a.tcpFlags |= f.TCPFlags
			flowStart := f.Timestamp
			if f.Duration > 0 {
				flowStart = f.Timestamp.Add(-f.Duration)
			}
			if flowStart.Before(a.first) {
				a.first = flowStart
			}
			if f.Timestamp.After(a.last) {
				a.last = f.Timestamp
			}
		} else {
			flowStart := f.Timestamp
			if f.Duration > 0 {
				flowStart = f.Timestamp.Add(-f.Duration)
			}
			agg[k] = &sessAgg{
				srcAddr: src, dstAddr: dst,
				srcPort: f.SrcPort, dstPort: f.DstPort,
				proto: f.Protocol, bytes: f.Bytes, packets: f.Packets,
				flowCount: 1, first: flowStart, last: f.Timestamp,
				retrans: f.Retransmissions, ooo: f.OutOfOrder, loss: f.PacketLoss,
				appProto: model.AppProtocol(f.Protocol, f.SrcPort, f.DstPort),
				tcpFlags: f.TCPFlags,
			}
		}
	}

	sessions := make([]APISession, 0, len(agg))
	var totalBytes, totalPackets uint64

	for _, a := range agg {
		dur := a.last.Sub(a.first)
		var thru string
		if dur > 0 {
			thru = formatBPS(a.bytes, dur)
		}
		sessions = append(sessions, APISession{
			SrcAddr:    a.srcAddr,
			DstAddr:    a.dstAddr,
			SrcPort:    a.srcPort,
			DstPort:    a.dstPort,
			Protocol:   model.ProtocolName(a.proto),
			Bytes:      a.bytes,
			Packets:    a.packets,
			FlowCount:  a.flowCount,
			FirstSeen:  a.first,
			LastSeen:   a.last,
			Duration:   formatUptime(dur),
			Throughput: thru,
			AppProto:   a.appProto,
			Retrans:    a.retrans,
			OOO:        a.ooo,
			Loss:       a.loss,
			TCPFlags:   model.FormatTCPFlags(a.tcpFlags),
		})
		totalBytes += a.bytes
		totalPackets += a.packets
	}

	writeJSON(w, http.StatusOK, APISessionsResponse{
		TotalSessions: len(sessions),
		TotalBytes:    totalBytes,
		TotalPackets:  totalPackets,
		Sessions:      sessions,
	})
}

func (s *Server) handleAPIAdvisories(w http.ResponseWriter, r *http.Request) {
	var advisories []APIAdvisory
	if s.engine != nil {
		for _, a := range s.engine.Advisories() {
			advisories = append(advisories, APIAdvisory{
				Severity:    a.Severity.String(),
				Timestamp:   a.Timestamp,
				Title:       a.Title,
				Description: a.Description,
				Action:      a.Action,
				Resolved:    a.Resolved,
			})
		}
	}
	if advisories == nil {
		advisories = []APIAdvisory{}
	}

	writeJSON(w, http.StatusOK, APIAdvisoriesResponse{
		Advisories: advisories,
	})
}

func (s *Server) handleAPIDashboard(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	flows, err := s.flowSvc.RecentFlows(window, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Error("API dashboard query error: %v", err)
		return
	}

	model.StitchFlows(flows)
	data := buildDashboardData(flows, window, s.fullCfg.Collector.InterfaceNames)

	topSrc := make([]APITalkerEntry, len(data.TopSrc))
	for i, t := range data.TopSrc {
		topSrc[i] = APITalkerEntry{IP: t.IP, Bytes: t.Bytes, Packets: t.Packets, Pct: t.Pct}
	}

	topDst := make([]APITalkerEntry, len(data.TopDst))
	for i, t := range data.TopDst {
		topDst[i] = APITalkerEntry{IP: t.IP, Bytes: t.Bytes, Packets: t.Packets, Pct: t.Pct}
	}

	protocols := make([]APIProtocolEntry, len(data.Protocols))
	for i, p := range data.Protocols {
		protocols[i] = APIProtocolEntry{Name: p.Name, Bytes: p.Bytes, Packets: p.Packets, Pct: p.Pct}
	}

	writeJSON(w, http.StatusOK, APIDashboardResponse{
		TotalBytes:   data.TotalBytes,
		TotalPackets: data.TotalPackets,
		BPS:          data.BPS,
		PPS:          data.PPS,
		FlowCount:    data.FlowCount,
		ActiveFlows:  data.ActiveFlows,
		ActiveHosts:  data.ActiveHosts,
		Window:       data.Window.String(),
		TopSrc:       topSrc,
		TopDst:       topDst,
		Protocols:    protocols,
	})
}
