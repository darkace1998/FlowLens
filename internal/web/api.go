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
	Page       int       `json:"page"`
	TotalPages int       `json:"total_pages"`
	TotalFlows int       `json:"total_flows"`
	Flows      []APIFlow `json:"flows"`
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
	TotalHosts int       `json:"total_hosts"`
	TotalBytes uint64    `json:"total_bytes"`
	Hosts      []APIHost `json:"hosts"`
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

// APIExportersResponse is the JSON response for GET /api/exporters.
type APIExportersResponse struct {
	TotalExporters int           `json:"total_exporters"`
	TotalBytes     uint64        `json:"total_bytes"`
	Exporters      []APIExporter `json:"exporters"`
}

// APIExporter is a single exporter record in the JSON API.
type APIExporter struct {
	IP        string    `json:"ip"`
	Bytes     uint64    `json:"bytes"`
	Packets   uint64    `json:"packets"`
	FlowCount int       `json:"flow_count"`
	Pct       float64   `json:"pct"`
	TopProto  string    `json:"top_proto"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// --- JSON helper ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logging.Default().Error("JSON encode error: %v", err)
	}
}

// APIVLANsResponse is the JSON response for GET /api/vlans.
type APIVLANsResponse struct {
	TotalVLANs int       `json:"total_vlans"`
	TotalBytes uint64    `json:"total_bytes"`
	VLANs      []APIVLAN `json:"vlans"`
}

// APIVLAN is a single VLAN record in the JSON API.
type APIVLAN struct {
	ID      uint16 `json:"id"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   int    `json:"flows"`
}

// APIMACsResponse is the JSON response for GET /api/macs.
type APIMACsResponse struct {
	TotalMACs  int      `json:"total_macs"`
	TotalBytes uint64   `json:"total_bytes"`
	MACs       []APIMAC `json:"macs"`
}

// APIMAC is a single MAC address record in the JSON API.
type APIMAC struct {
	MAC     string `json:"mac"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	VLAN    uint16 `json:"vlan"`
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
	filterAppProto := strings.TrimSpace(r.URL.Query().Get("app_proto"))
	filterAppCat := strings.TrimSpace(r.URL.Query().Get("app_cat"))
	filterStart := strings.TrimSpace(r.URL.Query().Get("start"))
	filterEnd := strings.TrimSpace(r.URL.Query().Get("end"))

	var filterBytesMin, filterBytesMax uint64
	if bs := strings.TrimSpace(r.URL.Query().Get("bytes_min")); bs != "" {
		if val, err := strconv.ParseUint(bs, 10, 64); err == nil {
			filterBytesMin = val
		}
	}
	if bs := strings.TrimSpace(r.URL.Query().Get("bytes_max")); bs != "" {
		if val, err := strconv.ParseUint(bs, 10, 64); err == nil {
			filterBytesMax = val
		}
	}

	// Phase 2 filters
	filterTCPFlags := strings.TrimSpace(r.URL.Query().Get("tcp_flags"))

	var filterToS uint8
	if to := strings.TrimSpace(r.URL.Query().Get("tos")); to != "" {
		if val, err := strconv.ParseUint(to, 10, 8); err == nil {
			filterToS = uint8(val)
		}
	}

	filterInIface := strings.TrimSpace(r.URL.Query().Get("in_iface"))
	filterOutIface := strings.TrimSpace(r.URL.Query().Get("out_iface"))

	var filterSrcAS, filterDstAS uint32
	if as := strings.TrimSpace(r.URL.Query().Get("src_as")); as != "" {
		if val, err := strconv.ParseUint(as, 10, 32); err == nil {
			filterSrcAS = uint32(val)
		}
	}
	if as := strings.TrimSpace(r.URL.Query().Get("dst_as")); as != "" {
		if val, err := strconv.ParseUint(as, 10, 32); err == nil {
			filterDstAS = uint32(val)
		}
	}

	filterSrcMAC := strings.TrimSpace(r.URL.Query().Get("src_mac"))
	filterDstMAC := strings.TrimSpace(r.URL.Query().Get("dst_mac"))

	var filterVLAN uint16
	if vl := strings.TrimSpace(r.URL.Query().Get("vlan")); vl != "" {
		if val, err := strconv.ParseUint(vl, 10, 16); err == nil {
			filterVLAN = uint16(val)
		}
	}

	var filterEtherType uint16
	if et := strings.TrimSpace(r.URL.Query().Get("ether_type")); et != "" {
		// Support hex format (0x0800) or decimal (2048)
		etClean := strings.TrimPrefix(et, "0x")
		if val, err := strconv.ParseUint(etClean, 16, 16); err == nil {
			filterEtherType = uint16(val)
		}
	}

	filterExporter := strings.TrimSpace(r.URL.Query().Get("exporter"))

	// TCP Quality filters
	var filterRTTMin, filterRTTMax int64
	if rtt := strings.TrimSpace(r.URL.Query().Get("rtt_min")); rtt != "" {
		if val, err := strconv.ParseInt(rtt, 10, 64); err == nil {
			filterRTTMin = val
		}
	}
	if rtt := strings.TrimSpace(r.URL.Query().Get("rtt_max")); rtt != "" {
		if val, err := strconv.ParseInt(rtt, 10, 64); err == nil {
			filterRTTMax = val
		}
	}

	var filterRetransMin uint32
	if rt := strings.TrimSpace(r.URL.Query().Get("retrans_min")); rt != "" {
		if val, err := strconv.ParseUint(rt, 10, 32); err == nil {
			filterRetransMin = uint32(val)
		}
	}

	var filterOOOMin uint32
	if ooo := strings.TrimSpace(r.URL.Query().Get("ooo_min")); ooo != "" {
		if val, err := strconv.ParseUint(ooo, 10, 32); err == nil {
			filterOOOMin = uint32(val)
		}
	}

	var filterLossMin uint32
	if loss := strings.TrimSpace(r.URL.Query().Get("loss_min")); loss != "" {
		if val, err := strconv.ParseUint(loss, 10, 32); err == nil {
			filterLossMin = uint32(val)
		}
	}

	var filterJitterMin, filterJitterMax int64
	if jit := strings.TrimSpace(r.URL.Query().Get("jitter_min")); jit != "" {
		if val, err := strconv.ParseInt(jit, 10, 64); err == nil {
			filterJitterMin = val
		}
	}
	if jit := strings.TrimSpace(r.URL.Query().Get("jitter_max")); jit != "" {
		if val, err := strconv.ParseInt(jit, 10, 64); err == nil {
			filterJitterMax = val
		}
	}

	var filterMOSMin float32
	if mos := strings.TrimSpace(r.URL.Query().Get("mos_min")); mos != "" {
		if val, err := strconv.ParseFloat(mos, 32); err == nil {
			filterMOSMin = float32(val)
		}
	}

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
	filtered := filterFlows(allFlows, filterSrcIP, filterDstIP, filterPort, filterProto, filterIP, filterAppProto, filterAppCat, filterStart, filterEnd, filterBytesMin, filterBytesMax, filterTCPFlags, filterToS, filterInIface, filterOutIface, filterSrcAS, filterDstAS, filterSrcMAC, filterDstMAC, filterVLAN, filterEtherType, filterExporter, filterRTTMin, filterRTTMax, filterRetransMin, filterOOOMin, filterLossMin, filterJitterMin, filterJitterMax, filterMOSMin)

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
		srcAddr, dstAddr   string
		srcPort, dstPort   uint16
		proto              uint8
		bytes, packets     uint64
		flowCount          int
		first, last        time.Time
		retrans, ooo, loss uint32
		appProto           string
		tcpFlags           uint8
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
		topSrc[i] = APITalkerEntry(t)
	}

	topDst := make([]APITalkerEntry, len(data.TopDst))
	for i, t := range data.TopDst {
		topDst[i] = APITalkerEntry(t)
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

func (s *Server) handleAPIExporters(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	flows, err := s.flowSvc.RecentFlows(window, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Error("API exporters query error: %v", err)
		return
	}

	type exporterAgg struct {
		bytes, packets uint64
		flowCount      int
		protoCount     map[uint8]int
		first, last    time.Time
	}

	aggMap := make(map[string]*exporterAgg)
	var totalBytes uint64

	for _, f := range flows {
		totalBytes += f.Bytes
		ip := model.SafeIPString(f.ExporterIP)
		if ip == "" || ip == "<nil>" {
			ip = "unknown"
		}
		if a, ok := aggMap[ip]; ok {
			a.bytes += f.Bytes
			a.packets += f.Packets
			a.flowCount++
			a.protoCount[f.Protocol]++
			if f.Timestamp.Before(a.first) {
				a.first = f.Timestamp
			}
			if f.Timestamp.After(a.last) {
				a.last = f.Timestamp
			}
		} else {
			aggMap[ip] = &exporterAgg{
				bytes:      f.Bytes,
				packets:    f.Packets,
				flowCount:  1,
				protoCount: map[uint8]int{f.Protocol: 1},
				first:      f.Timestamp,
				last:       f.Timestamp,
			}
		}
	}

	exporters := make([]APIExporter, 0, len(aggMap))
	for ip, a := range aggMap {
		var topProto uint8
		var maxCount int
		for proto, count := range a.protoCount {
			if count > maxCount {
				topProto = proto
				maxCount = count
			}
		}
		exporters = append(exporters, APIExporter{
			IP:        ip,
			Bytes:     a.bytes,
			Packets:   a.packets,
			FlowCount: a.flowCount,
			Pct:       pctOf(a.bytes, totalBytes),
			TopProto:  model.ProtocolName(topProto),
			FirstSeen: a.first,
			LastSeen:  a.last,
		})
	}

	sortByBytes(exporters, func(e APIExporter) uint64 { return e.Bytes })

	writeJSON(w, http.StatusOK, APIExportersResponse{
		TotalExporters: len(exporters),
		TotalBytes:     totalBytes,
		Exporters:      exporters,
	})
}

func (s *Server) handleAPIVLANs(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	allFlows, err := s.flowSvc.RecentFlows(window, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Error("API vlans query error: %v", err)
		return
	}

	type vlanAgg struct {
		bytes   uint64
		packets uint64
		flows   int
	}
	aggMap := make(map[uint16]*vlanAgg)
	var totalBytes uint64

	for _, f := range allFlows {
		totalBytes += f.Bytes
		vid := f.VLAN
		if a, ok := aggMap[vid]; ok {
			a.bytes += f.Bytes
			a.packets += f.Packets
			a.flows++
		} else {
			aggMap[vid] = &vlanAgg{
				bytes:   f.Bytes,
				packets: f.Packets,
				flows:   1,
			}
		}
	}

	vlans := make([]APIVLAN, 0, len(aggMap))
	for vid, a := range aggMap {
		vlans = append(vlans, APIVLAN{
			ID:      vid,
			Bytes:   a.bytes,
			Packets: a.packets,
			Flows:   a.flows,
		})
	}

	sortByBytes(vlans, func(e APIVLAN) uint64 { return e.Bytes })

	writeJSON(w, http.StatusOK, APIVLANsResponse{
		TotalVLANs: len(vlans),
		TotalBytes: totalBytes,
		VLANs:      vlans,
	})
}

func (s *Server) handleAPIMACs(w http.ResponseWriter, r *http.Request) {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		window = 10 * time.Minute
	}
	allFlows, err := s.flowSvc.RecentFlows(window, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query flows"})
		logging.Default().Error("API macs query error: %v", err)
		return
	}

	type macAgg struct {
		vlan    uint16
		bytes   uint64
		packets uint64
	}
	aggMap := make(map[string]*macAgg)
	var totalBytes uint64

	for _, f := range allFlows {
		srcMAC := model.FormatMAC(f.SrcMAC)
		dstMAC := model.FormatMAC(f.DstMAC)

		if srcMAC != "—" || dstMAC != "—" {
			totalBytes += f.Bytes
		}

		if srcMAC != "—" {
			if a, ok := aggMap[srcMAC]; ok {
				a.vlan = f.VLAN
				a.bytes += f.Bytes
				a.packets += f.Packets
			} else {
				aggMap[srcMAC] = &macAgg{
					vlan:    f.VLAN,
					bytes:   f.Bytes,
					packets: f.Packets,
				}
			}
		}
		if dstMAC != "—" {
			if a, ok := aggMap[dstMAC]; ok {
				a.vlan = f.VLAN
				a.bytes += f.Bytes
				a.packets += f.Packets
			} else {
				aggMap[dstMAC] = &macAgg{
					vlan:    f.VLAN,
					bytes:   f.Bytes,
					packets: f.Packets,
				}
			}
		}
	}

	macs := make([]APIMAC, 0, len(aggMap))
	for mac, a := range aggMap {
		macs = append(macs, APIMAC{
			MAC:     mac,
			Bytes:   a.bytes,
			Packets: a.packets,
			VLAN:    a.vlan,
		})
	}

	sortByBytes(macs, func(e APIMAC) uint64 { return e.Bytes })

	writeJSON(w, http.StatusOK, APIMACsResponse{
		TotalMACs:  len(macs),
		TotalBytes: totalBytes,
		MACs:       macs,
	})
}
