package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func makeTestFlow(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8, bytes, pkts uint64) model.Flow {
	return model.Flow{
		Timestamp:   time.Now(),
		SrcAddr:     net.ParseIP(srcIP),
		DstAddr:     net.ParseIP(dstIP),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    proto,
		Bytes:       bytes,
		Packets:     pkts,
		TCPFlags:    0x02,
		ToS:         0,
		InputIface:  1,
		OutputIface: 2,
		SrcAS:       65000,
		DstAS:       65001,
		Duration:    5 * time.Second,
		ExporterIP:  net.ParseIP("10.0.0.1"),
	}
}

func newTestServer(t *testing.T) (*Server, *storage.RingBuffer) {
	t.Helper()
	ringBuf := storage.NewRingBuffer(1000)
	cfg := config.WebConfig{Listen: ":0", PageSize: 10}
	s := NewServer(cfg, ringBuf, nil, t.TempDir(), nil)
	return s, ringBuf
}

func TestDashboard_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Error("response should contain 'Dashboard'")
	}
	if !strings.Contains(body, "No flow data yet") {
		t.Error("empty dashboard should show 'No flow data yet'")
	}
}

func TestDashboard_WithFlows(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
		makeTestFlow("10.0.1.1", "192.168.1.2", 54321, 53, 17, 200, 2),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "10.0.1.1") {
		t.Error("dashboard should contain top talker IP 10.0.1.1")
	}
	if !strings.Contains(body, "TCP") {
		t.Error("dashboard should show TCP protocol")
	}
	if !strings.Contains(body, "Top Sources") {
		t.Error("dashboard should show Top Sources section")
	}
}

func TestFlows_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/flows", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Flow Explorer") {
		t.Error("response should contain 'Flow Explorer'")
	}
	if !strings.Contains(body, "No flows match") {
		t.Error("empty flows page should show no-match message")
	}
}

func TestFlows_WithData(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/flows", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "10.0.1.1") {
		t.Error("flows page should contain source IP")
	}
	if !strings.Contains(body, "192.168.1.1") {
		t.Error("flows page should contain destination IP")
	}
}

func TestFlows_FilterBySrcIP(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
		makeTestFlow("172.16.0.1", "192.168.1.1", 54321, 22, 6, 300, 3),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/flows?src_ip=10.0.1", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "2 flows") {
		t.Errorf("filter by src_ip=10.0.1 should show 2 flows, got body snippet: %s", body[:min(len(body), 500)])
	}
}

func TestFlows_FilterByProtocol(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 54321, 53, 17, 200, 2),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/flows?protocol=udp", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "1 flows") {
		t.Errorf("filter by protocol=udp should show 1 flow, got body snippet: %s", body[:min(len(body), 500)])
	}
}

func TestFlows_Pagination(t *testing.T) {
	s, rb := newTestServer(t)
	// Insert 25 flows (page size is 10).
	for i := 0; i < 25; i++ {
		f := makeTestFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	// Page 1
	req := httptest.NewRequest("GET", "/flows?page=1", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "page 1 of 3") {
		t.Errorf("page 1 should show 'page 1 of 3', got body snippet: %s", body[:min(len(body), 500)])
	}

	// Page 3 (last page)
	req = httptest.NewRequest("GET", "/flows?page=3", nil)
	w = httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)
	body = w.Body.String()
	if !strings.Contains(body, "page 3 of 3") {
		t.Errorf("page 3 should show 'page 3 of 3', got body snippet: %s", body[:min(len(body), 500)])
	}
}

func TestNotFound(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestBuildDashboardData(t *testing.T) {
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
		makeTestFlow("10.0.1.1", "192.168.1.2", 54321, 53, 17, 200, 2),
	}

	data := buildDashboardData(flows, 10*time.Minute)

	if data.TotalBytes != 15200 {
		t.Errorf("TotalBytes = %d, want 15200", data.TotalBytes)
	}
	if data.TotalPackets != 152 {
		t.Errorf("TotalPackets = %d, want 152", data.TotalPackets)
	}
	if data.FlowCount != 3 {
		t.Errorf("FlowCount = %d, want 3", data.FlowCount)
	}
	if len(data.TopSrc) != 2 {
		t.Errorf("TopSrc count = %d, want 2", len(data.TopSrc))
	}
	if len(data.Protocols) != 2 {
		t.Errorf("Protocols count = %d, want 2", len(data.Protocols))
	}
	// Top source should be 10.0.1.1 (5000+200=5200 bytes) or 10.0.1.2 (10000 bytes)
	if data.TopSrc[0].IP != "10.0.1.2" {
		t.Errorf("TopSrc[0] = %s, want 10.0.1.2 (highest bytes)", data.TopSrc[0].IP)
	}
}

func TestFilterFlows(t *testing.T) {
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
		makeTestFlow("172.16.0.1", "192.168.1.2", 54321, 53, 17, 200, 2),
	}

	// Filter by port
	result := filterFlows(flows, "", "", "443", "")
	if len(result) != 1 {
		t.Errorf("filter port=443: got %d flows, want 1", len(result))
	}

	// Filter by protocol
	result = filterFlows(flows, "", "", "", "udp")
	if len(result) != 1 {
		t.Errorf("filter proto=udp: got %d flows, want 1", len(result))
	}

	// Filter by dst IP
	result = filterFlows(flows, "", "192.168.1.1", "", "")
	if len(result) != 2 {
		t.Errorf("filter dst=192.168.1.1: got %d flows, want 2", len(result))
	}

	// No filter
	result = filterFlows(flows, "", "", "", "")
	if len(result) != 3 {
		t.Errorf("no filter: got %d flows, want 3", len(result))
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatBPS(t *testing.T) {
	got := formatBPS(1000000, 10*time.Minute)
	if !strings.Contains(got, "Kbps") {
		t.Errorf("formatBPS(1MB, 10m) = %q, expected Kbps range", got)
	}
}

func TestAdvisories_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/advisories", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Advisories") {
		t.Error("response should contain 'Advisories'")
	}
	if !strings.Contains(body, "All clear") {
		t.Error("empty advisories page should show 'All clear'")
	}
}

func TestAdvisories_WithEngine(t *testing.T) {
	ringBuf := storage.NewRingBuffer(1000)
	ringBuf.Insert([]model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 10000, 100),
	})

	cfg := config.WebConfig{Listen: ":0", PageSize: 10}
	analysisCfg := config.AnalysisConfig{
		Interval:        50 * time.Millisecond,
		TopTalkersCount: 5,
		ScanThreshold:   500,
	}

	engine := analysis.NewEngine(analysisCfg, ringBuf,
		analysis.TopTalkers{},
		analysis.ProtocolDistribution{},
	)
	go engine.Start()
	time.Sleep(100 * time.Millisecond)

	s := NewServer(cfg, ringBuf, nil, t.TempDir(), engine)

	req := httptest.NewRequest("GET", "/advisories", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	engine.Stop()

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Top Talker") {
		t.Error("advisories should show Top Talker advisory")
	}
	if !strings.Contains(body, "severity-critical") || !strings.Contains(body, "CRITICAL") {
		t.Error("single host = 100% should show CRITICAL badge")
	}
}
