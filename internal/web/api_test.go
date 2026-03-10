package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// --- JSON REST API tests ---

func TestAPIFlows_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/flows", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp APIFlowsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp.TotalFlows != 0 {
		t.Errorf("TotalFlows = %d, want 0", resp.TotalFlows)
	}
	if resp.Page != 1 {
		t.Errorf("Page = %d, want 1", resp.Page)
	}
}

func TestAPIFlows_WithData(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/api/flows", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIFlowsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp.TotalFlows != 2 {
		t.Errorf("TotalFlows = %d, want 2", resp.TotalFlows)
	}
	if len(resp.Flows) != 2 {
		t.Errorf("len(Flows) = %d, want 2", len(resp.Flows))
	}
}

func TestAPIFlows_Filter(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/api/flows?src_ip=10.0.1.1", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	var resp APIFlowsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.TotalFlows != 1 {
		t.Errorf("filtered TotalFlows = %d, want 1", resp.TotalFlows)
	}
}

func TestAPIHosts_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/hosts", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIHostsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp.TotalHosts != 0 {
		t.Errorf("TotalHosts = %d, want 0", resp.TotalHosts)
	}
}

func TestAPIHosts_WithData(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/api/hosts", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	var resp APIHostsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2 (src + dst)", resp.TotalHosts)
	}
}

func TestAPISessions_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APISessionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp.TotalSessions != 0 {
		t.Errorf("TotalSessions = %d, want 0", resp.TotalSessions)
	}
}

func TestAPISessions_WithData(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("192.168.1.1", "10.0.1.1", 80, 12345, 6, 3000, 30),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	var resp APISessionsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.TotalSessions != 1 {
		t.Errorf("TotalSessions = %d, want 1 (bidirectional)", resp.TotalSessions)
	}
	if resp.TotalBytes != 8000 {
		t.Errorf("TotalBytes = %d, want 8000", resp.TotalBytes)
	}
}

func TestAPIAdvisories_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/advisories", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIAdvisoriesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if len(resp.Advisories) != 0 {
		t.Errorf("len(Advisories) = %d, want 0", len(resp.Advisories))
	}
}

func TestAPIDashboard_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIDashboardResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp.FlowCount != 0 {
		t.Errorf("FlowCount = %d, want 0", resp.FlowCount)
	}
}

func TestAPIDashboard_WithData(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	var resp APIDashboardResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.FlowCount != 1 {
		t.Errorf("FlowCount = %d, want 1", resp.FlowCount)
	}
	if resp.TotalBytes != 5000 {
		t.Errorf("TotalBytes = %d, want 5000", resp.TotalBytes)
	}
}

// --- Flow export tests ---

func TestFlowsExport_CSV(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/flows/export?format=csv", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "timestamp") {
		t.Error("CSV should contain header row with 'timestamp'")
	}
	if !strings.Contains(body, "10.0.1.1") {
		t.Error("CSV should contain flow source IP")
	}
}

func TestFlowsExport_JSON(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/flows/export?format=json", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "10.0.1.1") {
		t.Error("JSON export should contain flow source IP")
	}
}

func TestFlowsExport_WithFilter(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		makeTestFlow("10.0.1.2", "192.168.1.1", 12346, 443, 6, 10000, 100),
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/flows/export?format=csv&src_ip=10.0.1.1", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "10.0.1.1") {
		t.Error("filtered CSV should contain 10.0.1.1")
	}
	if strings.Contains(body, "10.0.1.2") {
		t.Error("filtered CSV should NOT contain 10.0.1.2")
	}
}

// --- Dashboard time-range selector tests ---

func TestDashboard_TimeRangeSelector(t *testing.T) {
	s, _ := newTestServer(t)

	// Test that the time-range selector buttons are rendered.
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "time-range-selector") {
		t.Error("dashboard should contain time-range-selector")
	}
	if !strings.Contains(body, "?range=5m") {
		t.Error("dashboard should have 5m range link")
	}
	if !strings.Contains(body, "?range=24h") {
		t.Error("dashboard should have 24h range link")
	}
}

func TestDashboard_TimeRangeParam(t *testing.T) {
	s, _ := newTestServer(t)

	// Test that selecting a range highlights it.
	req := httptest.NewRequest("GET", "/?range=1h", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Exporters page tests ---

func TestExporters_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/exporters", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Multi-Exporter") {
		t.Error("response should contain 'Multi-Exporter'")
	}
}

func TestExporters_WithData(t *testing.T) {
	s, rb := newTestServer(t)
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 12345, 80, 6, 5000, 50),
		{
			Timestamp:  time.Now(),
			SrcAddr:    net.ParseIP("10.0.2.1"),
			DstAddr:    net.ParseIP("192.168.2.1"),
			SrcPort:    54321,
			DstPort:    443,
			Protocol:   6,
			Bytes:      8000,
			Packets:    80,
			ExporterIP: net.ParseIP("172.16.0.1"),
		},
	}
	rb.Insert(flows)

	req := httptest.NewRequest("GET", "/exporters", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "10.0.0.1") {
		t.Error("exporters page should show default exporter 10.0.0.1")
	}
	if !strings.Contains(body, "172.16.0.1") {
		t.Error("exporters page should show exporter 172.16.0.1")
	}
}

// --- Counters page tests ---

func TestCounters_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/counters", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "sFlow Interface Counters") {
		t.Error("counters page should show title")
	}
	if !strings.Contains(body, "No sFlow counter data") {
		t.Error("empty counters page should show no-data message")
	}
}
