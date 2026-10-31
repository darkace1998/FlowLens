package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// Regression: matchIP must not do raw string-prefix matching.
func TestMatchIPNoStringPrefix(t *testing.T) {
	cases := []struct {
		ip, filter string
		want       bool
	}{
		{"10.0.12.3", "10.0.1", false},  // not in 10.0.1.0/24
		{"172.16.0.5", "1", false},      // must not match on first character
		{"10.0.1.5", "10.0.1", true},    // 10.0.1.0/24
		{"10.9.9.9", "10", true},        // 10.0.0.0/8
		{"10.1.2.3", "10.0.0.0/8", true},// CIDR
		{"192.168.1.1", "192.168.1.1", true},
		{"192.168.1.2", "192.168.1.1", false},
	}
	for _, c := range cases {
		if got := matchIP(net.ParseIP(c.ip), c.filter); got != c.want {
			t.Errorf("matchIP(%s, %q) = %v, want %v", c.ip, c.filter, got, c.want)
		}
	}
}

// Regression: datetime-local time filters ("2006-01-02T15:04") must apply.
func TestFilterFlowsTimeLocalFormat(t *testing.T) {
	flows := []model.Flow{{
		Timestamp: time.Date(2024, 1, 2, 15, 30, 0, 0, time.UTC),
		SrcAddr:   net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"),
		Protocol: 6, Bytes: 100, Packets: 1,
	}}
	q := url.Values{"start": {"2024-01-02T16:00"}, "end": {"2024-01-02T17:00"}}
	if got := filterFlows(flows, flowFiltersFromQuery(q)); len(got) != 0 {
		t.Errorf("datetime-local start filter: got %d flows, want 0 (flow at 15:30 is before 16:00)", len(got))
	}
	q2 := url.Values{"start": {"2024-01-02T15:00"}, "end": {"2024-01-02T16:00"}}
	if got := filterFlows(flows, flowFiltersFromQuery(q2)); len(got) != 1 {
		t.Errorf("datetime-local range containing flow: got %d flows, want 1", len(got))
	}
	// RFC3339 still works
	q3 := url.Values{"start": {"2024-01-02T16:00:00Z"}}
	if got := filterFlows(flows, flowFiltersFromQuery(q3)); len(got) != 0 {
		t.Errorf("RFC3339 start filter: got %d flows, want 0", len(got))
	}
}

// Regression: ether_type must accept decimal and 0x-hex.
func TestParseEtherType(t *testing.T) {
	if v, ok := parseEtherType("2048"); !ok || v != 0x0800 {
		t.Errorf("parseEtherType(\"2048\") = %d, %v; want 2048, true", v, ok)
	}
	if v, ok := parseEtherType("0x0800"); !ok || v != 0x0800 {
		t.Errorf("parseEtherType(\"0x0800\") = %#x, %v; want 0x800, true", v, ok)
	}
	if _, ok := parseEtherType("bogus"); ok {
		t.Error("parseEtherType(\"bogus\") should fail")
	}
}

// Regression: ether_type=2048 (decimal) must match an 0x0800 flow end-to-end.
func TestAPIFlowsEtherTypeDecimal(t *testing.T) {
	rb := storage.NewRingBuffer(16)
	_ = rb.Insert([]model.Flow{{
		Timestamp: time.Now(), SrcAddr: net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"),
		Protocol: 6, SrcPort: 1234, DstPort: 80, Bytes: 100, Packets: 1, EtherType: 0x0800,
	}})
	s := NewServer(config.WebConfig{PageSize: 50}, rb, nil, "", nil, nil, nil, nil)
	cfg := config.Defaults()
	cfg.Storage.RingBufferDuration = time.Hour
	s.SetAboutInfo(cfg, "test", time.Now())

	req := httptest.NewRequest(http.MethodGet, "/api/flows?ether_type=2048", nil)
	rec := httptest.NewRecorder()
	s.handleAPIFlows(rec, req)
	var resp APIFlowsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(resp.Flows) != 1 {
		t.Errorf("ether_type=2048: got %d flows, want 1", len(resp.Flows))
	}
}

// Regression: saving a preset must capture filter fields sent in the POST body.
func TestSavePresetCapturesBodyFilters(t *testing.T) {
	t.Chdir(t.TempDir())
	rb := storage.NewRingBuffer(16)
	s := NewServer(config.WebConfig{}, rb, nil, "", nil, nil, nil, nil)

	body := "name=mypreset&description=d&src_ip=1.2.3.4&port=443"
	req := httptest.NewRequest(http.MethodPost, "/flows/filter-preset/save", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleSaveFilterPreset(rec, req)

	data, err := os.ReadFile(filepath.Join("data", "filter_presets.json"))
	if err != nil {
		t.Fatalf("preset file not written: %v (redirect %s)", err, rec.Header().Get("Location"))
	}
	var presets []FilterPreset
	if err := json.Unmarshal(data, &presets); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(presets) != 1 {
		t.Fatalf("expected 1 preset, got %d", len(presets))
	}
	pq, err := url.ParseQuery(presets[0].Filters)
	if err != nil {
		t.Fatalf("preset filters not a query string: %v", err)
	}
	if pq.Get("src_ip") != "1.2.3.4" || pq.Get("port") != "443" {
		t.Errorf("preset filters = %q, want src_ip=1.2.3.4 and port=443", presets[0].Filters)
	}
	if pq.Get("name") != "" || pq.Get("description") != "" {
		t.Errorf("preset filters should not contain name/description: %q", presets[0].Filters)
	}
}

// Regression: numeric filters must support the value 0 (explicit set vs unset).
func TestFilterFlowsZeroValues(t *testing.T) {
	flows := []model.Flow{
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"), Protocol: 6, ToS: 0, VLAN: 0, Bytes: 10, Packets: 1},
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("10.0.0.3"), DstAddr: net.ParseIP("10.0.0.4"), Protocol: 6, ToS: 46, VLAN: 100, Bytes: 20, Packets: 1},
	}
	// tos=0 must match only the ToS=0 flow
	q := url.Values{"tos": {"0"}}
	if got := filterFlows(flows, flowFiltersFromQuery(q)); len(got) != 1 || got[0].ToS != 0 {
		t.Errorf("tos=0 filter: got %d flows, want 1 (the ToS=0 flow)", len(got))
	}
	// vlan=0 must match only the untagged flow
	q = url.Values{"vlan": {"0"}}
	if got := filterFlows(flows, flowFiltersFromQuery(q)); len(got) != 1 || got[0].VLAN != 0 {
		t.Errorf("vlan=0 filter: got %d flows, want 1 (the VLAN=0 flow)", len(got))
	}
}
