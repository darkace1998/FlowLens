package analysis

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestHTTPFloodDetector_NoData(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := HTTPFloodDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestHTTPFloodDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Normal traffic: HTTP flows below threshold (1000)
	flows := make([]model.Flow, 0, 100)
	for i := 0; i < 100; i++ {
		flows = append(flows, makeFlow("10.0.1.1", "192.168.1.1", 10000+uint16(i), 80, 6, 1000, 10))
	}
	rb.Insert(flows)

	advisories := HTTPFloodDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal traffic should produce 0 advisories, got %d", len(advisories))
	}
}

func TestHTTPFloodDetector_WarningFlood(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	// Flood traffic: 1200 HTTP flows (>= 1000 and < 3000)
	flows := make([]model.Flow, 0, 1200)
	for i := 0; i < 1200; i++ {
		flows = append(flows, makeFlow("10.0.1.1", "192.168.1.1", 10000+uint16(i%1000), 80, 6, 1000, 10))
	}
	rb.Insert(flows)

	advisories := HTTPFloodDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for HTTP flood, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("1200 flows should be WARNING, got %s", advisories[0].Severity)
	}
	if advisories[0].Title != "HTTP Flood Attack: 192.168.1.1" {
		t.Errorf("unexpected title: %s", advisories[0].Title)
	}
}

func TestHTTPFloodDetector_CriticalFlood(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	// Critical flood traffic: 3500 HTTP flows (>= 3000)
	flows := make([]model.Flow, 0, 3500)
	for i := 0; i < 3500; i++ {
		flows = append(flows, makeFlow(fmt.Sprintf("10.0.1.%d", i%20), "192.168.1.1", 10000+uint16(i%1000), 443, 6, 1000, 10))
	}
	rb.Insert(flows)

	advisories := HTTPFloodDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for HTTP flood, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("3500 flows should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestHTTPFloodDetector_IgnoresNonHTTP(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	// High flow count, but not on port 80/443
	flows := make([]model.Flow, 0, 3500)
	for i := 0; i < 3500; i++ {
		flows = append(flows, makeFlow("10.0.1.1", "192.168.1.1", 10000+uint16(i%1000), 22, 6, 1000, 10)) // SSH
	}
	// High flow count on HTTP/HTTPS port but UDP
	for i := 0; i < 3500; i++ {
		flows = append(flows, makeFlow("10.0.1.1", "192.168.1.1", 10000+uint16(i%1000), 80, 17, 1000, 10)) // UDP/80
	}
	rb.Insert(flows)

	advisories := HTTPFloodDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("Non-HTTP flows should not trigger HTTP flood detection, got %d advisories", len(advisories))
	}
}

func TestHTTPFloodDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := HTTPFloodDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
	if !strings.Contains(buf.String(), "HTTPFloodDetector: failed to query recent flows: mock storage error") {
		t.Errorf("expected error log, got %q", buf.String())
	}
}

func TestHTTPFloodDetector_Name(t *testing.T) {
	name := HTTPFloodDetector{}.Name()
	expected := "HTTP Flood Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}
