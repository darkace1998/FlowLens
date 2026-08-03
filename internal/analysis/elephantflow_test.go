package analysis

import (
	"strings"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestElephantFlowDetector_Name(t *testing.T) {
	name := ElephantFlowDetector{}.Name()
	expected := "Elephant Flow Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestElephantFlowDetector_StorageError(t *testing.T) {
	advisories := ElephantFlowDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestElephantFlowDetector_ZeroFlows(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := ElephantFlowDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when no flows, got %d", len(advisories))
	}
}

func TestElephantFlowDetector_BelowThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	f1 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000000, 5000)  // 50MB (below 100MB threshold)
	f2 := makeFlow("10.0.1.2", "192.168.1.1", 1235, 443, 6, 90000000, 9000) // 90MB

	rb.Insert([]model.Flow{f1, f2})

	cfg := defaultCfg()
	cfg.ElephantBytesThreshold = 104857600 // 100MB

	advisories := ElephantFlowDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when flows are below threshold, got %d", len(advisories))
	}
}

func TestElephantFlowDetector_WithElephantFlows(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Elephant TCP Flow (200MB, warning)
	f1 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 209715200, 20000)
	// Elephant UDP Flow (600MB, critical > 5x 100MB)
	f2 := makeFlow("10.0.1.2", "192.168.1.1", 1235, 53, 17, 629145600, 60000)
	// Small Flow (1MB, ignored)
	f3 := makeFlow("10.0.1.3", "192.168.1.1", 1236, 53, 17, 1048576, 100)
	// Elephant ICMP Flow (200MB, ignored because not TCP/UDP)
	f4 := makeFlow("10.0.1.4", "192.168.1.1", 1237, 0, 1, 209715200, 20000)

	rb.Insert([]model.Flow{f1, f2, f3, f4})

	cfg := defaultCfg()
	cfg.ElephantBytesThreshold = 104857600 // 100MB

	advisories := ElephantFlowDetector{}.Analyze(rb, cfg)
	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advisories))
	}

	// Verify advisories
	hasTCPWarning := false
	hasUDPCritical := false
	for _, a := range advisories {
		if strings.Contains(a.Title, "10.0.1.1:1234") {
			hasTCPWarning = true
			if a.Severity != WARNING {
				t.Errorf("expected severity WARNING, got %v", a.Severity)
			}
			if !strings.Contains(a.Description, "TCP") {
				t.Errorf("expected description to mention TCP, got %q", a.Description)
			}
			if !strings.Contains(a.Description, "200.0 MB") {
				t.Errorf("expected description to mention 200.0 MB, got %q", a.Description)
			}
		}
		if strings.Contains(a.Title, "10.0.1.2:1235") {
			hasUDPCritical = true
			if a.Severity != CRITICAL {
				t.Errorf("expected severity CRITICAL, got %v", a.Severity)
			}
			if !strings.Contains(a.Description, "UDP") {
				t.Errorf("expected description to mention UDP, got %q", a.Description)
			}
			if !strings.Contains(a.Description, "600.0 MB") {
				t.Errorf("expected description to mention 600.0 MB, got %q", a.Description)
			}
		}
	}

	if !hasTCPWarning {
		t.Error("missing advisory for elephant TCP connection")
	}
	if !hasUDPCritical {
		t.Error("missing advisory for elephant UDP connection")
	}
}

func TestElephantFlowDetector_DefaultFallback(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// 150 MB flow
	f1 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 157286400, 15000)

	rb.Insert([]model.Flow{f1})

	cfg := defaultCfg()
	cfg.ElephantBytesThreshold = 0 // Should fall back to 100MB

	advisories := ElephantFlowDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory due to default fallback, got %d", len(advisories))
	}
}
