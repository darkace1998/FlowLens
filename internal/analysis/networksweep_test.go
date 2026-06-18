package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestNetworkSweepDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := NetworkSweepDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestNetworkSweepDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Same source, connecting to 10 unique targets (below threshold of 250)
	var flows []model.Flow
	for i := 0; i < 10; i++ {
		dstIP := fmt.Sprintf("192.168.1.%d", i+1)
		flows = append(flows, makeTestFlow("10.0.0.1", dstIP, 12345, 80, 6, 100, 1))
	}
	rb.Insert(flows)

	advisories := NetworkSweepDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal traffic should produce 0 advisories, got %d", len(advisories))
	}
}

func TestNetworkSweepDetector_WarningThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(2000)

	cfg := defaultCfg()
	cfg.SweepThreshold = 100 // Set lower for easier testing

	var flows []model.Flow
	// Source connects to 120 unique IPs (>= 100 but < 500)
	for i := 0; i < 120; i++ {
		dstIP := fmt.Sprintf("192.168.1.%d", i+1) // Simplified, actual IP generation would wrap > 255 but string works
		flows = append(flows, makeTestFlow("10.0.0.1", dstIP, 12345, 80, 6, 100, 1))
	}
	rb.Insert(flows)

	advisories := NetworkSweepDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for network sweep, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %s", advisories[0].Severity)
	}
	if advisories[0].Title != "Network Sweep Detected: 10.0.0.1" {
		t.Errorf("unexpected title: %s", advisories[0].Title)
	}
}

func TestNetworkSweepDetector_CriticalThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(2000)

	cfg := defaultCfg()
	cfg.SweepThreshold = 20

	var flows []model.Flow
	// Source connects to 110 unique IPs (>= 5 * 20 = 100)
	for i := 0; i < 110; i++ {
		dstIP := fmt.Sprintf("10.0.0.%d", i+1)
		flows = append(flows, makeTestFlow("192.168.1.100", dstIP, 12345, 80, 6, 100, 1))
	}
	rb.Insert(flows)

	advisories := NetworkSweepDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %s", advisories[0].Severity)
	}
}

func TestNetworkSweepDetector_StorageError(t *testing.T) {
	// mockErrorStorage is defined in scanner_test.go and accessible across the analysis package.
	advisories := NetworkSweepDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}
