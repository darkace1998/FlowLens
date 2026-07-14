package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestElephantFlowDetector_Analyze(t *testing.T) {
	now := time.Now()
	cfg := config.AnalysisConfig{QueryWindow: 5 * time.Minute}

	// 1 GB is the threshold
	const gigabyte = 1000000000

	flows := []model.Flow{
		// Flow 1: Mice flow (tiny)
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.10"), DstAddr: net.ParseIP("10.0.0.5"),
			SrcPort: 12345, DstPort: 80, Protocol: 6,
			Bytes: 1500, Packets: 10,
		},
		// Flow 2: Elephant flow (1.5 GB total across two segments)
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.100"), DstAddr: net.ParseIP("10.0.0.50"),
			SrcPort: 54321, DstPort: 443, Protocol: 6,
			Bytes: gigabyte, Packets: 1000000,
		},
		{
			Timestamp: now.Add(1 * time.Minute),
			SrcAddr:   net.ParseIP("192.168.1.100"), DstAddr: net.ParseIP("10.0.0.50"),
			SrcPort: 54321, DstPort: 443, Protocol: 6,
			Bytes: gigabyte / 2, Packets: 500000,
		},
		// Flow 3: Critical Elephant flow (15 GB)
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.200"), DstAddr: net.ParseIP("10.0.0.60"),
			SrcPort: 2222, DstPort: 22, Protocol: 6,
			Bytes: gigabyte * 15, Packets: 15000000,
		},
	}

	rb := storage.NewRingBuffer(100)
	rb.Insert(flows)

	det := ElephantFlowDetector{}
	advisories := det.Analyze(rb, cfg)

	if len(advisories) != 2 {
		t.Fatalf("Analyze() returned %d advisories, want 2", len(advisories))
	}

	// Advisories should be sorted by bytes descending.
	if advisories[0].Severity != CRITICAL {
		t.Errorf("advisories[0].Severity = %v, want CRITICAL (15 GB flow)", advisories[0].Severity)
	}
	if advisories[1].Severity != WARNING {
		t.Errorf("advisories[1].Severity = %v, want WARNING (1.5 GB flow)", advisories[1].Severity)
	}
}

func TestElephantFlowDetector_NoFlows(t *testing.T) {
	cfg := config.AnalysisConfig{QueryWindow: 5 * time.Minute}
	rb := storage.NewRingBuffer(10)
	det := ElephantFlowDetector{}
	advisories := det.Analyze(rb, cfg)

	if len(advisories) != 0 {
		t.Errorf("Analyze() returned %d advisories, want 0 on empty DB", len(advisories))
	}
}
