package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestUDPFloodDetector_Name(t *testing.T) {
	name := UDPFloodDetector{}.Name()
	expected := "UDP Flood Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestUDPFloodDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := UDPFloodDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestUDPFloodDetector_BelowThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create a flow with 5000 UDP packets (below 10000 threshold)
	f := makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17, 200000, 5000)
	rb.Insert([]model.Flow{f})

	detector := UDPFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestUDPFloodDetector_UDPFloodWarning(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create flows exceeding 10000 threshold
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17, 400000, 15000)
	rb.Insert([]model.Flow{f1})

	detector := UDPFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}
}

func TestUDPFloodDetector_UDPFloodCritical(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create flows exceeding 50000 threshold (CRITICAL)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17, 2000000, 60000)
	rb.Insert([]model.Flow{f1})

	detector := UDPFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}
}

func TestUDPFloodDetector_IgnoreNonUDP(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// TCP
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 400000, 20000)
	rb.Insert([]model.Flow{f1})

	// ICMP
	f2 := makeFlow("10.0.0.2", "192.168.1.1", 12345, 0, 1, 400000, 20000)
	rb.Insert([]model.Flow{f2})

	detector := UDPFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestUDPFloodDetector_StorageError(t *testing.T) {
	detector := UDPFloodDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestUDPFloodDetector_MultipleTargets(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	flows := make([]model.Flow, 0, 15)

	// Target 1: 15 sources * 1000 packets = 15000 UDP packets (WARNING)
	for i := 0; i < 15; i++ {
		src := fmt.Sprintf("10.0.1.%d", i)
		f := makeFlow(src, "192.168.1.1", uint16(10000+i), 53, 17, 40000, 1000)
		flows = append(flows, f)
	}

	// Target 2: 12 sources * 5000 packets = 60000 UDP packets (CRITICAL)
	for i := 0; i < 12; i++ {
		src := fmt.Sprintf("10.0.2.%d", i)
		f := makeFlow(src, "192.168.1.2", uint16(10000+i), 53, 17, 200000, 5000)
		flows = append(flows, f)
	}

	// Target 3: 5 sources * 1000 packets = 5000 UDP packets (No advisory)
	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("10.0.3.%d", i)
		f := makeFlow(src, "192.168.1.3", uint16(10000+i), 53, 17, 40000, 1000)
		flows = append(flows, f)
	}

	rb.Insert(flows)

	detector := UDPFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advisories))
	}

	// Should be sorted by packet count descending (Target 2 first, then Target 1)
	if advisories[0].Severity != CRITICAL {
		t.Errorf("first advisory should be CRITICAL, got %v", advisories[0].Severity)
	}
	if advisories[1].Severity != WARNING {
		t.Errorf("second advisory should be WARNING, got %v", advisories[1].Severity)
	}
}
