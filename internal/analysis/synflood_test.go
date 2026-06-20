package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestSYNFloodDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := SYNFloodDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestSYNFloodDetector_BelowThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create a flow with 5000 SYN packets (below 10000 threshold)
	f := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 200000, 5000)
	f.TCPFlags = 0x02 // SYN only
	rb.Insert([]model.Flow{f})

	detector := SYNFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestSYNFloodDetector_SYNFloodWarning(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create flows exceeding 10000 threshold
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 400000, 15000)
	f1.TCPFlags = 0x02 // SYN only
	rb.Insert([]model.Flow{f1})

	detector := SYNFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}
}

func TestSYNFloodDetector_SYNFloodCritical(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create flows exceeding 50000 threshold (CRITICAL)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 2000000, 60000)
	f1.TCPFlags = 0x02 // SYN only
	rb.Insert([]model.Flow{f1})

	detector := SYNFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}
}

func TestSYNFloodDetector_IgnoreNonSYN(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// SYN-ACK (0x12)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 400000, 20000)
	f1.TCPFlags = 0x12
	rb.Insert([]model.Flow{f1})

	// ACK (0x10)
	f2 := makeFlow("10.0.0.2", "192.168.1.1", 12345, 80, 6, 400000, 20000)
	f2.TCPFlags = 0x10
	rb.Insert([]model.Flow{f2})

	// UDP
	f3 := makeFlow("10.0.0.3", "192.168.1.1", 12345, 53, 17, 400000, 20000)
	rb.Insert([]model.Flow{f3})

	detector := SYNFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestSYNFloodDetector_StorageError(t *testing.T) {
	detector := SYNFloodDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestSYNFloodDetector_MultipleTargets(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	flows := make([]model.Flow, 0, 15)

	// Target 1: 15 sources * 1000 packets = 15000 SYN packets (WARNING)
	for i := 0; i < 15; i++ {
		src := fmt.Sprintf("10.0.1.%d", i)
		f := makeFlow(src, "192.168.1.1", uint16(10000+i), 80, 6, 40000, 1000)
		f.TCPFlags = 0x02
		flows = append(flows, f)
	}

	// Target 2: 12 sources * 5000 packets = 60000 SYN packets (CRITICAL)
	for i := 0; i < 12; i++ {
		src := fmt.Sprintf("10.0.2.%d", i)
		f := makeFlow(src, "192.168.1.2", uint16(10000+i), 443, 6, 200000, 5000)
		f.TCPFlags = 0x02
		flows = append(flows, f)
	}

	// Target 3: 5 sources * 1000 packets = 5000 SYN packets (No advisory)
	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("10.0.3.%d", i)
		f := makeFlow(src, "192.168.1.3", uint16(10000+i), 80, 6, 40000, 1000)
		f.TCPFlags = 0x02
		flows = append(flows, f)
	}

	rb.Insert(flows)

	detector := SYNFloodDetector{}
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
