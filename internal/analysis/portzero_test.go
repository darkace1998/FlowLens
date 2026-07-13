package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestPortZeroDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := PortZeroDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestPortZeroDetector_StorageError(t *testing.T) {
	detector := PortZeroDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestPortZeroDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 100, 1)
	rb.Insert([]model.Flow{f1})

	f2 := makeFlow("192.168.1.1", "10.0.0.1", 80, 12345, 6, 100, 1)
	rb.Insert([]model.Flow{f2})

	f3 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17, 100, 1)
	rb.Insert([]model.Flow{f3})

	// ICMP should be ignored, even if ports are 0 (ICMP doesn't use ports the same way)
	f4 := makeFlow("10.0.0.1", "192.168.1.1", 0, 0, 1, 100, 1)
	rb.Insert([]model.Flow{f4})

	detector := PortZeroDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestPortZeroDetector_SrcPortZero(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	f := makeFlow("10.0.0.1", "192.168.1.2", 0, 80, 6, 100, 1)
	rb.Insert([]model.Flow{f})

	detector := PortZeroDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Invalid Port 0 Traffic: 10.0.0.1"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestPortZeroDetector_DstPortZeroCritical(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 15)
	// Create flows hitting 15 targets (above 10 threshold for CRITICAL)
	for i := 0; i < 15; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i+1)
		f := makeFlow("10.0.0.2", dst, 12345, 0, 17, 100, 1)
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := PortZeroDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Invalid Port 0 Traffic: 10.0.0.2"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestPortZeroDetector_HighPacketVolumeCritical(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	f := makeFlow("10.0.0.3", "192.168.1.2", 0, 0, 6, 15000, 150)
	rb.Insert([]model.Flow{f})

	detector := PortZeroDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity for high volume, got %v", advisories[0].Severity)
	}
}
