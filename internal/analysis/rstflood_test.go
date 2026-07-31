package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestRSTFloodDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := RSTFloodDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestRSTFloodDetector_StorageError(t *testing.T) {
	detector := RSTFloodDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestRSTFloodDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Below threshold RST
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 1000, 500)
	f1.TCPFlags = 0x04 // RST
	rb.Insert([]model.Flow{f1})

	// UDP traffic
	f2 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17, 1000, 20000)
	rb.Insert([]model.Flow{f2})

	// TCP traffic without RST
	f3 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 1000, 20000)
	f3.TCPFlags = 0x10 // ACK
	rb.Insert([]model.Flow{f3})

	detector := RSTFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestRSTFloodDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 5)
	// Target 1 receives exactly rstFloodMinPackets (10,000) from 5 sources (2000 each)
	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("10.0.0.%d", i+1)
		f := makeFlow(src, "192.168.1.10", 12345, 80, 6, 40, 2000)
		f.TCPFlags = 0x04 // RST
		flows = append(flows, f)
	}
	rb.Insert(flows)

	// Target 2 receives below threshold
	fBelow := makeFlow("10.0.0.99", "192.168.1.20", 12345, 80, 6, 40, 5000)
	fBelow.TCPFlags = 0x04 // RST
	rb.Insert([]model.Flow{fBelow})

	detector := RSTFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "TCP RST Flood: 192.168.1.10"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestRSTFloodDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 10)
	// Target receives rstFloodMinPackets * 5 (50,000) packets from 10 sources
	for i := 0; i < 10; i++ {
		src := fmt.Sprintf("10.0.0.%d", i+1)
		f := makeFlow(src, "192.168.1.10", 12345, 80, 6, 40, 5000) // 10 * 5000 = 50,000
		f.TCPFlags = 0x04                                          // RST
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := RSTFloodDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "TCP RST Flood: 192.168.1.10"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}
