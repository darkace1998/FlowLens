package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// makeVoIPFlow is a helper to generate a typical VoIP flow for testing.
func makeVoIPFlow(src, dst string, srcPort, dstPort uint16, mos float32, jitterMicros int64, packetLoss uint32, packets uint64) model.Flow {
	f := makeFlow(src, dst, srcPort, dstPort, 17, 200*packets, packets) // 17 is UDP
	f.MOS = mos
	f.JitterMicros = jitterMicros
	f.PacketLoss = packetLoss
	f.Packets = packets
	return f
}

func TestVoIPQualityDetector_Name(t *testing.T) {
	name := VoIPQualityDetector{}.Name()
	expected := "VoIP Quality Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestVoIPQualityDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := VoIPQualityDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestVoIPQualityDetector_GoodQuality(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Add some flows with good MOS
	rb.Insert([]model.Flow{
		makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 4.2, 5000, 0, 1000),
		makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 4.0, 5000, 0, 1000),
	})

	advisories := VoIPQualityDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for good quality VoIP, got %d", len(advisories))
	}
}

func TestVoIPQualityDetector_WarningQuality(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Add some flows with warning level MOS (between 3.0 and 3.5)
	rb.Insert([]model.Flow{
		makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 3.2, 20000, 5, 1000),
		makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 3.4, 20000, 5, 1000),
	})

	advisories := VoIPQualityDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 warning advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %s", advisories[0].Severity)
	}
}

func TestVoIPQualityDetector_CriticalQuality(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Add some flows with critical level MOS (< 3.0)
	rb.Insert([]model.Flow{
		makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 2.5, 50000, 50, 1000),
		makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 2.7, 50000, 50, 1000),
	})

	advisories := VoIPQualityDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 critical advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %s", advisories[0].Severity)
	}
}

func TestVoIPQualityDetector_StorageError(t *testing.T) {
	advisories := VoIPQualityDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestVoIPQualityDetector_NonVoIP(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Add flow that represents regular web traffic (TCP, port 80)
	f1 := makeFlow("10.0.1.1", "192.168.1.1", 54321, 80, 6, 10000, 100)
	// Give it artificially low MOS to ensure the filter works
	f1.MOS = 2.0

	rb.Insert([]model.Flow{f1})

	advisories := VoIPQualityDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for non-VoIP traffic, got %d", len(advisories))
	}
}

func TestVoIPQualityDetector_CalculatesMOS(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Add flow with 0 MOS but with jitter and packet loss, should be calculated
	f := makeVoIPFlow("10.0.1.1", "192.168.1.1", 15000, 15002, 0, 600000, 500, 1000)
	f.RTTMicros = 600000 // 10% packet loss, 60ms jitter
	rb.Insert([]model.Flow{f})

	advisories := VoIPQualityDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory due to calculated low MOS, got %d", len(advisories))
	}
	// With 60ms jitter and 10% packet loss, the MOS should be definitely low enough to trigger an advisory
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity for computed low MOS, got %s", advisories[0].Severity)
	}
}
