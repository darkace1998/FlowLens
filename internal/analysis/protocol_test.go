package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)


// --- Protocol Distribution Analyzer tests ---

func TestProtocolDistribution_Name(t *testing.T) {
	name := ProtocolDistribution{}.Name()
	expected := "Protocol Distribution"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestProtocolDistribution_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestProtocolDistribution_StorageError(t *testing.T) {
	advisories := ProtocolDistribution{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestProtocolDistribution_ZeroBytes(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Insert flows with 0 bytes
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 0, 50),
		makeFlow("10.0.1.1", "192.168.1.1", 1235, 53, 17, 0, 30),
	})

	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("0 bytes should produce 0 advisories, got %d", len(advisories))
	}
}

func TestProtocolDistribution_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Normal traffic: Mostly TCP (6) and UDP (17), maybe small ICMP (1) < 10%
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 8000, 50),   // 80%
		makeFlow("10.0.1.1", "192.168.1.1", 1235, 53, 17, 1500, 30),  // 15%
		makeFlow("10.0.1.1", "192.168.1.1", 0, 0, 1, 500, 10),        // 5%
	})

	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal traffic should produce 0 advisories, got %d", len(advisories))
	}
}

func TestProtocolDistribution_ICMPFlood(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// ICMP > 10%
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 8000, 50),   // 80%
		makeFlow("10.0.1.1", "192.168.1.1", 0, 0, 1, 2000, 40),       // 20%
	})

	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for ICMP flood, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("ICMP > 10%% should be WARNING, got %s", advisories[0].Severity)
	}
	if advisories[0].Title != "Protocol: ICMP (20.0%)" {
		t.Errorf("expected Title 'Protocol: ICMP (20.0%%)', got '%s'", advisories[0].Title)
	}
}

func TestProtocolDistribution_NonStandardProtocol(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Non-standard protocol (e.g., 47 GRE) > 5%
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 9000, 50),   // 90%
		makeFlow("10.0.1.1", "192.168.1.1", 0, 0, 47, 1000, 20),      // 10%
	})

	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for non-standard protocol, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("GRE > 5%% should be WARNING, got %s", advisories[0].Severity)
	}
	if advisories[0].Title != "Protocol: GRE (10.0%)" {
		t.Errorf("expected Title 'Protocol: GRE (10.0%%)', got '%s'", advisories[0].Title)
	}
}
