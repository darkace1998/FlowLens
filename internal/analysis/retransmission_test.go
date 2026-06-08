package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// Helper copied from analysis_test.go to keep tests independent.
func makeTestFlow(src, dst string, srcPort, dstPort uint16, proto uint8, bytes, pkts uint64) model.Flow {
	return model.Flow{
		Timestamp: time.Now(),
		SrcAddr:   net.ParseIP(src),
		DstAddr:   net.ParseIP(dst),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		Bytes:     bytes,
		Packets:   pkts,
		Duration:  5 * time.Second,
	}
}

// --- Retransmission Detector (Heuristic) tests ---

func TestRetransmissionDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestRetransmissionDetector_NormalTCP(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Normal TCP: 1000 bytes/pkt average — well above smallPacketThreshold.
	rb.Insert([]model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 50),
	})

	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal TCP should produce 0 advisories, got %d", len(advisories))
	}
}

func TestRetransmissionDetector_SmallPackets(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Small packets: 40 bytes/pkt (likely retransmissions) with enough packets.
	rb.Insert([]model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 2400, 60),
	})

	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for small packets, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("40 bytes/pkt should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestRetransmissionDetector_IgnoresUDP(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// UDP with small packets — should not trigger.
	rb.Insert([]model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 53, 17, 2400, 60),
	})

	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("UDP flows should not trigger retransmission detection, got %d", len(advisories))
	}
}

// --- Retransmission Detector (With Counters) tests ---

func TestRetransmissionDetector_WithCounters_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	f := makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 100)
	// 2% retransmission rate
	f.Retransmissions = 2
	rb.Insert([]model.Flow{f})

	cfg := defaultCfg()
	cfg.RetransRateThreshold = 1.0
	cfg.RetransCriticalThreshold = 5.0

	advisories := RetransmissionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING, got %s", advisories[0].Severity)
	}
}

func TestRetransmissionDetector_WithCounters_Critical_Rate(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	f := makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 100)
	// 6% retransmission rate
	f.Retransmissions = 6
	rb.Insert([]model.Flow{f})

	cfg := defaultCfg()
	cfg.RetransRateThreshold = 1.0
	cfg.RetransCriticalThreshold = 5.0

	advisories := RetransmissionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestRetransmissionDetector_WithCounters_Critical_Loss(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	f := makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 100)
	f.PacketLoss = 1
	rb.Insert([]model.Flow{f})

	cfg := defaultCfg()

	advisories := RetransmissionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	// Packet loss should always trigger CRITICAL
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestRetransmissionDetector_WithCounters_OutOfOrder(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	f := makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 100)
	f.OutOfOrder = 1
	rb.Insert([]model.Flow{f})

	cfg := defaultCfg()

	advisories := RetransmissionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	// Out of order without loss or critical retransmission triggers WARNING
	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING, got %s", advisories[0].Severity)
	}
}

func TestRetransmissionDetector_WithCounters_IgnoresUDP(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	f := makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, 17, 50000, 100) // UDP
	f.Retransmissions = 10
	rb.Insert([]model.Flow{f})

	cfg := defaultCfg()

	advisories := RetransmissionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("UDP should not trigger advisory, got %d", len(advisories))
	}
}

// --- Storage Error tests ---

func TestRetransmissionDetector_StorageError(t *testing.T) {
	// mockErrorStorage is defined in scanner_test.go
	advisories := RetransmissionDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}
