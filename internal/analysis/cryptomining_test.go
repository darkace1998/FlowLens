package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestCryptominingDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := CryptominingDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on empty store, got %d", len(advisories))
	}
}

func TestCryptominingDetector_StorageError(t *testing.T) {
	detector := CryptominingDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestCryptominingDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	// Traffic to non-mining port
	f1 := model.Flow{
		Timestamp: now,
		SrcAddr:   net.ParseIP("192.168.1.10"),
		DstAddr:   net.ParseIP("10.0.0.1"),
		DstPort:   80,
		Protocol:  6,
		Bytes:     5000,
		Packets:   200,
		Duration:  120 * time.Second,
	}
	rb.Insert([]model.Flow{f1})

	// Traffic to mining port but low duration/packets
	f2 := model.Flow{
		Timestamp: now,
		SrcAddr:   net.ParseIP("192.168.1.11"),
		DstAddr:   net.ParseIP("203.0.113.1"),
		DstPort:   3333,
		Protocol:  6,
		Bytes:     100,
		Packets:   10, // below 100 packets
		Duration:  30 * time.Second, // below 60 seconds
	}
	rb.Insert([]model.Flow{f2})

	detector := CryptominingDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestCryptominingDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()
	cfg := config.AnalysisConfig{QueryWindow: 10 * time.Minute}

	f := model.Flow{
		Timestamp: now,
		SrcAddr:   net.ParseIP("192.168.1.12"),
		DstAddr:   net.ParseIP("8.8.8.8"),
		DstPort:   4444, // Mining port
		Protocol:  6,
		Bytes:     1000000, // 1MB, below 10MB critical threshold
		Packets:   500,     // > 100
		Duration:  120 * time.Second, // > 60s, < 300s (5 * 60) for warning
	}
	rb.Insert([]model.Flow{f})

	detector := CryptominingDetector{}
	advisories := detector.Analyze(rb, cfg)

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Cryptomining Activity: 192.168.1.12"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestCryptominingDetector_CriticalDuration(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	f := model.Flow{
		Timestamp: now,
		SrcAddr:   net.ParseIP("10.1.2.3"),
		DstAddr:   net.ParseIP("9.9.9.9"),
		DstPort:   8332, // Bitcoin RPC
		Protocol:  6,
		Bytes:     500000, // 500KB
		Packets:   150,
		Duration:  400 * time.Second, // > 300s (5 * 60) for critical
	}
	rb.Insert([]model.Flow{f})

	detector := CryptominingDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}
}

func TestCryptominingDetector_CriticalBytes(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	f := model.Flow{
		Timestamp: now,
		SrcAddr:   net.ParseIP("192.168.100.5"),
		DstAddr:   net.ParseIP("4.4.4.4"),
		DstPort:   14444, // Stratum (Monero)
		Protocol:  6,
		Bytes:     15 * 1024 * 1024, // 15MB (> 10MB critical threshold)
		Packets:   2000,
		Duration:  100 * time.Second, // > 60s
	}
	rb.Insert([]model.Flow{f})

	detector := CryptominingDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}
}
