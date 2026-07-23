package analysis

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestCryptoMiningDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	detector := CryptoMiningDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Fatalf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestCryptoMiningDetector_StorageError(t *testing.T) {
	detector := CryptoMiningDetector{}

	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Fatalf("expected 0 advisories on error, got %d", len(advisories))
	}
	if !strings.Contains(buf.String(), "CryptoMiningDetector: failed to query flows: mock storage error") {
		t.Errorf("expected error log, got %q", buf.String())
	}
}

func TestCryptoMiningDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	detector := CryptoMiningDetector{}

	now := time.Now()
	// Normal HTTPS traffic
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.100"),
			DstAddr:   net.ParseIP("10.0.0.1"),
			Protocol:  6,
			SrcPort:   12345,
			DstPort:   443,
			Packets:   100,
			Bytes:     5000,
		},
	})

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Fatalf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestCryptoMiningDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	detector := CryptoMiningDetector{}
	now := time.Now()

	// 20 packets to port 3333 (Stratum) -> triggers WARNING
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.100"),
			DstAddr:   net.ParseIP("8.8.8.8"),
			Protocol:  6,
			SrcPort:   12345,
			DstPort:   3333,
			Packets:   20,
			Bytes:     1000,
		},
	})

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != WARNING {
		t.Errorf("expected WARNING, got %v", adv.Severity)
	}
	if !strings.Contains(adv.Title, "Crypto Mining Activity: 192.168.1.100") {
		t.Errorf("unexpected title: %s", adv.Title)
	}
}

func TestCryptoMiningDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	detector := CryptoMiningDetector{}
	now := time.Now()

	// 200 packets to port 14444 -> triggers CRITICAL
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("10.0.0.50"),
			DstAddr:   net.ParseIP("9.9.9.9"),
			Protocol:  6,
			SrcPort:   55555,
			DstPort:   14444,
			Packets:   200,
			Bytes:     15000,
		},
	})

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != CRITICAL {
		t.Errorf("expected CRITICAL, got %v", adv.Severity)
	}
}

func TestCryptoMiningDetector_Name(t *testing.T) {
	name := CryptoMiningDetector{}.Name()
	if name != "Crypto Mining Detector" {
		t.Errorf("unexpected name: %s", name)
	}
}
