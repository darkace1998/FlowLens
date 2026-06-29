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

func TestBroadcastStormDetector_NoData(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	advisories := BroadcastStormDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestBroadcastStormDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	now := time.Now()

	// Normal traffic: Broadcast packets below threshold (10,000)
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.10"),
			DstAddr:   net.IPv4bcast, // 255.255.255.255
			Packets:   9000,
			Bytes:     9000 * 64,
		},
	})

	advisories := BroadcastStormDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestBroadcastStormDetector_WarningStorm(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	now := time.Now()

	// Storm traffic: 15,000 Broadcast packets (>= 10,000 and < 50,000)
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.10"),
			DstMAC:    net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			Packets:   15000,
			Bytes:     15000 * 64,
		},
	})

	advisories := BroadcastStormDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for broadcast storm, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("expected severity WARNING, got %v", advisories[0].Severity)
	}
	if advisories[0].Title != "Broadcast Storm Detected: 192.168.1.10" {
		t.Errorf("unexpected title: %s", advisories[0].Title)
	}
	if !strings.Contains(advisories[0].Description, "15.0K broadcast/multicast packets") {
		t.Errorf("unexpected description: %s", advisories[0].Description)
	}
}

func TestBroadcastStormDetector_CriticalStorm(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	now := time.Now()

	// Critical storm traffic: 60,000 Multicast packets (>= 50,000)
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.20"),
			DstAddr:   net.ParseIP("224.0.0.1"),
			Packets:   60000,
			Bytes:     60000 * 64,
		},
	})

	advisories := BroadcastStormDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for broadcast storm, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected severity CRITICAL, got %v", advisories[0].Severity)
	}
	if advisories[0].Title != "Broadcast Storm Detected: 192.168.1.20" {
		t.Errorf("unexpected title: %s", advisories[0].Title)
	}
	if !strings.Contains(advisories[0].Description, "60.0K broadcast/multicast packets") {
		t.Errorf("unexpected description: %s", advisories[0].Description)
	}
}

func TestBroadcastStormDetector_IgnoresUnicast(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	now := time.Now()

	// Huge amount of unicast packets, shouldn't trigger broadcast storm
	rb.Insert([]model.Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("192.168.1.30"),
			DstAddr:   net.ParseIP("10.0.0.1"),
			DstMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			Packets:   100000,
			Bytes:     100000 * 64,
		},
	})

	advisories := BroadcastStormDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("Unicast flows should not trigger broadcast storm detection, got %d advisories", len(advisories))
	}
}

func TestBroadcastStormDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := BroadcastStormDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
	if !strings.Contains(buf.String(), "BroadcastStormDetector: failed to query recent flows: mock storage error") {
		t.Errorf("expected storage error log, got %q", buf.String())
	}
}

func TestBroadcastStormDetector_Name(t *testing.T) {
	name := BroadcastStormDetector{}.Name()
	expected := "Broadcast Storm Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}
