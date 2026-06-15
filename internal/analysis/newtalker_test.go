package analysis

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// --- New Talker Detector tests ---

func TestNewTalkerDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := NewTalkerDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestNewTalkerDetector_AllKnownHosts(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: host was active 5 minutes ago.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: same host is still active.
	f2 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("known host should produce 0 advisories, got %d", len(advisories))
	}
}

func TestNewTalkerDetector_NewHost(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: only 10.0.1.1 was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: new host 10.0.1.99 appears with significant traffic.
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for new host, got %d", len(advisories))
	}
	if advisories[0].Title != "New Talker: 10.0.1.99" {
		t.Errorf("expected advisory for 10.0.1.99, got %q", advisories[0].Title)
	}
}

func TestNewTalkerDetector_SmallTrafficIgnored(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: host was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: new host with tiny traffic (below threshold).
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 100, 1)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("small traffic new host should be ignored, got %d advisories", len(advisories))
	}
}

func TestNewTalkerDetector_Name(t *testing.T) {
	name := NewTalkerDetector{}.Name()
	expected := "New Talker Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestNewTalkerDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := NewTalkerDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "NewTalkerDetector: failed to query flows:") {
		t.Errorf("expected log to contain \"NewTalkerDetector: failed to query flows:\", got %q", logOutput)
	}
}

func TestNewTalkerDetector_IntervalFallback(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 0 // Should fallback to 60s

	now := time.Now()
	// Baseline: only 10.0.1.1 was active > 60s ago
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-65 * time.Second)
	rb.Insert([]model.Flow{f})

	// Recent: new host 10.0.1.99 appears
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory with fallback interval, got %d", len(advisories))
	}
	if advisories[0].Title != "New Talker: 10.0.1.99" {
		t.Errorf("expected advisory for 10.0.1.99, got %q", advisories[0].Title)
	}
}

func TestNewTalkerDetector_NoBaseline(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// All flows are recent, no baseline flows
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when no baseline exists, got %d", len(advisories))
	}
}

func TestNewTalkerDetector_CriticalSeverity(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: only 10.0.1.1 was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: new host 10.0.1.99 appears with > 1MB traffic.
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 1000001, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for new host, got %d", len(advisories))
	}
	if advisories[0].Title != "New Talker: 10.0.1.99" {
		t.Errorf("expected advisory for 10.0.1.99, got %q", advisories[0].Title)
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity for >1MB traffic, got %s", advisories[0].Severity)
	}
}

func TestNewTalkerDetector_Over10Talkers(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: only 10.0.1.1 was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: 15 new hosts appear
	for i := 0; i < 15; i++ {
		src := fmt.Sprintf("10.0.1.%d", 100+i)
		f2 := makeFlow(src, "192.168.1.1", 1234, 80, 6, uint64(50000+i*1000), 500)
		f2.Timestamp = now.Add(-10 * time.Second)
		rb.Insert([]model.Flow{f2})
	}

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 10 {
		t.Fatalf("expected exactly 10 advisories for >10 new talkers, got %d", len(advisories))
	}
}

func TestNewTalkerDetector_AccumulateHostTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: only 10.0.1.1 was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: new host 10.0.1.99 appears with 2 flows, accumulating traffic.
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 6000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})
	f3 := makeFlow("10.0.1.99", "192.168.1.1", 1235, 80, 6, 5000, 500) // 6000+5000 = 11000 > 10000
	f3.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f3})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for accumulated traffic > min threshold, got %d", len(advisories))
	}
}
