package analysis

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// --- Port Scan Detector tests ---

func TestScanDetector_NoScan(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50),
		makeFlow("10.0.1.1", "192.168.1.1", 1235, 443, 6, 3000, 30),
	})

	advisories := ScanDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("2 ports should not trigger scan, got %d advisories", len(advisories))
	}
}

func TestScanDetector_ScanDetected(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Simulate a port scan: one source hits 600 unique ports.
	flows := make([]model.Flow, 0, 600)
	for i := 0; i < 600; i++ {
		flows = append(flows, makeFlow("10.0.1.100", "192.168.1.1", 50000, uint16(i+1), 6, 100, 1))
	}
	rb.Insert(flows)

	cfg := defaultCfg()
	cfg.ScanThreshold = 500

	advisories := ScanDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 scan advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("600 ports (threshold 500) should be WARNING, got %s", advisories[0].Severity)
	}
}

func TestScanDetector_CriticalScan(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Simulate a massive scan: 1500+ unique ports (>= 3x threshold of 500).
	flows := make([]model.Flow, 0, 1600)
	for i := 0; i < 1600; i++ {
		flows = append(flows, makeFlow("10.0.1.200", "192.168.1.1", 50000, uint16(i+1), 6, 100, 1))
	}
	rb.Insert(flows)

	cfg := defaultCfg()
	cfg.ScanThreshold = 500

	advisories := ScanDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 scan advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("1600 ports (>= 3x 500) should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestScanDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := ScanDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestScanDetector_IgnoresNonTCPUDP(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// ICMP flows to many destinations shouldn't trigger scan detection.
	flows := make([]model.Flow, 0, 600)
	for i := 0; i < 600; i++ {
		flows = append(flows, makeFlow("10.0.1.100", "192.168.1.1", 0, 0, 1, 100, 1))
	}
	rb.Insert(flows)

	advisories := ScanDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("ICMP flows should not trigger scan detection, got %d advisories", len(advisories))
	}
}

func TestScanDetector_Name(t *testing.T) {
	name := ScanDetector{}.Name()
	expected := "Port Scan Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestScanDetector_DefaultThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Simulate a port scan hitting exactly the default threshold of 500 ports.
	flows := make([]model.Flow, 0, 500)
	for i := 0; i < 500; i++ {
		flows = append(flows, makeFlow("10.0.1.150", "192.168.1.1", 50000, uint16(i+1), 6, 100, 1))
	}
	rb.Insert(flows)

	// Configure with a threshold of 0, which should fall back to 500.
	cfg := defaultCfg()
	cfg.ScanThreshold = 0

	advisories := ScanDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 scan advisory with default threshold, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("500 ports (default threshold 500) should be WARNING, got %s", advisories[0].Severity)
	}

	// Also test negative threshold falls back to 500.
	cfg.ScanThreshold = -10
	advisories = ScanDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 scan advisory with negative threshold, got %d", len(advisories))
	}
}

// mockErrorStorage implements storage.Storage and always returns an error for Recent.
type mockErrorStorage struct{}

func (m mockErrorStorage) Insert(flows []model.Flow) error {
	return nil
}

func (m mockErrorStorage) Recent(d time.Duration, limit int) ([]model.Flow, error) {
	return nil, errors.New("mock storage error")
}

func (m mockErrorStorage) Close() error {
	return nil
}

func TestScanDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := ScanDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
	if !strings.Contains(buf.String(), "ScanDetector: failed to query flows: mock storage error") {
		t.Errorf("expected error log to contain 'ScanDetector: failed to query flows: mock storage error', got %q", buf.String())
	}
}

func TestScanDetector_StorageError_ExplicitNil(t *testing.T) {
	advisories := ScanDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}
