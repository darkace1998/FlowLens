package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestLongConnectionDetector_Name(t *testing.T) {
	name := LongConnectionDetector{}.Name()
	expected := "Long Connection Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestLongConnectionDetector_StorageError(t *testing.T) {
	advisories := LongConnectionDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestLongConnectionDetector_ZeroFlows(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := LongConnectionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when no flows, got %d", len(advisories))
	}
}

func TestLongConnectionDetector_NoLongConnections(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	f1 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000, 10)
	f1.Duration = 5 * time.Minute
	f2 := makeFlow("10.0.1.2", "192.168.1.1", 1235, 443, 6, 2000, 20)
	f2.Duration = 10 * time.Minute

	rb.Insert([]model.Flow{f1, f2})

	cfg := defaultCfg()
	cfg.LongConnectionThreshold = 1 * time.Hour

	advisories := LongConnectionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when no long connections exist, got %d", len(advisories))
	}
}

func TestLongConnectionDetector_WithLongConnections(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	f1 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000, 10)
	f1.Duration = 2 * time.Hour // Long TCP connection
	f2 := makeFlow("10.0.1.2", "192.168.1.1", 1235, 443, 6, 2000, 20)
	f2.Duration = 10 * time.Minute // Short connection
	f3 := makeFlow("10.0.1.3", "192.168.1.1", 1236, 53, 17, 3000, 30)
	f3.Duration = 90 * time.Minute // Long UDP connection
	f4 := makeFlow("10.0.1.4", "192.168.1.1", 1237, 0, 1, 4000, 40)
	f4.Duration = 3 * time.Hour // Long ICMP connection (should be ignored)

	rb.Insert([]model.Flow{f1, f2, f3, f4})

	cfg := defaultCfg()
	cfg.LongConnectionThreshold = 1 * time.Hour

	advisories := LongConnectionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advisories))
	}

	// Verify advisories
	hasTCP := false
	hasUDP := false
	for _, a := range advisories {
		if a.Severity != WARNING {
			t.Errorf("expected severity WARNING, got %v", a.Severity)
		}
		if strings.Contains(a.Title, "10.0.1.1:1234") {
			hasTCP = true
			if !strings.Contains(a.Description, "TCP") {
				t.Errorf("expected description to mention TCP, got %q", a.Description)
			}
			if !strings.Contains(a.Description, "2h") {
				t.Errorf("expected description to mention 2h duration, got %q", a.Description)
			}
		}
		if strings.Contains(a.Title, "10.0.1.3:1236") {
			hasUDP = true
			if !strings.Contains(a.Description, "UDP") {
				t.Errorf("expected description to mention UDP, got %q", a.Description)
			}
			if !strings.Contains(a.Description, "1h 30m") {
				t.Errorf("expected description to mention 1h 30m duration, got %q", a.Description)
			}
		}
	}

	if !hasTCP {
		t.Error("missing advisory for long TCP connection")
	}
	if !hasUDP {
		t.Error("missing advisory for long UDP connection")
	}
}

func TestLongConnectionDetector_DefaultFallback(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	f1 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000, 10)
	f1.Duration = 90 * time.Minute // 1.5 hours

	rb.Insert([]model.Flow{f1})

	cfg := defaultCfg()
	cfg.LongConnectionThreshold = 0 // Should fall back to 1 hour

	advisories := LongConnectionDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory due to default fallback, got %d", len(advisories))
	}
}
