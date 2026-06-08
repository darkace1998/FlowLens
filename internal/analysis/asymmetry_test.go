package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestFlowAsymmetry_StorageError(t *testing.T) {
	advisories := FlowAsymmetry{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestFlowAsymmetry_Name(t *testing.T) {
	name := FlowAsymmetry{}.Name()
	expected := "Flow Asymmetry"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestFlowAsymmetry_CustomThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Ratio is 5:1 (500000 / 100000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 500000, 500),
		makeFlow("192.168.1.1", "10.0.1.1", 80, 1234, 6, 100000, 100),
	})

	cfg := defaultCfg()
	// Default threshold is 10, so this shouldn't trigger
	cfg.AsymmetryThreshold = 0
	advisories := FlowAsymmetry{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("5:1 ratio should not trigger with default threshold 10, got %d", len(advisories))
	}

	// But if we set threshold to 4, it should trigger
	cfg.AsymmetryThreshold = 4
	advisories = FlowAsymmetry{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Errorf("5:1 ratio should trigger with custom threshold 4, got %d", len(advisories))
	}

	// Negative threshold defaults to 10, shouldn't trigger
	cfg.AsymmetryThreshold = -5
	advisories = FlowAsymmetry{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("5:1 ratio should not trigger with negative threshold (defaults to 10), got %d", len(advisories))
	}
}

func TestFlowAsymmetry_HighToLow(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Flow from "192.168.1.1" (high) to "10.0.1.1" (low) is much larger
	rb.Insert([]model.Flow{
		// low to high
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 10000, 10),
		// high to low (much larger, 50x)
		makeFlow("192.168.1.1", "10.0.1.1", 80, 1234, 6, 500000, 500),
	})

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("50:1 ratio should be WARNING, got %s", advisories[0].Severity)
	}
}
