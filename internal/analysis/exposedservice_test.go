package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestExposedServiceDetector_NoData(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := ExposedServiceDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	// Internal to Internal
	rb.Insert([]model.Flow{makeFlow("192.168.1.100", "10.0.0.5", 12345, 3389, 6, 5000, 50)})
	// Public to Public
	rb.Insert([]model.Flow{makeFlow("8.8.8.8", "1.1.1.1", 12345, 3389, 6, 5000, 50)})
	// Public to Internal but on safe port (80)
	rb.Insert([]model.Flow{makeFlow("8.8.8.8", "192.168.1.5", 12345, 80, 6, 5000, 50)})
	// Public to Internal on risky port but small packet count (likely dropped scanner SYN)
	rb.Insert([]model.Flow{makeFlow("8.8.8.8", "10.0.0.5", 12345, 3389, 6, 100, 1)})

	detector := ExposedServiceDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal/dropped traffic, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_Exposed(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	// Public IP to Internal IP on RDP port (3389) with > 3 packets
	rb.Insert([]model.Flow{makeFlow("8.8.8.8", "192.168.1.10", 12345, 3389, 6, 5000, 50)})

	detector := ExposedServiceDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", adv.Severity)
	}
	expectedTitle := "Exposed RDP Service: 192.168.1.10"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}

func TestExposedServiceDetector_MultipleSources(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	flows := []model.Flow{
		makeFlow("8.8.8.8", "10.0.0.50", 12345, 445, 6, 5000, 50),
		makeFlow("1.1.1.1", "10.0.0.50", 23456, 445, 6, 5000, 50),
		makeFlow("9.9.9.9", "10.0.0.50", 34567, 445, 6, 5000, 50),
	}
	rb.Insert(flows)

	detector := ExposedServiceDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	expectedTitle := "Exposed SMB Service: 10.0.0.50"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}
