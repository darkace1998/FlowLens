package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestLateralMovementDetector_Name(t *testing.T) {
	detector := LateralMovementDetector{}
	expected := "Lateral Movement Detector"
	if detector.Name() != expected {
		t.Errorf("expected %q, got %q", expected, detector.Name())
	}
}

func TestLateralMovementDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := LateralMovementDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestLateralMovementDetector_StorageError(t *testing.T) {
	detector := LateralMovementDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestLateralMovementDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Below threshold connections (e.g. 5 distinct targets)
	for i := 1; i <= 5; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i)
		f := makeFlow("10.0.0.1", dst, 10000+uint16(i), 445, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	// Normal web traffic (not lateral movement ports)
	for i := 1; i <= 30; i++ {
		dst := fmt.Sprintf("10.0.1.%d", i)
		f := makeFlow("10.0.0.1", dst, 10000+uint16(i), 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	detector := LateralMovementDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestLateralMovementDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// At threshold connections (e.g. 20 distinct targets)
	for i := 1; i <= 20; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i)
		f := makeFlow("10.0.0.2", dst, 10000+uint16(i), 445, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	detector := LateralMovementDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}
	expectedTitle := "Lateral Movement Detected: 10.0.0.2"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestLateralMovementDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Above critical threshold connections (e.g. 60 distinct targets)
	for i := 1; i <= 60; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i)
		f := makeFlow("10.0.0.3", dst, 10000+uint16(i), 3389, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	detector := LateralMovementDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}
}
