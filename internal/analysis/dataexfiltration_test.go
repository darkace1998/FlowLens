package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestDataExfiltrationDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_StorageError(t *testing.T) {
	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestDataExfiltrationDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Internal to internal traffic
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 600000000, 1)
	rb.Insert([]model.Flow{f1})

	// External to internal traffic
	f2 := makeFlow("8.8.8.8", "10.0.0.1", 80, 12345, 6, 600000000, 1)
	rb.Insert([]model.Flow{f2})

	// Internal to external, but under threshold (400 MB)
	f3 := makeFlow("10.0.0.2", "8.8.8.8", 12345, 80, 6, 400000000, 1)
	rb.Insert([]model.Flow{f3})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// 600 MB internal to external (Warning threshold is 500 MB)
	f1 := makeFlow("10.0.0.3", "8.8.8.8", 12345, 80, 6, 600000000, 1)
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration Activity: 10.0.0.3"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// 1200 MB internal to external (Critical threshold is 1000 MB)
	f1 := makeFlow("10.0.0.4", "8.8.8.8", 12345, 80, 6, 1200000000, 1)
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration Activity: 10.0.0.4"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_MultipleTargets(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 5)
	for i := 0; i < 5; i++ {
		dst := fmt.Sprintf("8.8.8.%d", i+1)
		// 150 MB each, total 750 MB (Warning)
		f := makeFlow("10.0.0.5", dst, 12345, 80, 6, 150000000, 1)
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}
}
