package analysis

import (
	"fmt"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestDataExfiltrationDetector_Name(t *testing.T) {
	name := DataExfiltrationDetector{}.Name()
	expected := "Data Exfiltration Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestDataExfiltrationDetector_StorageError(t *testing.T) {
	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestDataExfiltrationDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on empty store, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_NoExfiltration(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Internal to internal traffic
	f1 := makeFlow("10.0.0.1", "10.0.0.2", 12345, 80, 6, 600000000, 6000)
	f1.Timestamp = time.Now()
	rb.Insert([]model.Flow{f1})

	// External to internal traffic
	f2 := makeFlow("8.8.8.8", "10.0.0.1", 443, 12345, 6, 600000000, 6000)
	f2.Timestamp = time.Now()
	rb.Insert([]model.Flow{f2})

	// Internal to external, but low volume
	f3 := makeFlow("10.0.0.1", "8.8.8.8", 12345, 443, 6, 100000000, 1000)
	f3.Timestamp = time.Now()
	rb.Insert([]model.Flow{f3})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Internal to external traffic > 500MB (e.g. 600MB)
	f1 := makeFlow("10.0.0.1", "8.8.8.8", 12345, 443, 6, 600000000, 6000)
	f1.Timestamp = time.Now()
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration Activity: 10.0.0.1 → 8.8.8.8"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Internal to external traffic >= 2.5GB (e.g. 3GB)
	f1 := makeFlow("10.0.0.2", "8.8.8.8", 12345, 443, 6, 3000000000, 30000)
	f1.Timestamp = time.Now()
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration Activity: 10.0.0.2 → 8.8.8.8"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_MultipleHosts(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Traffic from multiple internal hosts to various external destinations
	flows := []model.Flow{}
	for i := 0; i < 15; i++ {
		src := fmt.Sprintf("10.0.0.%d", i+1)
		dst := fmt.Sprintf("8.8.8.%d", i+1)
		// 600MB each
		f := makeFlow(src, dst, 12345, 443, 6, 600000000, 6000)
		f.Timestamp = time.Now()
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 10 {
		t.Errorf("expected at most 10 advisories (limited), got %d", len(advisories))
	}
}
