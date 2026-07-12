package analysis

import (
	"fmt"
	"testing"
	"time"

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

func TestDataExfiltrationDetector_InternalToInternal(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	// High volume, but internal to internal
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 200000000, 1000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for internal-to-internal traffic, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_PublicToPublic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	// High volume, but public to public (e.g. transit traffic)
	f1 := makeFlow("8.8.8.8", "1.1.1.1", 12345, 80, 6, 200000000, 1000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for public-to-public traffic, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_LowVolume(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	// Internal to public, but low volume
	f1 := makeFlow("10.0.0.1", "8.8.8.8", 12345, 443, 6, 50000000, 100)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for low volume outbound traffic, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_ExfiltrationWarning(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	// Internal to public, high volume (Warning: >= 100MB, < 500MB)
	f1 := makeFlow("10.0.0.1", "8.8.8.8", 12345, 443, 6, 150000000, 1000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Potential Data Exfiltration: 10.0.0.1"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_ExfiltrationCritical(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	now := time.Now()

	// Internal to public, very high volume (Critical: >= 500MB)
	f1 := makeFlow("10.0.0.2", "8.8.8.8", 12345, 443, 6, 600000000, 5000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Potential Data Exfiltration: 10.0.0.2"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_MultipleTargets(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	now := time.Now()

	flows := make([]model.Flow, 0, 5)
	// Create flows hitting 5 external targets, accumulating to > 100MB
	for i := 0; i < 5; i++ {
		dst := fmt.Sprintf("8.8.8.%d", i+1)
		f := makeFlow("192.168.1.100", dst, 12345, 443, 6, 25000000, 100)
		f.Timestamp = now
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

	expectedTitle := "Potential Data Exfiltration: 192.168.1.100"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}
