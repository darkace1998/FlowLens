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

func TestDataExfiltrationDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}
	now := time.Now()

	// Internal to external, but below threshold
	f1 := makeFlow("192.168.1.100", "8.8.8.8", 12345, 443, 6, 100*1024*1024, 1000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	// Internal to internal, above threshold (should be ignored)
	f2 := makeFlow("192.168.1.100", "10.0.0.5", 12345, 445, 6, 600*1024*1024, 5000)
	f2.Timestamp = now
	rb.Insert([]model.Flow{f2})

	// External to internal, above threshold (should be ignored)
	f3 := makeFlow("8.8.8.8", "192.168.1.100", 443, 12345, 6, 600*1024*1024, 5000)
	f3.Timestamp = now
	rb.Insert([]model.Flow{f3})

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}
	now := time.Now()

	// Internal to external, just above threshold (WARNING)
	f1 := makeFlow("192.168.1.100", "8.8.8.8", 12345, 443, 6, 600*1024*1024, 5000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration: 192.168.1.100 → 8.8.8.8"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}
	now := time.Now()

	// Internal to external, above 5x threshold (CRITICAL)
	f1 := makeFlow("192.168.1.100", "8.8.8.8", 12345, 443, 6, 3000*1024*1024, 25000)
	f1.Timestamp = now
	rb.Insert([]model.Flow{f1})

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration: 192.168.1.100 → 8.8.8.8"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_MultipleFlows(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}
	now := time.Now()

	// Internal to external, split across multiple flows
	for i := 0; i < 6; i++ {
		f := makeFlow("10.0.0.50", "9.9.9.9", uint16(10000+i), 443, 6, 100*1024*1024, 1000)
		f.Timestamp = now
		rb.Insert([]model.Flow{f})
	}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Data Exfiltration: 10.0.0.50 → 9.9.9.9"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_Top10(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := DataExfiltrationDetector{}
	now := time.Now()

	// 15 unique targets, all above threshold
	for i := 0; i < 15; i++ {
		dst := fmt.Sprintf("8.8.8.%d", i+1)
		f := makeFlow("192.168.1.200", dst, 12345, 443, 6, uint64(600+i)*1024*1024, 5000)
		f.Timestamp = now
		rb.Insert([]model.Flow{f})
	}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 10 {
		t.Fatalf("expected 10 advisories (limited to top 10), got %d", len(advisories))
	}
}
