package analysis

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestAnomalyDetector_NoSpikeNoDrop(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	now := time.Now()

	interval := 60 * time.Second
	cfg := config.AnalysisConfig{Interval: interval, QueryWindow: 10 * time.Minute}

	// Create baseline buckets
	for i := 1; i <= 8; i++ {
		tFlow := now.Add(-time.Duration(i) * interval).Add(-time.Second) // middle of bucket
		f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50)
		f.Timestamp = tFlow
		rb.Insert([]model.Flow{f})
	}

	// Create current bucket (within sampleWindow)
	fCurrent := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5100, 50)
	fCurrent.Timestamp = now.Add(-time.Second)
	rb.Insert([]model.Flow{fCurrent})

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for stable traffic, got %d", len(advisories))
	}
}

func TestAnomalyDetector_SpikeDetected(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	now := time.Now()

	interval := 60 * time.Second
	cfg := config.AnalysisConfig{Interval: interval, QueryWindow: 10 * time.Minute}

	// Create baseline buckets
	for i := 1; i <= 8; i++ {
		tFlow := now.Add(-time.Duration(i) * interval).Add(-time.Second)
		f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, uint64(5000+i*10), 50)
		f.Timestamp = tFlow
		rb.Insert([]model.Flow{f})
	}

	// Create current bucket (within sampleWindow) with huge bytes
	fCurrent := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 500000, 5000)
	fCurrent.Timestamp = now.Add(-time.Second)
	rb.Insert([]model.Flow{fCurrent})

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	if len(advisories) == 0 {
		t.Fatalf("expected advisory for traffic spike, got 0")
	}
	if advisories[0].Title != "Traffic Spike Detected" {
		t.Errorf("unexpected advisory title: %s", advisories[0].Title)
	}
	if !strings.Contains(advisories[0].Description, "above baseline mean") {
		t.Errorf("unexpected description: %s", advisories[0].Description)
	}
}

func TestAnomalyDetector_DropDetected(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	now := time.Now()

	interval := 60 * time.Second
	cfg := config.AnalysisConfig{Interval: interval, QueryWindow: 10 * time.Minute}

	// Create baseline buckets
	for i := 1; i <= 8; i++ {
		tFlow := now.Add(-time.Duration(i) * interval).Add(-time.Second)
		f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, uint64(50000+i*10), 500)
		f.Timestamp = tFlow
		rb.Insert([]model.Flow{f})
	}

	// Create current bucket (within sampleWindow) with very few bytes
	fCurrent := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 100, 1)
	fCurrent.Timestamp = now.Add(-time.Second)
	rb.Insert([]model.Flow{fCurrent})

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	if len(advisories) == 0 {
		t.Fatalf("expected advisory for traffic drop, got 0")
	}
	if advisories[0].Title != "Traffic Drop Detected" {
		t.Errorf("unexpected advisory title: %s", advisories[0].Title)
	}
	if !strings.Contains(advisories[0].Description, "below baseline mean") {
		t.Errorf("unexpected description: %s", advisories[0].Description)
	}
}

type mockAnomalyErrorStorage struct {
	storage.Storage
}

func (m mockAnomalyErrorStorage) Recent(d time.Duration, limit int) ([]model.Flow, error) {
	return nil, errors.New("simulated error")
}

func TestAnomalyDetector_StorageError(t *testing.T) {
	mockStore := mockAnomalyErrorStorage{}
	cfg := config.AnalysisConfig{Interval: 60 * time.Second, QueryWindow: 10 * time.Minute}

	advisories := AnomalyDetector{}.Analyze(mockStore, cfg)
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestAnomalyDetector_InsufficientBaseline(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	now := time.Now()

	interval := 60 * time.Second
	cfg := config.AnalysisConfig{Interval: interval, QueryWindow: 10 * time.Minute}

	// Insert only one baseline flow
	tFlow := now.Add(-interval).Add(-time.Second)
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50)
	f.Timestamp = tFlow
	rb.Insert([]model.Flow{f})

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for insufficient baseline data, got %d", len(advisories))
	}
}
