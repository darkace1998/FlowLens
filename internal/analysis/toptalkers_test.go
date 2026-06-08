package analysis

import (
	"testing"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestTopTalkers_Name(t *testing.T) {
	name := TopTalkers{}.Name()
	expected := "Top Talkers"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestTopTalkers_StorageError(t *testing.T) {
	advisories := TopTalkers{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestTopTalkers_ZeroBytes(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 0, 50),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 443, 6, 0, 30),
	})
	advisories := TopTalkers{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when total bytes is 0, got %d", len(advisories))
	}
}

func TestTopTalkers_NegativePctFallback(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 6000, 50),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 443, 6, 4000, 30),
	})

	cfg := defaultCfg()
	cfg.TopTalkerPercent = -5 // Should fall back to 25

	advisories := TopTalkers{}.Analyze(rb, cfg)
	if len(advisories) != 2 {
		t.Errorf("expected 2 advisories with negative pct fallback, got %d", len(advisories))
	}
}

func TestBuildTopTalkersReport(t *testing.T) {
	flows := []model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1000, 80, 6, 100, 10),
		makeFlow("10.0.1.2", "192.168.1.1", 1000, 80, 6, 200, 20),
		makeFlow("10.0.1.1", "192.168.1.1", 1000, 80, 6, 300, 30),
		makeFlow("10.0.1.3", "192.168.1.1", 1000, 80, 6, 50, 5),
	}

	// Total: 10.0.1.1 = 400 bytes, 40 pkts
	// Total: 10.0.1.2 = 200 bytes, 20 pkts
	// Total: 10.0.1.3 = 50 bytes, 5 pkts

	report := BuildTopTalkersReport(flows, 2)

	if len(report) != 2 {
		t.Fatalf("expected report length 2, got %d", len(report))
	}

	if report[0].IP != "10.0.1.1" || report[0].Bytes != 400 || report[0].Packets != 40 {
		t.Errorf("expected first entry 10.0.1.1 (400B, 40P), got %s (%dB, %dP)", report[0].IP, report[0].Bytes, report[0].Packets)
	}

	if report[1].IP != "10.0.1.2" || report[1].Bytes != 200 || report[1].Packets != 20 {
		t.Errorf("expected second entry 10.0.1.2 (200B, 20P), got %s (%dB, %dP)", report[1].IP, report[1].Bytes, report[1].Packets)
	}

	// Test n > len(entries)
	reportAll := BuildTopTalkersReport(flows, 10)
	if len(reportAll) != 3 {
		t.Fatalf("expected report length 3, got %d", len(reportAll))
	}
}
