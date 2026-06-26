package analysis

import (
	"fmt"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestEngine_RunsAnalyzers(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Single host = 100% traffic → CRITICAL advisory (exceeds 25% threshold).
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 10000, 100),
	})

	cfg := defaultCfg()
	cfg.Interval = 50 * time.Millisecond

	engine := NewEngine(cfg, rb, TopTalkers{})
	engine.Start()
	time.Sleep(100 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) == 0 {
		t.Error("engine should produce at least one advisory")
	}
}

func TestEngine_EmptyStore(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	cfg := defaultCfg()

	engine := NewEngine(cfg, rb, TopTalkers{}, ProtocolDistribution{}, ScanDetector{})
	engine.Start()
	time.Sleep(50 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestEngine_SortsBySeverity(t *testing.T) {
	rb := storage.NewRingBuffer(10000)

	// One dominant source (>50% = CRITICAL) and one at ~30% (WARNING).
	flows := []model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 70000, 700),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 80, 6, 30000, 300),
	}
	rb.Insert(flows)

	cfg := defaultCfg()
	cfg.TopTalkersCount = 2

	engine := NewEngine(cfg, rb, TopTalkers{})
	engine.Start()
	time.Sleep(50 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) < 2 {
		t.Fatalf("expected at least 2 advisories, got %d", len(advisories))
	}
	// First should be highest severity.
	if advisories[0].Severity < advisories[len(advisories)-1].Severity {
		t.Error("advisories should be sorted with highest severity first")
	}
}

func TestEngine_AdvisoryHistory(t *testing.T) {
	rb := storage.NewRingBuffer(10000)

	// First cycle: insert a dominant host to trigger CRITICAL.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 100000, 1000),
	})

	cfg := defaultCfg()
	cfg.Interval = 50 * time.Millisecond
	cfg.TopTalkersCount = 1

	engine := NewEngine(cfg, rb, TopTalkers{})
	engine.Start()
	time.Sleep(80 * time.Millisecond)

	// Should have the advisory.
	advisories := engine.Advisories()
	if len(advisories) == 0 {
		t.Fatal("expected at least 1 advisory after first cycle")
	}
	if advisories[0].Resolved {
		t.Error("active advisory should not be resolved")
	}

	// Dilute the ring buffer: add enough traffic from many hosts to push
	// 10.0.1.1 well below the 25% threshold.
	for i := 0; i < 200; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.2.%d", i), "192.168.1.1", uint16(2000+i), 80, 6, 5000, 50),
		})
	}

	time.Sleep(80 * time.Millisecond)
	engine.Stop()

	advisories = engine.Advisories()
	// The old advisory should still be present but marked resolved.
	foundResolved := false
	for _, a := range advisories {
		if a.Title == "Top Talker: 10.0.1.1" && a.Resolved {
			foundResolved = true
		}
	}
	if !foundResolved {
		t.Error("old advisory should be present and marked as resolved")
	}
}

func TestFormatWindowShort(t *testing.T) {
	tests := []struct {
		d        time.Duration
		expected string
	}{
		{500 * time.Millisecond, "500ms"},
		{2*time.Hour + 30*time.Minute, "2h 30m"},
		{2 * time.Hour, "2h"},
		{5*time.Minute + 15*time.Second, "5m 15s"},
		{5 * time.Minute, "5m"},
		{45 * time.Second, "45s"},
	}

	for _, tc := range tests {
		result := formatWindowShort(tc.d)
		if result != tc.expected {
			t.Errorf("formatWindowShort(%v) = %q, want %q", tc.d, result, tc.expected)
		}
	}
}

func TestQueryWindow(t *testing.T) {
	// Test configured window
	cfg := config.AnalysisConfig{QueryWindow: 5 * time.Minute}
	if w := queryWindow(cfg); w != 5*time.Minute {
		t.Errorf("expected 5m, got %v", w)
	}

	// Test default fallback
	emptyCfg := config.AnalysisConfig{}
	if w := queryWindow(emptyCfg); w != 10*time.Minute {
		t.Errorf("expected 10m fallback, got %v", w)
	}
}

// mockSpamAnalyzer generates a large number of advisories to test history truncation
type mockSpamAnalyzer struct{}

func (m mockSpamAnalyzer) Name() string { return "SpamAnalyzer" }
func (m mockSpamAnalyzer) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	advs := make([]Advisory, 150)
	for i := 0; i < 150; i++ {
		advs[i] = Advisory{
			Title:     fmt.Sprintf("Spam Advisory %d", i),
			Severity:  INFO,
			Timestamp: time.Now(),
		}
	}
	return advs
}

func TestEngine_MaxHistory(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	cfg := defaultCfg()
	cfg.Interval = 50 * time.Millisecond

	engine := NewEngine(cfg, rb, mockSpamAnalyzer{})
	engine.Start()
	time.Sleep(100 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) != maxAdvisoryHistory {
		t.Errorf("expected history to be truncated to %d, got %d", maxAdvisoryHistory, len(advisories))
	}
}

// mockSortAnalyzer returns a specific set of advisories to test sorting rules
type mockSortAnalyzer struct{}

func (m mockSortAnalyzer) Name() string { return "SortAnalyzer" }
func (m mockSortAnalyzer) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	now := time.Now()
	return []Advisory{
		{Title: "B - Active Warning", Severity: WARNING, Timestamp: now.Add(-time.Hour)},
		{Title: "C - Active Critical", Severity: CRITICAL, Timestamp: now},
		{Title: "D - Active Critical Recent", Severity: CRITICAL, Timestamp: now.Add(time.Hour)},
	}
}

func TestEngine_Sorting(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	cfg := defaultCfg()
	cfg.Interval = 50 * time.Millisecond

	engine := NewEngine(cfg, rb, mockSortAnalyzer{})

	// Add a resolved advisory manually to test active vs resolved sorting
	now := time.Now()
	engine.advisories = []Advisory{
		{Title: "A - Resolved Critical", Resolved: true, Severity: CRITICAL, Timestamp: now},
	}

	engine.Start()
	time.Sleep(100 * time.Millisecond)
	engine.Stop()

	advs := engine.Advisories()

	// Expect 4 advisories total
	if len(advs) != 4 {
		t.Fatalf("expected 4 advisories, got %d", len(advs))
	}

	// 1. D - Active Critical Recent (Active, Critical, Most Recent)
	if advs[0].Title != "D - Active Critical Recent" {
		t.Errorf("expected 1st advisory to be 'D - Active Critical Recent', got %s", advs[0].Title)
	}

	// 2. C - Active Critical (Active, Critical, Older)
	if advs[1].Title != "C - Active Critical" {
		t.Errorf("expected 2nd advisory to be 'C - Active Critical', got %s", advs[1].Title)
	}

	// 3. B - Active Warning (Active, Warning)
	if advs[2].Title != "B - Active Warning" {
		t.Errorf("expected 3rd advisory to be 'B - Active Warning', got %s", advs[2].Title)
	}

	// 4. A - Resolved Critical (Resolved always goes last, despite being Critical)
	if advs[3].Title != "A - Resolved Critical" {
		t.Errorf("expected 4th advisory to be 'A - Resolved Critical', got %s", advs[3].Title)
	}
}
