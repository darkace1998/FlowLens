package analysis

import (
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// regressionPanicAnalyzer always panics, simulating a faulty detector.
type regressionPanicAnalyzer struct{}

func (regressionPanicAnalyzer) Name() string { return "regression-panic" }
func (regressionPanicAnalyzer) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	panic("boom")
}

// regressionOKAnalyzer returns one advisory, simulating a healthy detector.
type regressionOKAnalyzer struct{}

func (regressionOKAnalyzer) Name() string { return "regression-ok" }
func (regressionOKAnalyzer) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	return []Advisory{{Severity: INFO, Title: "regression-ok-advisory", Timestamp: time.Now()}}
}

// Regression: one panicking analyzer must not crash the whole engine; the
// healthy analyzer must still produce its advisory.
func TestEngine_RunAllRecoversFromPanic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	engine := NewEngine(defaultCfg(), rb, regressionPanicAnalyzer{}, regressionOKAnalyzer{})

	// Must not panic.
	engine.runAll()

	advisories := engine.Advisories()
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory from the healthy analyzer, got %d", len(advisories))
	}
	if advisories[0].Title != "regression-ok-advisory" {
		t.Errorf("unexpected advisory title: %q", advisories[0].Title)
	}
}

// Regression: Start/Stop with a panicking analyzer must not crash, and Stop
// must be safe to call more than once.
func TestEngine_PanickingAnalyzerStartStop(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	cfg := defaultCfg()
	cfg.Interval = 20 * time.Millisecond

	engine := NewEngine(cfg, rb, regressionPanicAnalyzer{}, regressionOKAnalyzer{})
	engine.Start()
	time.Sleep(60 * time.Millisecond)
	engine.Stop()
	engine.Stop() // idempotent — must not panic on double close

	if len(engine.Advisories()) == 0 {
		t.Error("expected the healthy analyzer's advisory to be recorded")
	}
}

// Regression: Stop must be idempotent even without Start.
func TestEngine_StopIdempotent(t *testing.T) {
	engine := NewEngine(defaultCfg(), storage.NewRingBuffer(10))
	engine.Stop()
	engine.Stop()
}
