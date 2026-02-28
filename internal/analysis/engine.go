package analysis

import (
	"sort"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// queryWindow returns the configured analysis query window, falling back to
// 10 minutes if not set.
func queryWindow(cfg config.AnalysisConfig) time.Duration {
	if cfg.QueryWindow > 0 {
		return cfg.QueryWindow
	}
	return 10 * time.Minute
}

// Analyzer is the interface that all analysis modules must implement.
type Analyzer interface {
	// Name returns the analyzer's human-readable name.
	Name() string
	// Analyze inspects recent flow data and returns any advisories.
	Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory
}

// Engine runs registered analyzers on a configurable schedule and maintains
// a thread-safe rolling history of advisories.
type Engine struct {
	cfg       config.AnalysisConfig
	store     *storage.RingBuffer
	analyzers []Analyzer

	mu         sync.RWMutex
	advisories []Advisory

	stop   chan struct{}
	wg     sync.WaitGroup
}

// maxAdvisoryHistory is the maximum number of advisories to retain.
const maxAdvisoryHistory = 100

// NewEngine creates a new analysis engine with the given config, storage, and analyzers.
func NewEngine(cfg config.AnalysisConfig, store *storage.RingBuffer, analyzers ...Analyzer) *Engine {
	return &Engine{
		cfg:       cfg,
		store:     store,
		analyzers: analyzers,
		stop:      make(chan struct{}),
	}
}

// Start begins the periodic analysis loop. It runs immediately once, then on the
// configured interval. It blocks until Stop is called.
func (e *Engine) Start() {
	e.wg.Add(1)
	defer e.wg.Done()

	// Run immediately on start.
	e.runAll()

	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.runAll()
		case <-e.stop:
			return
		}
	}
}

// Stop signals the engine to stop and waits for it to finish.
func (e *Engine) Stop() {
	close(e.stop)
	e.wg.Wait()
}

// Advisories returns a copy of the current advisories sorted by severity
// (CRITICAL first, then WARNING, then INFO).
func (e *Engine) Advisories() []Advisory {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Advisory, len(e.advisories))
	copy(result, e.advisories)
	return result
}

// runAll executes all registered analyzers and merges results into the
// rolling advisory history. Previously-active advisories that are no longer
// reported are marked as resolved rather than deleted.
func (e *Engine) runAll() {
	// Collect new advisories from all analyzers.
	var newAdvisories []Advisory
	for _, a := range e.analyzers {
		results := a.Analyze(e.store, e.cfg)
		if len(results) > 0 {
			logging.Default().Info("Analysis [%s]: %d advisories", a.Name(), len(results))
		}
		newAdvisories = append(newAdvisories, results...)
	}

	// Build a set of currently-active advisory titles for quick lookup.
	activeSet := make(map[string]struct{}, len(newAdvisories))
	for _, a := range newAdvisories {
		activeSet[a.Title] = struct{}{}
	}

	now := time.Now()

	e.mu.Lock()
	defer e.mu.Unlock()

	// Mark previously-active advisories as resolved if they are no longer reported.
	for i := range e.advisories {
		if e.advisories[i].Resolved {
			continue
		}
		if _, stillActive := activeSet[e.advisories[i].Title]; !stillActive {
			e.advisories[i].Resolved = true
			e.advisories[i].ResolvedAt = now
		}
	}

	// Build a set of existing advisory titles to avoid duplicating active ones.
	existingActive := make(map[string]struct{})
	for _, a := range e.advisories {
		if !a.Resolved {
			existingActive[a.Title] = struct{}{}
		}
	}

	// Append genuinely new advisories.
	for _, a := range newAdvisories {
		if _, exists := existingActive[a.Title]; !exists {
			e.advisories = append(e.advisories, a)
		}
	}

	// Sort: active before resolved, then CRITICAL > WARNING > INFO,
	// then by timestamp (most recent first).
	sort.Slice(e.advisories, func(i, j int) bool {
		// Active advisories come before resolved ones.
		if e.advisories[i].Resolved != e.advisories[j].Resolved {
			return !e.advisories[i].Resolved
		}
		if e.advisories[i].Severity != e.advisories[j].Severity {
			return e.advisories[i].Severity > e.advisories[j].Severity
		}
		return e.advisories[i].Timestamp.After(e.advisories[j].Timestamp)
	})

	// Trim to max history size, keeping most important/recent entries.
	if len(e.advisories) > maxAdvisoryHistory {
		e.advisories = e.advisories[:maxAdvisoryHistory]
	}
}
