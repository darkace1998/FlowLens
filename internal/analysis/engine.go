package analysis

import (
	"log"
	"sort"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// Analyzer is the interface that all analysis modules must implement.
type Analyzer interface {
	// Name returns the analyzer's human-readable name.
	Name() string
	// Analyze inspects recent flow data and returns any advisories.
	Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory
}

// Engine runs registered analyzers on a configurable schedule and maintains
// a thread-safe list of active advisories.
type Engine struct {
	cfg       config.AnalysisConfig
	store     *storage.RingBuffer
	analyzers []Analyzer

	mu         sync.RWMutex
	advisories []Advisory

	stop   chan struct{}
	wg     sync.WaitGroup
}

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

// runAll executes all registered analyzers and updates the advisory list.
func (e *Engine) runAll() {
	var all []Advisory
	for _, a := range e.analyzers {
		results := a.Analyze(e.store, e.cfg)
		if len(results) > 0 {
			log.Printf("Analysis [%s]: %d advisories", a.Name(), len(results))
		}
		all = append(all, results...)
	}

	// Sort: CRITICAL > WARNING > INFO, then by timestamp (most recent first).
	sort.Slice(all, func(i, j int) bool {
		if all[i].Severity != all[j].Severity {
			return all[i].Severity > all[j].Severity
		}
		return all[i].Timestamp.After(all[j].Timestamp)
	})

	e.mu.Lock()
	e.advisories = all
	e.mu.Unlock()
}
