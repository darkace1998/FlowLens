package collector

import (
	"sync"
	"time"
)

// CounterStore stores recent sFlow counter samples for display.
type CounterStore struct {
	mu       sync.RWMutex
	counters []SFlowCounterSample
	maxAge   time.Duration
}

// NewCounterStore creates a new counter store with the given max retention.
func NewCounterStore(maxAge time.Duration) *CounterStore {
	return &CounterStore{
		maxAge: maxAge,
	}
}

// Insert adds counter samples to the store and prunes old entries.
func (cs *CounterStore) Insert(samples []SFlowCounterSample) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.counters = append(cs.counters, samples...)
	cs.prune()
}

// Recent returns all counter samples within the given duration.
func (cs *CounterStore) Recent(d time.Duration) []SFlowCounterSample {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	cutoff := time.Now().Add(-d)
	var result []SFlowCounterSample
	for _, c := range cs.counters {
		if c.Timestamp.After(cutoff) {
			result = append(result, c)
		}
	}
	return result
}

// Len returns the number of stored counter samples.
func (cs *CounterStore) Len() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.counters)
}

func (cs *CounterStore) prune() {
	cutoff := time.Now().Add(-cs.maxAge)
	i := 0
	for i < len(cs.counters) && cs.counters[i].Timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		cs.counters = cs.counters[i:]
	}
}
