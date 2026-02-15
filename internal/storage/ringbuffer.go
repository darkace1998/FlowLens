package storage

import (
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// RingBuffer is a fixed-capacity, thread-safe, in-memory ring buffer for flow records.
type RingBuffer struct {
	mu       sync.RWMutex
	buf      []model.Flow
	capacity int
	head     int // next write position
	count    int // number of valid entries
}

// NewRingBuffer creates a new ring buffer with the given maximum record capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		buf:      make([]model.Flow, capacity),
		capacity: capacity,
	}
}

// Insert adds flow records to the ring buffer, overwriting the oldest entries
// when the buffer is full.
func (rb *RingBuffer) Insert(flows []model.Flow) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for _, f := range flows {
		rb.buf[rb.head] = f
		rb.head = (rb.head + 1) % rb.capacity
		if rb.count < rb.capacity {
			rb.count++
		}
	}
	return nil
}

// Recent returns flow records with timestamps within the last duration d.
// If limit > 0, at most limit records are returned (most recent first).
func (rb *RingBuffer) Recent(d time.Duration, limit int) ([]model.Flow, error) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	cutoff := time.Now().Add(-d)
	var result []model.Flow

	// Walk backwards from most recent entry.
	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + rb.capacity) % rb.capacity
		f := rb.buf[idx]
		if f.Timestamp.Before(cutoff) {
			break
		}
		result = append(result, f)
		if limit > 0 && len(result) >= limit {
			break
		}
	}

	return result, nil
}

// All returns all valid flow records currently in the buffer, most recent first.
func (rb *RingBuffer) All() []model.Flow {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]model.Flow, 0, rb.count)
	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + rb.capacity) % rb.capacity
		result = append(result, rb.buf[idx])
	}
	return result
}

// Len returns the number of valid records in the buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// Close is a no-op for the in-memory ring buffer (satisfies the Storage interface).
func (rb *RingBuffer) Close() error {
	return nil
}
