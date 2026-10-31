package storage

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// Regression: NewRingBuffer(0) (or negative) must not panic on Insert.
func TestRingBuffer_NonPositiveCapacityClamped(t *testing.T) {
	for _, cap := range []int{0, -1, -100} {
		rb := NewRingBuffer(cap)
		if err := rb.Insert([]model.Flow{{SrcAddr: net.ParseIP("10.0.0.1")}}); err != nil {
			t.Fatalf("capacity %d: Insert returned error: %v", cap, err)
		}
		if rb.Len() != 1 {
			t.Errorf("capacity %d: expected Len 1 after insert, got %d", cap, rb.Len())
		}
		all := rb.All()
		if len(all) != 1 {
			t.Errorf("capacity %d: expected 1 record from All, got %d", cap, len(all))
		}
	}
}

// Regression: NewSQLiteStore must create missing parent directories.
func TestNewSQLiteStore_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "flows.db")

	s, err := NewSQLiteStore(path, time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewSQLiteStore with nested path returned error: %v", err)
	}
	defer s.Close() // nolint:errcheck // test cleanup

	if err := s.Insert([]model.Flow{makeTestFlow("10.9.9.9", "10.9.9.10", 1234, 80, time.Now())}); err != nil {
		t.Fatalf("Insert into fresh nested DB failed: %v", err)
	}
	recent, err := s.Recent(time.Hour, 10)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 1 {
		t.Errorf("expected 1 recent flow, got %d", len(recent))
	}
}
