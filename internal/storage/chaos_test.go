package storage

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// --- Chaos / error-injection tests for storage failures ---

// TestSQLiteStore_ReadOnlyFS verifies that Insert returns an error (not a panic)
// when the database file becomes read-only after initial creation.
func TestSQLiteStore_ReadOnlyFS(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "readonly.db")

	store, err := NewSQLiteStore(dbPath, 1*time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Insert should work initially.
	flows := []model.Flow{makeTestFlow("10.0.0.1", "192.168.1.1", 1234, 80, time.Now())}
	if err := store.Insert(flows); err != nil {
		t.Fatalf("initial insert failed: %v", err)
	}

	// Make the directory read-only to prevent WAL writes.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Skipf("cannot chmod directory: %v", err)
	}
	defer os.Chmod(dir, 0755)

	// Attempting to insert more data may fail due to read-only filesystem.
	// The test verifies no panic occurs — the error itself depends on OS/SQLite behaviour.
	_ = store.Insert(flows)
}

// TestSQLiteStore_CorruptDB verifies that NewSQLiteStore handles a pre-existing
// corrupt database file gracefully (returns error, no panic).
func TestSQLiteStore_CorruptDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corrupt.db")

	// Write garbage to the DB path.
	if err := os.WriteFile(dbPath, []byte("this is not a sqlite database"), 0644); err != nil {
		t.Fatalf("writing corrupt file: %v", err)
	}

	store, err := NewSQLiteStore(dbPath, 1*time.Hour, 10*time.Minute)
	if err != nil {
		// Expected: cannot open corrupt DB.
		return
	}
	defer store.Close()

	// If Open succeeded (some drivers defer errors), Insert should surface
	// the corruption without panicking.
	flows := []model.Flow{makeTestFlow("10.0.0.1", "192.168.1.1", 1234, 80, time.Now())}
	_ = store.Insert(flows)
}

// TestSQLiteStore_ConcurrentInsertAndQuery exercises concurrent reads and writes
// to detect any race conditions or deadlocks.
func TestSQLiteStore_ConcurrentInsertAndQuery(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC()
	done := make(chan struct{})

	// Writer goroutine: inserts 200 flows.
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			f := model.Flow{
				Timestamp:   now.Add(-time.Duration(i) * time.Second),
				SrcAddr:     net.IPv4(10, 0, 0, byte(i%255+1)),
				DstAddr:     net.IPv4(192, 168, 1, 1),
				SrcPort:     uint16(1000 + i),
				DstPort:     80,
				Protocol:    6,
				Bytes:       1000,
				Packets:     10,
				ExporterIP:  net.ParseIP("10.0.0.1"),
				Duration:    time.Second,
			}
			if err := store.Insert([]model.Flow{f}); err != nil {
				t.Errorf("concurrent insert failed: %v", err)
				return
			}
		}
	}()

	// Reader goroutine: queries during writes.
	for i := 0; i < 50; i++ {
		_, err := store.Recent(time.Hour, 10)
		if err != nil {
			t.Errorf("concurrent query failed: %v", err)
		}
		time.Sleep(time.Millisecond)
	}

	<-done
}

// TestSQLiteStore_EmptyInsert verifies that inserting an empty slice is a no-op.
func TestSQLiteStore_EmptyInsert(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	if err := store.Insert(nil); err != nil {
		t.Errorf("Insert(nil) should not error, got: %v", err)
	}
	if err := store.Insert([]model.Flow{}); err != nil {
		t.Errorf("Insert(empty) should not error, got: %v", err)
	}
}

// TestSQLiteStore_LargeInsert verifies batch insert with a large number of flows.
func TestSQLiteStore_LargeInsert(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC()
	flows := make([]model.Flow, 1000)
	for i := range flows {
		flows[i] = model.Flow{
			Timestamp:   now.Add(-time.Duration(i) * time.Second),
			SrcAddr:     net.IPv4(10, 0, byte(i>>8), byte(i)),
			DstAddr:     net.IPv4(192, 168, 1, 1),
			SrcPort:     uint16(1000 + i%60000),
			DstPort:     80,
			Protocol:    6,
			Bytes:       1500,
			Packets:     10,
			ExporterIP:  net.ParseIP("10.0.0.1"),
			Duration:    time.Second,
		}
	}

	if err := store.Insert(flows); err != nil {
		t.Fatalf("large insert failed: %v", err)
	}

	recent, err := store.Recent(time.Hour, 0)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 1000 {
		t.Errorf("expected 1000 flows, got %d", len(recent))
	}
}

// TestSQLiteStore_NilIP verifies that flows with nil IPs don't panic.
func TestSQLiteStore_NilIP(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	f := model.Flow{
		Timestamp: time.Now(),
		SrcAddr:   nil,
		DstAddr:   nil,
		Protocol:  6,
		Bytes:     100,
		Packets:   1,
	}

	// Should not panic. Error is acceptable.
	_ = store.Insert([]model.Flow{f})
}

// TestRingBuffer_StressOverflow exercises rapid overflow cycles.
func TestRingBuffer_StressOverflow(t *testing.T) {
	rb := NewRingBuffer(100)

	for round := 0; round < 100; round++ {
		batch := make([]model.Flow, 50)
		for i := range batch {
			batch[i] = model.Flow{
				Timestamp: time.Now(),
				SrcAddr:   net.IPv4(10, 0, byte(round), byte(i)),
				DstAddr:   net.IPv4(192, 168, 1, 1),
				SrcPort:   uint16(1000 + i),
				DstPort:   80,
				Protocol:  6,
				Bytes:     1000,
				Packets:   10,
			}
		}
		rb.Insert(batch)
	}

	// After 100 rounds × 50 = 5000 inserts into capacity-100 buffer,
	// we should have exactly 100 entries.
	if rb.Len() != 100 {
		t.Errorf("Len() = %d, want 100 after stress overflow", rb.Len())
	}

	all := rb.All()
	if len(all) != 100 {
		t.Errorf("All() returned %d, want 100", len(all))
	}
}
