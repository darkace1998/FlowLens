package storage

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

func makeTestFlow(srcIP string, dstIP string, srcPort, dstPort uint16, ts time.Time) model.Flow {
	return model.Flow{
		Timestamp:   ts,
		SrcAddr:     net.ParseIP(srcIP),
		DstAddr:     net.ParseIP(dstIP),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    6,
		Bytes:       1000,
		Packets:     10,
		TCPFlags:    0x02,
		ToS:         0,
		InputIface:  1,
		OutputIface: 2,
		SrcAS:       65000,
		DstAS:       65001,
		Duration:    5 * time.Second,
		ExporterIP:  net.ParseIP("10.0.0.1"),
	}
}

func TestRingBuffer_InsertAndLen(t *testing.T) {
	rb := NewRingBuffer(10)

	if rb.Len() != 0 {
		t.Errorf("empty buffer Len() = %d, want 0", rb.Len())
	}

	now := time.Now()
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, now),
		makeTestFlow("10.0.1.2", "192.168.1.2", 1235, 443, now),
	}
	if err := rb.Insert(flows); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	if rb.Len() != 2 {
		t.Errorf("Len() = %d, want 2", rb.Len())
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	rb := NewRingBuffer(3)

	now := time.Now()
	for i := 0; i < 5; i++ {
		f := makeTestFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, now.Add(time.Duration(i)*time.Second))
		if err := rb.Insert([]model.Flow{f}); err != nil {
			t.Fatalf("Insert %d failed: %v", i, err)
		}
	}

	// Capacity is 3, so only 3 records should be stored even after inserting 5.
	if rb.Len() != 3 {
		t.Errorf("Len() = %d, want 3 (capacity)", rb.Len())
	}

	// The most recent records should be the last 3 inserted (srcPort 1002, 1003, 1004).
	all := rb.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d records, want 3", len(all))
	}

	// All() returns most recent first.
	if all[0].SrcPort != 1004 {
		t.Errorf("all[0].SrcPort = %d, want 1004 (most recent)", all[0].SrcPort)
	}
	if all[2].SrcPort != 1002 {
		t.Errorf("all[2].SrcPort = %d, want 1002 (oldest remaining)", all[2].SrcPort)
	}
}

func TestRingBuffer_Recent(t *testing.T) {
	rb := NewRingBuffer(100)

	now := time.Now()
	// Insert flows spread across time.
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1000, 80, now.Add(-30*time.Minute)), // too old
		makeTestFlow("10.0.1.2", "192.168.1.2", 1001, 80, now.Add(-5*time.Minute)),  // within 10m
		makeTestFlow("10.0.1.3", "192.168.1.3", 1002, 80, now.Add(-1*time.Minute)),  // within 10m
		makeTestFlow("10.0.1.4", "192.168.1.4", 1003, 80, now),                       // within 10m
	}
	if err := rb.Insert(flows); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	recent, err := rb.Recent(10*time.Minute, 0)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}

	if len(recent) != 3 {
		t.Errorf("Recent(10m) returned %d records, want 3", len(recent))
	}

	// Should be most recent first.
	if len(recent) > 0 && recent[0].SrcPort != 1003 {
		t.Errorf("recent[0].SrcPort = %d, want 1003 (most recent)", recent[0].SrcPort)
	}
}

func TestRingBuffer_RecentWithLimit(t *testing.T) {
	rb := NewRingBuffer(100)

	now := time.Now()
	for i := 0; i < 20; i++ {
		f := makeTestFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, now.Add(-time.Duration(i)*time.Second))
		if err := rb.Insert([]model.Flow{f}); err != nil {
			t.Fatalf("Insert failed: %v", err)
		}
	}

	recent, err := rb.Recent(time.Hour, 5)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}

	if len(recent) != 5 {
		t.Errorf("Recent(1h, limit=5) returned %d records, want 5", len(recent))
	}
}

func TestRingBuffer_Close(t *testing.T) {
	rb := NewRingBuffer(10)
	if err := rb.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestRingBuffer_ConcurrentAccess(t *testing.T) {
	rb := NewRingBuffer(1000)
	now := time.Now()

	done := make(chan struct{})

	// Writer goroutine.
	go func() {
		for i := 0; i < 500; i++ {
			f := makeTestFlow("10.0.1.1", "192.168.1.1", uint16(i), 80, now)
			rb.Insert([]model.Flow{f})
		}
		close(done)
	}()

	// Reader goroutine (concurrent).
	for i := 0; i < 100; i++ {
		rb.Recent(time.Hour, 10)
		rb.Len()
		rb.All()
	}

	<-done

	if rb.Len() != 500 {
		t.Errorf("Len() = %d, want 500 after concurrent writes", rb.Len())
	}
}
