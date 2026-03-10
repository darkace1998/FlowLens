package collector

import (
	"net"
	"testing"
	"time"
)

func TestCounterStore_InsertAndRecent(t *testing.T) {
	cs := NewCounterStore(10 * time.Minute)

	samples := []SFlowCounterSample{
		{
			IfIndex:   1,
			IfSpeed:   1_000_000_000,
			InOctets:  1000,
			OutOctets: 2000,
			AgentIP:   net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		},
		{
			IfIndex:   2,
			IfSpeed:   10_000_000_000,
			InOctets:  5000,
			OutOctets: 3000,
			AgentIP:   net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		},
	}

	cs.Insert(samples)

	if cs.Len() != 2 {
		t.Errorf("Len() = %d, want 2", cs.Len())
	}

	recent := cs.Recent(10 * time.Minute)
	if len(recent) != 2 {
		t.Errorf("Recent() returned %d, want 2", len(recent))
	}
}

func TestCounterStore_Pruning(t *testing.T) {
	cs := NewCounterStore(1 * time.Minute)

	old := []SFlowCounterSample{
		{
			IfIndex:   1,
			IfSpeed:   1_000_000_000,
			AgentIP:   net.ParseIP("10.0.0.1"),
			Timestamp: time.Now().Add(-2 * time.Minute), // older than max age
		},
	}
	cs.Insert(old)

	fresh := []SFlowCounterSample{
		{
			IfIndex:   2,
			IfSpeed:   1_000_000_000,
			AgentIP:   net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		},
	}
	cs.Insert(fresh)

	// Old entry should be pruned after inserting fresh.
	if cs.Len() != 1 {
		t.Errorf("Len() = %d, want 1 after pruning", cs.Len())
	}

	recent := cs.Recent(10 * time.Minute)
	if len(recent) != 1 {
		t.Errorf("Recent() = %d, want 1", len(recent))
	}
	if recent[0].IfIndex != 2 {
		t.Errorf("IfIndex = %d, want 2 (fresh entry)", recent[0].IfIndex)
	}
}

func TestCounterStore_RecentWindow(t *testing.T) {
	cs := NewCounterStore(1 * time.Hour)

	cs.Insert([]SFlowCounterSample{
		{
			IfIndex:   1,
			AgentIP:   net.ParseIP("10.0.0.1"),
			Timestamp: time.Now().Add(-30 * time.Minute),
		},
		{
			IfIndex:   2,
			AgentIP:   net.ParseIP("10.0.0.1"),
			Timestamp: time.Now(),
		},
	})

	// Query only last 5 minutes
	recent := cs.Recent(5 * time.Minute)
	if len(recent) != 1 {
		t.Errorf("Recent(5m) = %d, want 1", len(recent))
	}
}

func TestCounterStore_Empty(t *testing.T) {
	cs := NewCounterStore(10 * time.Minute)

	if cs.Len() != 0 {
		t.Errorf("Len() = %d, want 0", cs.Len())
	}

	recent := cs.Recent(10 * time.Minute)
	if len(recent) != 0 {
		t.Errorf("Recent() = %d, want 0", len(recent))
	}
}
