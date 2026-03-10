package web

import (
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// TestDefaultFlowService verifies that the defaultFlowService correctly
// delegates to the underlying RingBuffer.
func TestDefaultFlowService(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	svc := &defaultFlowService{rb: rb}

	// FlowCount on empty buffer.
	if got := svc.FlowCount(); got != 0 {
		t.Errorf("FlowCount() = %d, want 0", got)
	}

	// Insert some flows.
	flows := []model.Flow{
		makeTestFlow("10.0.0.1", "10.0.0.2", 80, 12345, 6, 1000, 10),
		makeTestFlow("10.0.0.3", "10.0.0.4", 443, 54321, 6, 2000, 20),
	}
	if err := svc.InsertFlows(flows); err != nil {
		t.Fatalf("InsertFlows: %v", err)
	}

	if got := svc.FlowCount(); got != 2 {
		t.Errorf("FlowCount() = %d, want 2", got)
	}

	// RecentFlows should return the inserted flows.
	recent, err := svc.RecentFlows(5*time.Minute, 0)
	if err != nil {
		t.Fatalf("RecentFlows: %v", err)
	}
	if len(recent) != 2 {
		t.Errorf("RecentFlows() = %d flows, want 2", len(recent))
	}
}

// TestFlowServiceInterface verifies that defaultFlowService satisfies FlowService.
func TestFlowServiceInterface(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	var _ FlowService = &defaultFlowService{rb: rb}
}
