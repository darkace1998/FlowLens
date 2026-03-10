package tracing

import (
	"context"
	"testing"
)

func TestNoopTracer(t *testing.T) {
	tr := Global()
	ctx, end := tr.StartSpan(context.Background(), "test-op")
	if ctx == nil {
		t.Fatal("StartSpan returned nil context")
	}
	end() // should be a no-op, no panic
}

func TestSetGlobal(t *testing.T) {
	original := Global()

	var called bool
	mock := &mockTracer{onStart: func() { called = true }}
	SetGlobal(mock)
	defer SetGlobal(original) // restore

	_, end := Global().StartSpan(context.Background(), "test")
	if !called {
		t.Error("expected mock tracer to be called")
	}
	end()
}

func TestSetGlobal_Nil(t *testing.T) {
	original := Global()
	SetGlobal(nil)
	defer SetGlobal(original)

	// Should not panic — falls back to noopTracer.
	_, end := Global().StartSpan(context.Background(), "test")
	end()
}

type mockTracer struct {
	onStart func()
}

func (m *mockTracer) StartSpan(ctx context.Context, _ string) (context.Context, func()) {
	if m.onStart != nil {
		m.onStart()
	}
	return ctx, func() {}
}
