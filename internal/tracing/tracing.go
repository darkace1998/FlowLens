// Package tracing provides a minimal tracing interface for future
// OpenTelemetry integration. The default implementation is a no-op tracer
// that adds zero overhead. To enable real tracing, replace the global
// tracer with an OpenTelemetry-backed implementation using SetGlobal().
//
// Example (future integration):
//
//	import "go.opentelemetry.io/otel"
//	tp := otel.GetTracerProvider().Tracer("flowlens")
//	tracing.SetGlobal(&otelTracer{tp: tp})
package tracing

import "context"

// Tracer defines the minimal interface for request/query tracing.
// Implementations should create spans that track operation duration,
// attributes, and error status.
type Tracer interface {
	// StartSpan begins a new trace span with the given operation name.
	// The returned context carries the span; call the returned function
	// to end the span.
	StartSpan(ctx context.Context, operationName string) (context.Context, func())
}

// noopTracer is the default tracer that does nothing. It adds zero overhead
// since the compiler can inline the empty closure.
type noopTracer struct{}

func (noopTracer) StartSpan(ctx context.Context, _ string) (context.Context, func()) {
	return ctx, func() {}
}

var globalTracer Tracer = noopTracer{}

// Global returns the current global tracer instance.
func Global() Tracer {
	return globalTracer
}

// SetGlobal replaces the global tracer. This should be called once at
// application startup before any requests are served. It is not safe for
// concurrent use.
func SetGlobal(t Tracer) {
	if t == nil {
		globalTracer = noopTracer{}
		return
	}
	globalTracer = t
}
