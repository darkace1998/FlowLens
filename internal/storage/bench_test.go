package storage

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// --- Benchmarks for ring buffer hot paths ---

func makeBenchFlow(i int) model.Flow {
	return model.Flow{
		Timestamp:   time.Now(),
		SrcAddr:     net.IPv4(10, 0, byte(i>>8), byte(i)),
		DstAddr:     net.IPv4(192, 168, 1, byte(i)),
		SrcPort:     uint16(1000 + i%60000),
		DstPort:     80,
		Protocol:    6,
		Bytes:       1500,
		Packets:     10,
		TCPFlags:    0x12,
		Duration:    5 * time.Second,
		ExporterIP:  net.ParseIP("10.0.0.1"),
	}
}

func BenchmarkRingBuffer_Insert(b *testing.B) {
	rb := NewRingBuffer(10000)
	flows := make([]model.Flow, 100)
	for i := range flows {
		flows[i] = makeBenchFlow(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Insert(flows)
	}
}

func BenchmarkRingBuffer_Insert_Single(b *testing.B) {
	rb := NewRingBuffer(10000)
	f := makeBenchFlow(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Insert([]model.Flow{f})
	}
}

func BenchmarkRingBuffer_Recent(b *testing.B) {
	rb := NewRingBuffer(10000)
	// Pre-fill the buffer.
	for i := 0; i < 10000; i++ {
		rb.Insert([]model.Flow{makeBenchFlow(i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Recent(10*time.Minute, 0)
	}
}

func BenchmarkRingBuffer_All(b *testing.B) {
	rb := NewRingBuffer(10000)
	for i := 0; i < 10000; i++ {
		rb.Insert([]model.Flow{makeBenchFlow(i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.All()
	}
}
