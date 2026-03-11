package model

import (
	"net"
	"testing"
	"time"
)

// --- Benchmarks for model hot paths ---

func BenchmarkCalcMOS(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalcMOS(15000, 40000, 1.5) // typical VoIP values
	}
}

func BenchmarkCalcMOS_ZeroLoss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalcMOS(10000, 30000, 0.0)
	}
}

func BenchmarkCalcMOS_HighDelay(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalcMOS(50000, 500000, 5.0) // bad network conditions
	}
}

func BenchmarkFlowKey(b *testing.B) {
	srcIP := net.ParseIP("10.0.1.50")
	dstIP := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FlowKey(srcIP, dstIP, 12345, 443, 6)
	}
}

func BenchmarkStitchFlows_100(b *testing.B) {
	flows := makeStitchBenchFlows(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a copy since StitchFlows modifies in place.
		c := make([]Flow, len(flows))
		copy(c, flows)
		StitchFlows(c)
	}
}

func BenchmarkStitchFlows_1000(b *testing.B) {
	flows := makeStitchBenchFlows(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := make([]Flow, len(flows))
		copy(c, flows)
		StitchFlows(c)
	}
}

func BenchmarkStitchFlows_10000(b *testing.B) {
	flows := makeStitchBenchFlows(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := make([]Flow, len(flows))
		copy(c, flows)
		StitchFlows(c)
	}
}

func BenchmarkIsVoIP(b *testing.B) {
	f := Flow{Protocol: 17, SrcPort: 15000, DstPort: 15002}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.IsVoIP()
	}
}

func BenchmarkClassify(b *testing.B) {
	f := Flow{Protocol: 6, DstPort: 443}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Classify()
	}
}

// makeStitchBenchFlows creates n bidirectional flow pairs for stitching benchmarks.
func makeStitchBenchFlows(n int) []Flow {
	flows := make([]Flow, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		srcLast := byte(i%254 + 1)
		dstLast := byte((i/254)%254 + 1)

		if i%2 == 0 {
			// Forward direction.
			flows[i] = Flow{
				Timestamp: now.Add(time.Duration(i) * time.Millisecond),
				SrcAddr:   net.IPv4(10, 0, 1, srcLast),
				DstAddr:   net.IPv4(192, 168, 1, dstLast),
				SrcPort:   uint16(10000 + i%50000),
				DstPort:   443,
				Protocol:  6,
				Bytes:     1500,
				Packets:   10,
				Duration:  5 * time.Second,
			}
		} else {
			// Reverse direction.
			flows[i] = Flow{
				Timestamp: now.Add(time.Duration(i)*time.Millisecond + 500*time.Microsecond),
				SrcAddr:   net.IPv4(192, 168, 1, dstLast),
				DstAddr:   net.IPv4(10, 0, 1, srcLast),
				SrcPort:   443,
				DstPort:   uint16(10000 + (i-1)%50000),
				Protocol:  6,
				Bytes:     1000,
				Packets:   8,
				Duration:  5 * time.Second,
			}
		}
	}
	return flows
}
