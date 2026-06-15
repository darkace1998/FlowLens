package web

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

func BenchmarkBuildMapData(b *testing.B) {
	// Generate dummy flows
	numFlows := 10000
	flows := make([]model.Flow, numFlows)
	for i := 0; i < numFlows; i++ {
		// Use a limited number of unique IPs to simulate real traffic
		srcIPStr := fmt.Sprintf("192.168.1.%d", (i%50)+1)
		dstIPStr := fmt.Sprintf("10.0.0.%d", (i%20)+1)
		flows[i] = model.Flow{
			SrcAddr:   net.ParseIP(srcIPStr),
			DstAddr:   net.ParseIP(dstIPStr),
			Bytes:     uint64((i % 1000) + 100),
			Timestamp: time.Now(),
		}
	}

	srv := &Server{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = srv.buildMapData(flows)
	}
}
