package collector

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/darkace1998/FlowLens/internal/config"
)

// --- Benchmarks for protocol decoders ---

func BenchmarkDecodeNetFlowV5_1Record(b *testing.B) {
	pkt := buildNFV5Packet(1)
	exporterIP := net.ParseIP("10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeNetFlowV5(pkt, exporterIP)
	}
}

func BenchmarkDecodeNetFlowV5_30Records(b *testing.B) {
	pkt := buildNFV5Packet(30)
	exporterIP := net.ParseIP("10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeNetFlowV5(pkt, exporterIP)
	}
}

func BenchmarkDecodeNetFlowV9(b *testing.B) {
	cache := NewNFV9TemplateCache()
	exporterIP := net.ParseIP("10.0.0.1")

	fields := standardNFV9Fields()
	tmplFS := buildNFV9TemplateFlowSet(256, fields)
	recData := buildNFV9RecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0, 1, 2, 65000, 65001, 594000, 599000,
	)
	dataFS := buildNFV9DataFlowSet(256, recData)
	pkt := buildNFV9Packet(0, 600000, 1700000000, tmplFS, dataFS)

	// Prime the cache.
	DecodeNetFlowV9(pkt, exporterIP, cache)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeNetFlowV9(pkt, exporterIP, cache)
	}
}

func BenchmarkDecodeIPFIX(b *testing.B) {
	cache := NewIPFIXTemplateCache()
	exporterIP := net.ParseIP("10.0.0.1")

	fields := standardIPFIXFields()
	tmplSet := buildIPFIXTemplateSet(256, fields)
	recData := buildIPFIXRecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0, 1, 2, 65000, 65001,
	)
	dataSet := buildIPFIXDataSet(256, recData)
	pkt := buildIPFIXPacket(0, 1700000000, tmplSet, dataSet)

	// Prime the cache.
	DecodeIPFIX(pkt, exporterIP, cache)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeIPFIX(pkt, exporterIP, cache)
	}
}

func BenchmarkDecodeSFlow(b *testing.B) {
	rawPkt := buildEtherIPv4TCP(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"), 12345, 443,
	)
	sample := buildSFlowFlowSample(512, 1, 2, rawPkt)
	pkt := buildSFlowDatagram(net.ParseIP("10.0.0.1"), sample)
	exporterIP := net.ParseIP("10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeSFlow(pkt, exporterIP)
	}
}

func BenchmarkDecodePacket(b *testing.B) {
	pkt := buildNFV5Packet(1)
	exporterIP := net.ParseIP("10.0.0.1")
	cfg := config.CollectorConfig{
		NetFlowPort: 0,
		BufferSize:  65535,
	}
	c := New(cfg, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.decodePacket(pkt, exporterIP)
	}
}

func BenchmarkDecodePacket_VersionDetection(b *testing.B) {
	nfv5 := buildNFV5Packet(1)

	nfv9 := make([]byte, 20)
	binary.BigEndian.PutUint16(nfv9[0:2], 9)

	cfg := config.CollectorConfig{NetFlowPort: 0, BufferSize: 65535}
	c := New(cfg, nil)

	b.Run("NFv5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			c.decodePacket(nfv5, net.ParseIP("10.0.0.1"))
		}
	})
	b.Run("NFv9_header", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			c.decodePacket(nfv9, net.ParseIP("10.0.0.1"))
		}
	})
}
