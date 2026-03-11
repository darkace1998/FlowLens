package collector

import (
	"encoding/binary"
	"net"
	"testing"
)

// --- Fuzz tests for protocol decoders ---
// These exercise the parsers with random/mutated input to find panics,
// out-of-bounds reads, or other undefined behavior in untrusted-input paths.

// FuzzDecodeNetFlowV5 fuzzes the NetFlow v5 decoder with arbitrary byte slices.
func FuzzDecodeNetFlowV5(f *testing.F) {
	// Seed with a valid packet.
	f.Add(buildNFV5Packet(1))
	// Seed with a valid multi-record packet.
	f.Add(buildNFV5Packet(5))
	// Seed with minimal header-only data.
	f.Add(make([]byte, nfv5HeaderSize))
	// Seed with an empty slice.
	f.Add([]byte{})
	// Seed with a very short slice.
	f.Add([]byte{0x00, 0x05})

	f.Fuzz(func(t *testing.T, data []byte) {
		// The decoder must never panic regardless of input.
		DecodeNetFlowV5(data, net.ParseIP("10.0.0.1"))
	})
}

// FuzzDecodeNetFlowV9 fuzzes the NetFlow v9 decoder with arbitrary byte slices.
func FuzzDecodeNetFlowV9(f *testing.F) {
	// Seed with a valid NFv9 packet.
	fields := standardNFV9Fields()
	tmplFS := buildNFV9TemplateFlowSet(256, fields)
	recData := buildNFV9RecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0, 1, 2, 65000, 65001, 594000, 599000,
	)
	dataFS := buildNFV9DataFlowSet(256, recData)
	seed := buildNFV9Packet(0, 600000, 1700000000, tmplFS, dataFS)
	f.Add(seed)

	// Seed with header-only.
	hdr := make([]byte, nfv9HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], 9)
	f.Add(hdr)
	// Seed with empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		cache := NewNFV9TemplateCache()
		DecodeNetFlowV9(data, net.ParseIP("10.0.0.1"), cache)
	})
}

// FuzzDecodeIPFIX fuzzes the IPFIX decoder with arbitrary byte slices.
func FuzzDecodeIPFIX(f *testing.F) {
	// Seed with a valid IPFIX packet.
	fields := standardIPFIXFields()
	tmplSet := buildIPFIXTemplateSet(256, fields)
	recData := buildIPFIXRecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0, 1, 2, 65000, 65001,
	)
	dataSet := buildIPFIXDataSet(256, recData)
	seed := buildIPFIXPacket(0, 1700000000, tmplSet, dataSet)
	f.Add(seed)

	// Seed with header-only.
	hdr := make([]byte, ipfixHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], 10)
	f.Add(hdr)
	// Seed with empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		cache := NewIPFIXTemplateCache()
		DecodeIPFIX(data, net.ParseIP("10.0.0.1"), cache)
	})
}

// FuzzDecodeSFlow fuzzes the sFlow v5 decoder with arbitrary byte slices.
func FuzzDecodeSFlow(f *testing.F) {
	// Seed with a valid sFlow datagram containing a flow sample.
	rawPkt := buildEtherIPv4TCP(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"), 12345, 443,
	)
	sample := buildSFlowFlowSample(512, 1, 2, rawPkt)
	f.Add(buildSFlowDatagram(net.ParseIP("10.0.0.1"), sample))

	// Seed with minimal valid header.
	hdr := make([]byte, sflowDatagramMinLen)
	binary.BigEndian.PutUint32(hdr[0:4], 5) // version
	binary.BigEndian.PutUint32(hdr[4:8], 1) // agent address type (IPv4)
	f.Add(hdr)
	// Seed with empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		DecodeSFlow(data, net.ParseIP("10.0.0.1"))
	})
}
