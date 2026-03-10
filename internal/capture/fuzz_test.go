package capture

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// FuzzReadPcapFlows fuzzes the PCAP file reader with arbitrary byte slices.
// This exercises magic detection, byte-order handling, packet header parsing,
// and the capturedLen safety check against crafted inputs.
func FuzzReadPcapFlows(f *testing.F) {
	// Seed: valid little-endian microsecond PCAP with one Ethernet+IPv4+TCP packet.
	f.Add(buildMinimalPcap())
	// Seed: valid big-endian microsecond PCAP header only (no packets).
	f.Add(buildBEPcapHeader())
	// Seed: pcapng magic (should be rejected gracefully).
	f.Add(buildPcapngMagic())
	// Seed: empty input.
	f.Add([]byte{})
	// Seed: just the magic bytes.
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1})

	f.Fuzz(func(t *testing.T, data []byte) {
		// The reader must never panic regardless of input.
		ReadPcapFlows(bytes.NewReader(data))
	})
}

// buildMinimalPcap creates a minimal valid PCAP file (LE, µs) with one packet.
func buildMinimalPcap() []byte {
	var buf bytes.Buffer

	// Global header (24 bytes).
	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(ghdr[4:6], 2)           // major
	binary.LittleEndian.PutUint16(ghdr[6:8], 4)           // minor
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535)      // snaplen
	binary.LittleEndian.PutUint32(ghdr[20:24], 1)          // Ethernet
	buf.Write(ghdr[:])

	// Minimal Ethernet + IPv4 + TCP frame (54 bytes).
	pkt := make([]byte, 54)
	pkt[12] = 0x08
	pkt[13] = 0x00 // EtherType = IPv4
	pkt[14] = 0x45 // IPv4 version+IHL
	binary.BigEndian.PutUint16(pkt[16:18], 40) // total length
	pkt[23] = 6                                 // protocol = TCP
	copy(pkt[26:30], net.IPv4(10, 0, 0, 1).To4())
	copy(pkt[30:34], net.IPv4(192, 168, 1, 1).To4())

	// Packet header (16 bytes).
	var phdr [16]byte
	binary.LittleEndian.PutUint32(phdr[0:4], 1700000000) // timestamp sec
	binary.LittleEndian.PutUint32(phdr[8:12], 54)         // captured len
	binary.LittleEndian.PutUint32(phdr[12:16], 54)        // original len
	buf.Write(phdr[:])
	buf.Write(pkt)

	return buf.Bytes()
}

// buildBEPcapHeader creates a big-endian PCAP global header with Ethernet link type.
func buildBEPcapHeader() []byte {
	var ghdr [24]byte
	binary.BigEndian.PutUint32(ghdr[0:4], 0xa1b2c3d4) // BE magic (read as LE → 0xd4c3b2a1)
	// Actually for BE: the reader reads magic as LE first.
	// Use the constant pcapMagicBE = 0xd4c3b2a1 which is the LE reading of a BE file.
	binary.LittleEndian.PutUint32(ghdr[0:4], 0xd4c3b2a1) // will match pcapMagicBE
	binary.BigEndian.PutUint16(ghdr[4:6], 2)              // major
	binary.BigEndian.PutUint16(ghdr[6:8], 4)              // minor
	binary.BigEndian.PutUint32(ghdr[16:20], 65535)         // snaplen
	binary.BigEndian.PutUint32(ghdr[20:24], 1)             // Ethernet
	return ghdr[:]
}

// buildPcapngMagic creates a minimal pcapng-like header.
func buildPcapngMagic() []byte {
	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], 0x0a0d0d0a) // pcapng magic
	return ghdr[:]
}
