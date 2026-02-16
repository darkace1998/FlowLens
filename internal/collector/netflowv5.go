package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// NetFlow v5 header size and per-record size in bytes.
const (
	nfv5HeaderSize = 24
	nfv5RecordSize = 48
)

// nfv5Header represents the NetFlow v5 packet header.
type nfv5Header struct {
	Version      uint16
	Count        uint16
	SysUptime    uint32 // milliseconds since device boot
	UnixSecs     uint32
	UnixNsecs    uint32
	FlowSequence uint32
	EngineType   uint8
	EngineID     uint8
	SamplingInfo uint16 // sampling mode (2 bits) + interval (14 bits)
}

// nfv5Record represents a single NetFlow v5 flow record.
type nfv5Record struct {
	SrcAddr   uint32
	DstAddr   uint32
	NextHop   uint32
	Input     uint16
	Output    uint16
	Packets   uint32
	Bytes     uint32
	First     uint32 // sysUptime at flow start
	Last      uint32 // sysUptime at flow end
	SrcPort   uint16
	DstPort   uint16
	_         uint8 // pad1
	TCPFlags  uint8
	Protocol  uint8
	ToS       uint8
	SrcAS     uint16
	DstAS     uint16
	SrcMask   uint8
	DstMask   uint8
	_         uint16 // pad2
}

// DecodeNetFlowV5 decodes a raw NetFlow v5 UDP payload into a slice of Flow records.
// exporterIP is the source address of the UDP packet (the router that sent the data).
func DecodeNetFlowV5(data []byte, exporterIP net.IP) ([]model.Flow, error) {
	if len(data) < nfv5HeaderSize {
		return nil, fmt.Errorf("packet too short for NetFlow v5 header: %d bytes", len(data))
	}

	hdr := parseNFV5Header(data[:nfv5HeaderSize])

	if hdr.Version != 5 {
		return nil, fmt.Errorf("expected NetFlow version 5, got %d", hdr.Version)
	}
	if hdr.Count == 0 || hdr.Count > 30 {
		return nil, fmt.Errorf("invalid flow count: %d (expected 1-30)", hdr.Count)
	}

	expectedLen := nfv5HeaderSize + int(hdr.Count)*nfv5RecordSize
	if len(data) < expectedLen {
		return nil, fmt.Errorf("packet too short: need %d bytes for %d records, got %d",
			expectedLen, hdr.Count, len(data))
	}

	// Base timestamp from the header.
	baseTime := time.Unix(int64(hdr.UnixSecs), int64(hdr.UnixNsecs))

	flows := make([]model.Flow, 0, hdr.Count)
	for i := 0; i < int(hdr.Count); i++ {
		offset := nfv5HeaderSize + i*nfv5RecordSize
		rec := parseNFV5Record(data[offset : offset+nfv5RecordSize])

		// Calculate flow duration from sysUptime-relative timestamps.
		var duration time.Duration
		if rec.Last >= rec.First {
			duration = time.Duration(rec.Last-rec.First) * time.Millisecond
		}

		// Calculate flow timestamp: base time adjusted by how long ago the flow ended.
		// flowEnd = sysUptime at flow end; header.SysUptime = current sysUptime.
		flowTimestamp := baseTime
		if hdr.SysUptime >= rec.Last {
			offset := time.Duration(hdr.SysUptime-rec.Last) * time.Millisecond
			flowTimestamp = baseTime.Add(-offset)
		}

		flows = append(flows, model.Flow{
			Timestamp:   flowTimestamp,
			SrcAddr:     uint32ToIP(rec.SrcAddr),
			DstAddr:     uint32ToIP(rec.DstAddr),
			SrcPort:     rec.SrcPort,
			DstPort:     rec.DstPort,
			Protocol:    rec.Protocol,
			Bytes:       uint64(rec.Bytes),
			Packets:     uint64(rec.Packets),
			TCPFlags:    rec.TCPFlags,
			ToS:         rec.ToS,
			InputIface:  uint32(rec.Input),
			OutputIface: uint32(rec.Output),
			SrcAS:       uint32(rec.SrcAS),
			DstAS:       uint32(rec.DstAS),
			Duration:    duration,
			ExporterIP:  exporterIP,
		})
		flows[len(flows)-1].Classify()
	}

	return flows, nil
}

// parseNFV5Header parses the 24-byte NetFlow v5 header.
func parseNFV5Header(data []byte) nfv5Header {
	return nfv5Header{
		Version:      binary.BigEndian.Uint16(data[0:2]),
		Count:        binary.BigEndian.Uint16(data[2:4]),
		SysUptime:    binary.BigEndian.Uint32(data[4:8]),
		UnixSecs:     binary.BigEndian.Uint32(data[8:12]),
		UnixNsecs:    binary.BigEndian.Uint32(data[12:16]),
		FlowSequence: binary.BigEndian.Uint32(data[16:20]),
		EngineType:   data[20],
		EngineID:     data[21],
		SamplingInfo: binary.BigEndian.Uint16(data[22:24]),
	}
}

// parseNFV5Record parses a single 48-byte NetFlow v5 flow record.
func parseNFV5Record(data []byte) nfv5Record {
	return nfv5Record{
		SrcAddr:  binary.BigEndian.Uint32(data[0:4]),
		DstAddr:  binary.BigEndian.Uint32(data[4:8]),
		NextHop:  binary.BigEndian.Uint32(data[8:12]),
		Input:    binary.BigEndian.Uint16(data[12:14]),
		Output:   binary.BigEndian.Uint16(data[14:16]),
		Packets:  binary.BigEndian.Uint32(data[16:20]),
		Bytes:    binary.BigEndian.Uint32(data[20:24]),
		First:    binary.BigEndian.Uint32(data[24:28]),
		Last:     binary.BigEndian.Uint32(data[28:32]),
		SrcPort:  binary.BigEndian.Uint16(data[32:34]),
		DstPort:  binary.BigEndian.Uint16(data[34:36]),
		TCPFlags: data[37],
		Protocol: data[38],
		ToS:      data[39],
		SrcAS:    binary.BigEndian.Uint16(data[40:42]),
		DstAS:    binary.BigEndian.Uint16(data[42:44]),
		SrcMask:  data[44],
		DstMask:  data[45],
	}
}

// uint32ToIP converts a big-endian uint32 to a net.IP (IPv4).
func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	)
}
