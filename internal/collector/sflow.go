package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// sFlow v5 constants (RFC 3176 / sFlow v5 spec).
const (
	sflowVersion5           = 5
	sflowDatagramMinLen     = 28 // version(4)+agentAddr(8)+subAgentID(4)+seqNo(4)+uptime(4)+numSamples(4)
	sflowSampleTypeFlow     = 1  // enterprise=0, format=1 — flow sample
	sflowSampleTypeCounter  = 2  // enterprise=0, format=2 — counter sample
	sflowSampleTypeExpandedFlow    = 3 // enterprise=0, format=3 — expanded flow sample
	sflowSampleTypeExpandedCounter = 4 // enterprise=0, format=4 — expanded counter sample
	sflowRawPacketHeader    = 1  // enterprise=0, format=1 — raw packet header record
	sflowGenericIfCounters  = 1  // enterprise=0, format=1 — generic interface counters
)

// SFlowCounterSample represents a decoded sFlow counter sample for interface utilization.
type SFlowCounterSample struct {
	IfIndex      uint32
	IfType       uint32
	IfSpeed      uint64
	IfDirection  uint32 // 0=unknown, 1=full-duplex, 2=half-duplex, 3=in, 4=out
	IfStatus     uint32 // bit0=ifAdminStatus, bit1=ifOperStatus
	InOctets     uint64
	InPackets    uint32
	InErrors     uint32
	InDrops      uint32
	OutOctets    uint64
	OutPackets   uint32
	OutErrors    uint32
	OutDrops     uint32
	AgentIP      net.IP
	Timestamp    time.Time
}

// CounterHandler is a callback for decoded sFlow counter samples.
type CounterHandler func(counters []SFlowCounterSample)

// DecodeSFlow decodes an sFlow v5 datagram and returns flow records and counter samples.
// exporterIP is the source IP of the UDP packet (the sFlow agent).
func DecodeSFlow(data []byte, exporterIP net.IP) ([]model.Flow, []SFlowCounterSample, error) {
	if len(data) < sflowDatagramMinLen {
		return nil, nil, fmt.Errorf("sflow: packet too short: %d bytes", len(data))
	}

	version := binary.BigEndian.Uint32(data[0:4])
	if version != sflowVersion5 {
		return nil, nil, fmt.Errorf("sflow: unsupported version %d (expected 5)", version)
	}

	// Agent address: type(4) + addr(4 or 16)
	addrType := binary.BigEndian.Uint32(data[4:8])
	var agentIP net.IP
	var offset int
	switch addrType {
	case 1: // IPv4
		if len(data) < 12+16 {
			return nil, nil, fmt.Errorf("sflow: truncated agent address")
		}
		agentIP = net.IP(make([]byte, 4))
		copy(agentIP, data[8:12])
		offset = 12
	case 2: // IPv6
		if len(data) < 24+16 {
			return nil, nil, fmt.Errorf("sflow: truncated agent address")
		}
		agentIP = net.IP(make([]byte, 16))
		copy(agentIP, data[8:24])
		offset = 24
	default:
		return nil, nil, fmt.Errorf("sflow: unknown agent address type %d", addrType)
	}

	if len(data) < offset+16 {
		return nil, nil, fmt.Errorf("sflow: truncated datagram header")
	}

	// subAgentID := binary.BigEndian.Uint32(data[offset : offset+4])
	// seqNumber  := binary.BigEndian.Uint32(data[offset+4 : offset+8])
	sysUptime := binary.BigEndian.Uint32(data[offset+8 : offset+12])
	numSamples := binary.BigEndian.Uint32(data[offset+12 : offset+16])
	offset += 16

	_ = sysUptime // used for future timestamp calculations

	now := time.Now()

	var flows []model.Flow
	var counters []SFlowCounterSample

	for i := uint32(0); i < numSamples; i++ {
		if len(data) < offset+8 {
			break
		}

		sampleTypeRaw := binary.BigEndian.Uint32(data[offset : offset+4])
		sampleLen := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8

		if len(data) < offset+int(sampleLen) {
			break
		}

		sampleData := data[offset : offset+int(sampleLen)]
		offset += int(sampleLen)

		// Extract enterprise and format: enterprise = top 20 bits, format = bottom 12 bits
		enterprise := sampleTypeRaw >> 12
		format := sampleTypeRaw & 0xFFF

		if enterprise != 0 {
			continue // skip vendor-specific samples
		}

		switch format {
		case sflowSampleTypeFlow:
			fs := decodeSFlowFlowSample(sampleData, exporterIP, now, false)
			flows = append(flows, fs...)

		case sflowSampleTypeExpandedFlow:
			fs := decodeSFlowFlowSample(sampleData, exporterIP, now, true)
			flows = append(flows, fs...)

		case sflowSampleTypeCounter:
			cs := decodeSFlowCounterSample(sampleData, agentIP, now, false)
			counters = append(counters, cs...)

		case sflowSampleTypeExpandedCounter:
			cs := decodeSFlowCounterSample(sampleData, agentIP, now, true)
			counters = append(counters, cs...)
		}
	}

	return flows, counters, nil
}

// decodeSFlowFlowSample decodes a single sFlow flow sample (standard or expanded).
func decodeSFlowFlowSample(data []byte, exporterIP net.IP, ts time.Time, expanded bool) []model.Flow {
	// Standard flow sample header:
	//   seqNo(4) + sourceIDTypeIndex(4) + samplingRate(4) + samplePool(4) + drops(4) +
	//   input(4) + output(4) + numRecords(4) = 32 bytes
	// Expanded flow sample header:
	//   seqNo(4) + srcIDType(4) + srcIDIndex(4) + samplingRate(4) + samplePool(4) + drops(4) +
	//   inputFormat(4) + inputValue(4) + outputFormat(4) + outputValue(4) + numRecords(4) = 44 bytes

	var minLen int
	if expanded {
		minLen = 44
	} else {
		minLen = 32
	}

	if len(data) < minLen {
		return nil
	}

	var samplingRate uint32
	var inputIface, outputIface uint32
	var numRecords uint32
	var off int

	if expanded {
		samplingRate = binary.BigEndian.Uint32(data[12:16])
		// inputFormat := binary.BigEndian.Uint32(data[24:28])
		inputIface = binary.BigEndian.Uint32(data[28:32])
		// outputFormat := binary.BigEndian.Uint32(data[32:36])
		outputIface = binary.BigEndian.Uint32(data[36:40])
		numRecords = binary.BigEndian.Uint32(data[40:44])
		off = 44
	} else {
		samplingRate = binary.BigEndian.Uint32(data[8:12])
		inputIface = binary.BigEndian.Uint32(data[20:24])
		outputIface = binary.BigEndian.Uint32(data[24:28])
		numRecords = binary.BigEndian.Uint32(data[28:32])
		off = 32

		// In standard flow sample, input/output encode format in top 2 bits
		inputIface = inputIface & 0x3FFFFFFF
		outputIface = outputIface & 0x3FFFFFFF
	}

	var flows []model.Flow

	for r := uint32(0); r < numRecords; r++ {
		if len(data) < off+8 {
			break
		}

		recordTypeRaw := binary.BigEndian.Uint32(data[off : off+4])
		recordLen := binary.BigEndian.Uint32(data[off+4 : off+8])
		off += 8

		if len(data) < off+int(recordLen) {
			break
		}

		recordData := data[off : off+int(recordLen)]
		off += int(recordLen)

		recEnterprise := recordTypeRaw >> 12
		recFormat := recordTypeRaw & 0xFFF

		if recEnterprise != 0 || recFormat != sflowRawPacketHeader {
			continue
		}

		f, ok := decodeSFlowRawPacketHeader(recordData, ts)
		if !ok {
			continue
		}

		// Apply sampling rate multiplier to byte/packet counts.
		if samplingRate > 1 {
			f.Bytes *= uint64(samplingRate)
			f.Packets *= uint64(samplingRate)
		}

		f.InputIface = inputIface
		f.OutputIface = outputIface
		f.ExporterIP = exporterIP
		f.Classify()

		flows = append(flows, f)
	}

	return flows
}

// decodeSFlowRawPacketHeader decodes a raw packet header record into a Flow.
func decodeSFlowRawPacketHeader(data []byte, ts time.Time) (model.Flow, bool) {
	// Raw packet header record:
	//   headerProtocol(4) + frameLength(4) + strippedBytes(4) + headerLength(4) + header(variable)
	if len(data) < 16 {
		return model.Flow{}, false
	}

	headerProtocol := binary.BigEndian.Uint32(data[0:4])
	frameLength := binary.BigEndian.Uint32(data[4:8])
	// strippedBytes := binary.BigEndian.Uint32(data[8:12])
	headerLen := binary.BigEndian.Uint32(data[12:16])

	if len(data) < 16+int(headerLen) {
		return model.Flow{}, false
	}

	headerData := data[16 : 16+int(headerLen)]

	// Protocol 1 = Ethernet
	if headerProtocol != 1 {
		return model.Flow{}, false
	}

	f, ok := decodeSFlowEthernet(headerData, ts, frameLength)
	return f, ok
}

// decodeSFlowEthernet parses an Ethernet header and extracts IP flow fields.
func decodeSFlowEthernet(data []byte, ts time.Time, frameLength uint32) (model.Flow, bool) {
	if len(data) < 14 {
		return model.Flow{}, false
	}

	etherType := uint16(data[12])<<8 | uint16(data[13])
	offset := 14

	// Handle 802.1Q VLAN tag
	if etherType == 0x8100 {
		if len(data) < 18 {
			return model.Flow{}, false
		}
		etherType = uint16(data[16])<<8 | uint16(data[17])
		offset = 18
	}

	switch etherType {
	case 0x0800: // IPv4
		return decodeSFlowIPv4(data[offset:], ts, frameLength)
	case 0x86DD: // IPv6
		return decodeSFlowIPv6(data[offset:], ts, frameLength)
	default:
		return model.Flow{}, false
	}
}

// decodeSFlowIPv4 parses an IPv4 packet header from an sFlow sample.
func decodeSFlowIPv4(data []byte, ts time.Time, frameLength uint32) (model.Flow, bool) {
	if len(data) < 20 {
		return model.Flow{}, false
	}

	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return model.Flow{}, false
	}

	proto := data[9]
	srcIP := net.IP(make([]byte, 4))
	dstIP := net.IP(make([]byte, 4))
	copy(srcIP, data[12:16])
	copy(dstIP, data[16:20])
	tos := data[1]

	f := model.Flow{
		Timestamp: ts,
		SrcAddr:   srcIP,
		DstAddr:   dstIP,
		Protocol:  proto,
		Bytes:     uint64(frameLength),
		Packets:   1,
		ToS:       tos,
	}

	l4Data := data[ihl:]
	switch proto {
	case 6: // TCP
		if len(l4Data) >= 14 {
			f.SrcPort = uint16(l4Data[0])<<8 | uint16(l4Data[1])
			f.DstPort = uint16(l4Data[2])<<8 | uint16(l4Data[3])
			f.TCPFlags = l4Data[13]
		}
	case 17: // UDP
		if len(l4Data) >= 4 {
			f.SrcPort = uint16(l4Data[0])<<8 | uint16(l4Data[1])
			f.DstPort = uint16(l4Data[2])<<8 | uint16(l4Data[3])
		}
	}

	return f, true
}

// decodeSFlowIPv6 parses an IPv6 packet header from an sFlow sample.
func decodeSFlowIPv6(data []byte, ts time.Time, frameLength uint32) (model.Flow, bool) {
	if len(data) < 40 {
		return model.Flow{}, false
	}

	proto := data[6] // Next Header
	srcIP := net.IP(make([]byte, 16))
	dstIP := net.IP(make([]byte, 16))
	copy(srcIP, data[8:24])
	copy(dstIP, data[24:40])

	f := model.Flow{
		Timestamp: ts,
		SrcAddr:   srcIP,
		DstAddr:   dstIP,
		Protocol:  proto,
		Bytes:     uint64(frameLength),
		Packets:   1,
	}

	l4Data := data[40:]
	switch proto {
	case 6: // TCP
		if len(l4Data) >= 14 {
			f.SrcPort = uint16(l4Data[0])<<8 | uint16(l4Data[1])
			f.DstPort = uint16(l4Data[2])<<8 | uint16(l4Data[3])
			f.TCPFlags = l4Data[13]
		}
	case 17: // UDP
		if len(l4Data) >= 4 {
			f.SrcPort = uint16(l4Data[0])<<8 | uint16(l4Data[1])
			f.DstPort = uint16(l4Data[2])<<8 | uint16(l4Data[3])
		}
	}

	return f, true
}

// decodeSFlowCounterSample decodes counter records from an sFlow counter sample.
func decodeSFlowCounterSample(data []byte, agentIP net.IP, ts time.Time, expanded bool) []SFlowCounterSample {
	// Standard counter sample header:
	//   seqNo(4) + sourceIDTypeIndex(4) + numRecords(4) = 12 bytes
	// Expanded counter sample header:
	//   seqNo(4) + srcIDType(4) + srcIDIndex(4) + numRecords(4) = 16 bytes

	var minLen int
	var numRecords uint32
	var off int

	if expanded {
		minLen = 16
		if len(data) < minLen {
			return nil
		}
		numRecords = binary.BigEndian.Uint32(data[12:16])
		off = 16
	} else {
		minLen = 12
		if len(data) < minLen {
			return nil
		}
		numRecords = binary.BigEndian.Uint32(data[8:12])
		off = 12
	}

	var counters []SFlowCounterSample

	for r := uint32(0); r < numRecords; r++ {
		if len(data) < off+8 {
			break
		}

		recordTypeRaw := binary.BigEndian.Uint32(data[off : off+4])
		recordLen := binary.BigEndian.Uint32(data[off+4 : off+8])
		off += 8

		if len(data) < off+int(recordLen) {
			break
		}

		recordData := data[off : off+int(recordLen)]
		off += int(recordLen)

		recEnterprise := recordTypeRaw >> 12
		recFormat := recordTypeRaw & 0xFFF

		if recEnterprise != 0 || recFormat != sflowGenericIfCounters {
			continue
		}

		// Generic interface counters record: 88 bytes
		// ifIndex(4) + ifType(4) + ifSpeed(8) + ifDirection(4) + ifStatus(4) +
		// inOctets(8) + inUcastPkts(4) + inMulticastPkts(4) + inBroadcastPkts(4) + inDiscards(4) + inErrors(4) + inUnknownProtos(4) +
		// outOctets(8) + outUcastPkts(4) + outMulticastPkts(4) + outBroadcastPkts(4) + outDiscards(4) + outErrors(4)
		if len(recordData) < 88 {
			continue
		}

		cs := SFlowCounterSample{
			IfIndex:    binary.BigEndian.Uint32(recordData[0:4]),
			IfType:     binary.BigEndian.Uint32(recordData[4:8]),
			IfSpeed:    binary.BigEndian.Uint64(recordData[8:16]),
			IfDirection: binary.BigEndian.Uint32(recordData[16:20]),
			IfStatus:   binary.BigEndian.Uint32(recordData[20:24]),
			InOctets:   binary.BigEndian.Uint64(recordData[24:32]),
			InPackets:  binary.BigEndian.Uint32(recordData[32:36]) +
				binary.BigEndian.Uint32(recordData[36:40]) +
				binary.BigEndian.Uint32(recordData[40:44]),
			InDrops:    binary.BigEndian.Uint32(recordData[44:48]),
			InErrors:   binary.BigEndian.Uint32(recordData[48:52]),
			OutOctets:  binary.BigEndian.Uint64(recordData[56:64]),
			OutPackets: binary.BigEndian.Uint32(recordData[64:68]) +
				binary.BigEndian.Uint32(recordData[68:72]) +
				binary.BigEndian.Uint32(recordData[72:76]),
			OutDrops:   binary.BigEndian.Uint32(recordData[76:80]),
			OutErrors:  binary.BigEndian.Uint32(recordData[80:84]),
			AgentIP:    agentIP,
			Timestamp:  ts,
		}

		counters = append(counters, cs)
	}

	return counters
}
