// Package capture provides raw packet capture from mirror/SPAN ports and TAP
// interfaces. Captured packets are decoded into model.Flow records and
// forwarded to a FlowHandler callback, providing the same interface as the
// flow collector.
//
// This implementation uses Go's AF_PACKET raw sockets on Linux. On platforms
// where AF_PACKET is not available, Start returns a descriptive error.
package capture

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
)

// FlowHandler is a callback invoked for each batch of decoded flow records
// derived from captured packets.
type FlowHandler func(flows []model.Flow)

// Source represents a single packet capture source (mirror port or TAP interface).
type Source struct {
	cfg     config.InterfaceConfig
	handler FlowHandler
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewSource creates a new packet capture source.
func NewSource(cfg config.InterfaceConfig, handler FlowHandler) *Source {
	return &Source{
		cfg:     cfg,
		handler: handler,
		stopCh:  make(chan struct{}),
	}
}

// Start begins capturing packets on the configured interface.
// It blocks until Stop is called or an error occurs.
func (s *Source) Start() error {
	if s.cfg.Device == "" {
		return fmt.Errorf("capture: device not configured for interface %q", s.cfg.Name)
	}

	snapLen := s.cfg.SnapLen
	if snapLen <= 0 {
		snapLen = 65535
	}

	return s.startCapture(s.cfg.Device, snapLen)
}

// Stop terminates the capture loop.
func (s *Source) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// decodeEthernet parses a raw Ethernet frame and extracts IP flow fields.
// Returns a Flow and true if the packet was successfully decoded, or an empty
// Flow and false otherwise.
func decodeEthernet(data []byte, timestamp time.Time) (model.Flow, bool) {
	if len(data) < 14 {
		return model.Flow{}, false
	}

	// Ethernet header: 6 dst + 6 src + 2 ethertype.
	etherType := uint16(data[12])<<8 | uint16(data[13])

	offset := 14
	// Handle 802.1Q VLAN tag.
	if etherType == 0x8100 {
		if len(data) < 18 {
			return model.Flow{}, false
		}
		etherType = uint16(data[16])<<8 | uint16(data[17])
		offset = 18
	}

	switch etherType {
	case 0x0800: // IPv4
		return decodeIPv4(data[offset:], timestamp)
	case 0x86DD: // IPv6
		return decodeIPv6(data[offset:], timestamp)
	default:
		return model.Flow{}, false
	}
}

// decodeIPv4 parses an IPv4 packet and extracts flow fields.
func decodeIPv4(data []byte, timestamp time.Time) (model.Flow, bool) {
	if len(data) < 20 {
		return model.Flow{}, false
	}

	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return model.Flow{}, false
	}

	totalLen := int(data[2])<<8 | int(data[3])
	proto := data[9]
	srcIP := net.IP(make([]byte, 4))
	dstIP := net.IP(make([]byte, 4))
	copy(srcIP, data[12:16])
	copy(dstIP, data[16:20])
	tos := data[1]

	f := model.Flow{
		Timestamp: timestamp,
		SrcAddr:   srcIP,
		DstAddr:   dstIP,
		Protocol:  proto,
		Bytes:     uint64(totalLen),
		Packets:   1,
		ToS:       tos,
	}

	// Parse L4 header for ports and TCP flags.
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

	f.Classify()
	return f, true
}

// decodeIPv6 parses an IPv6 packet and extracts flow fields.
func decodeIPv6(data []byte, timestamp time.Time) (model.Flow, bool) {
	if len(data) < 40 {
		return model.Flow{}, false
	}

	payloadLen := int(data[4])<<8 | int(data[5])
	proto := data[6] // Next Header
	srcIP := net.IP(make([]byte, 16))
	dstIP := net.IP(make([]byte, 16))
	copy(srcIP, data[8:24])
	copy(dstIP, data[24:40])

	f := model.Flow{
		Timestamp: timestamp,
		SrcAddr:   srcIP,
		DstAddr:   dstIP,
		Protocol:  proto,
		Bytes:     uint64(40 + payloadLen),
		Packets:   1,
	}

	// Parse L4 header for ports.
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

	f.Classify()
	return f, true
}

// ProcessPacket decodes a raw Ethernet frame and sends the resulting flow to the handler.
// This is exported for testing and for platform-specific capture implementations.
func (s *Source) ProcessPacket(data []byte, timestamp time.Time) {
	f, ok := decodeEthernet(data, timestamp)
	if !ok {
		return
	}

	if s.handler != nil {
		s.handler([]model.Flow{f})
	}
}

// DeviceName returns the name of the configured capture device.
func (s *Source) DeviceName() string {
	return s.cfg.Device
}

// InterfaceName returns the human-readable name of this capture source.
func (s *Source) InterfaceName() string {
	if s.cfg.Name != "" {
		return s.cfg.Name
	}
	return s.cfg.Device
}

// logger returns the default logger for capture messages.
func logger() *logging.Logger {
	return logging.Default()
}
