package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// IPFIX Information Element IDs (RFC 7012) — same numbering as NetFlow v9 for most fields.
const (
	ipfixFieldOctetDeltaCount   = 1
	ipfixFieldPacketDeltaCount  = 2
	ipfixFieldProtocolID        = 4
	ipfixFieldIPClassOfService  = 5
	ipfixFieldTCPControlBits    = 6
	ipfixFieldSourceTransPort   = 7
	ipfixFieldSourceIPv4Addr    = 8
	ipfixFieldSourcePrefixLen   = 9
	ipfixFieldIngressInterface  = 10
	ipfixFieldDestTransPort     = 11
	ipfixFieldDestIPv4Addr      = 12
	ipfixFieldDestPrefixLen     = 13
	ipfixFieldEgressInterface   = 14
	ipfixFieldIPNextHopIPv4Addr = 15
	ipfixFieldBgpSourceAS       = 16
	ipfixFieldBgpDestAS         = 17
	ipfixFieldFlowEndSysUp     = 21
	ipfixFieldFlowStartSysUp   = 22
	ipfixFieldSourceIPv6Addr    = 27
	ipfixFieldDestIPv6Addr      = 28
	ipfixFieldFlowStartSec     = 150
	ipfixFieldFlowEndSec       = 151
	ipfixFieldFlowStartMilli   = 152
	ipfixFieldFlowEndMilli     = 153
	// TCP quality metrics (IANA IPFIX assignments).
	// Note: Actual IE support varies by exporter vendor. These IDs cover
	// common implementations; exporters that use different IDs will simply
	// have these fields as zero (the heuristic detector provides a fallback).
	ipfixFieldTCPRetransmissionCount = 321 // tcpRetransmissionCount (draft-ietf-ipfix-tcpControlBits)
	ipfixFieldTCPSynTotalCount       = 322 // tcpSynTotalCount
	ipfixFieldTCPOutOfOrderCount     = 227 // vendor-specific out-of-order counter (not in base IANA registry)
	ipfixFieldPacketLossCount        = 233 // vendor-specific packet loss counter (not in base IANA registry)
	ipfixFieldRTPJitter              = 387 // transportRtpJitterMean (IANA IPFIX IE 387) in microseconds
)

// ipfixHeaderSize is the size of the IPFIX message header in bytes (RFC 7011 §3.1).
const ipfixHeaderSize = 16

// ipfixTemplateField describes one field in an IPFIX template record.
type ipfixTemplateField struct {
	ID             uint16
	Length         uint16
	EnterpriseNum  uint32
	IsEnterprise   bool
}

// ipfixTemplate holds a cached IPFIX template.
type ipfixTemplate struct {
	Fields []ipfixTemplateField
	Size   int // total bytes per data record
}

// IPFIXTemplateCache stores IPFIX templates keyed by (observation domain, template ID).
type IPFIXTemplateCache struct {
	mu        sync.RWMutex
	templates map[ipfixTemplateCacheKey]*ipfixTemplate
}

type ipfixTemplateCacheKey struct {
	ObsDomainID uint32
	TemplateID  uint16
}

// NewIPFIXTemplateCache creates a new IPFIX template cache.
func NewIPFIXTemplateCache() *IPFIXTemplateCache {
	return &IPFIXTemplateCache{
		templates: make(map[ipfixTemplateCacheKey]*ipfixTemplate),
	}
}

func (c *IPFIXTemplateCache) get(obsDomainID uint32, templateID uint16) *ipfixTemplate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.templates[ipfixTemplateCacheKey{obsDomainID, templateID}]
}

func (c *IPFIXTemplateCache) set(obsDomainID uint32, templateID uint16, tmpl *ipfixTemplate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.templates[ipfixTemplateCacheKey{obsDomainID, templateID}] = tmpl
}

// DecodeIPFIX decodes a raw IPFIX UDP payload into a slice of Flow records.
// The template cache is used to store and look up templates. exporterIP is the
// source address of the UDP packet.
func DecodeIPFIX(data []byte, exporterIP net.IP, cache *IPFIXTemplateCache) ([]model.Flow, error) {
	if len(data) < ipfixHeaderSize {
		return nil, fmt.Errorf("packet too short for IPFIX header: %d bytes", len(data))
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 10 {
		return nil, fmt.Errorf("expected IPFIX version 10, got %d", version)
	}

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	exportTime := binary.BigEndian.Uint32(data[4:8])
	_ = binary.BigEndian.Uint32(data[8:12]) // sequence number
	obsDomainID := binary.BigEndian.Uint32(data[12:16])

	baseTime := time.Unix(int64(exportTime), 0)

	if msgLen < ipfixHeaderSize || msgLen > len(data) {
		msgLen = len(data)
	}

	var flows []model.Flow
	offset := ipfixHeaderSize

	for offset+4 <= msgLen {
		setID := binary.BigEndian.Uint16(data[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if setLen < 4 || offset+setLen > msgLen {
			break
		}

		setData := data[offset+4 : offset+setLen]

		switch {
		case setID == 2:
			// Template Set
			parseIPFIXTemplates(setData, obsDomainID, cache)
		case setID == 3:
			// Options Template Set — skip
		default:
			// Data Set (setID >= 256)
			if setID >= 256 {
				decoded := decodeIPFIXDataSet(setData, obsDomainID, setID, cache, exporterIP, baseTime)
				flows = append(flows, decoded...)
			}
		}

		offset += setLen
	}

	return flows, nil
}

// parseIPFIXTemplates parses an IPFIX Template Set and stores templates in the cache.
func parseIPFIXTemplates(data []byte, obsDomainID uint32, cache *IPFIXTemplateCache) {
	offset := 0
	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		tmpl := &ipfixTemplate{
			Fields: make([]ipfixTemplateField, 0, fieldCount),
		}

		for i := 0; i < fieldCount; i++ {
			if offset+4 > len(data) {
				return
			}

			rawID := binary.BigEndian.Uint16(data[offset : offset+2])
			fLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4

			field := ipfixTemplateField{
				ID:     rawID & 0x7FFF,
				Length: fLen,
			}

			// Enterprise bit is the high bit of the ID field
			if rawID&0x8000 != 0 {
				if offset+4 > len(data) {
					return
				}
				field.EnterpriseNum = binary.BigEndian.Uint32(data[offset : offset+4])
				field.IsEnterprise = true
				offset += 4
			}

			tmpl.Fields = append(tmpl.Fields, field)
			tmpl.Size += int(fLen)
		}

		cache.set(obsDomainID, templateID, tmpl)
	}
}

// ipfixRecordContext holds per-record state for timestamp calculation.
type ipfixRecordContext struct {
	flowStartSysUp uint32
	flowEndSysUp   uint32
	flowStartMilli uint64
	flowEndMilli   uint64
	hasStartSysUp  bool
	hasEndSysUp    bool
	hasStartMilli  bool
	hasEndMilli    bool
}

// decodeIPFIXDataSet decodes data records in a Data Set using the cached template.
func decodeIPFIXDataSet(data []byte, obsDomainID uint32, templateID uint16,
	cache *IPFIXTemplateCache, exporterIP net.IP, baseTime time.Time) []model.Flow {

	tmpl := cache.get(obsDomainID, templateID)
	if tmpl == nil || tmpl.Size == 0 {
		return nil
	}

	var flows []model.Flow
	offset := 0

	for offset+tmpl.Size <= len(data) {
		f := model.Flow{
			Timestamp:  baseTime,
			ExporterIP: exporterIP,
		}
		ctx := &ipfixRecordContext{}

		for _, field := range tmpl.Fields {
			if offset+int(field.Length) > len(data) {
				return flows
			}

			fieldData := data[offset : offset+int(field.Length)]
			if !field.IsEnterprise {
				applyIPFIXField(&f, field.ID, fieldData, ctx)
			}
			offset += int(field.Length)
		}

		// Calculate duration and timestamp
		if ctx.hasStartMilli && ctx.hasEndMilli && ctx.flowEndMilli >= ctx.flowStartMilli {
			f.Duration = time.Duration(ctx.flowEndMilli-ctx.flowStartMilli) * time.Millisecond
			f.Timestamp = time.UnixMilli(int64(ctx.flowEndMilli))
		} else if ctx.hasStartSysUp && ctx.hasEndSysUp && ctx.flowEndSysUp >= ctx.flowStartSysUp {
			f.Duration = time.Duration(ctx.flowEndSysUp-ctx.flowStartSysUp) * time.Millisecond
		}

		f.Classify()
		flows = append(flows, f)
	}

	return flows
}

// applyIPFIXField maps a single IPFIX field value to the Flow struct.
func applyIPFIXField(f *model.Flow, fieldID uint16, data []byte, ctx *ipfixRecordContext) {
	switch fieldID {
	case ipfixFieldSourceIPv4Addr:
		if len(data) == 4 {
			f.SrcAddr = net.IP(make([]byte, 4))
			copy(f.SrcAddr, data)
		}
	case ipfixFieldDestIPv4Addr:
		if len(data) == 4 {
			f.DstAddr = net.IP(make([]byte, 4))
			copy(f.DstAddr, data)
		}
	case ipfixFieldSourceIPv6Addr:
		if len(data) == 16 {
			f.SrcAddr = net.IP(make([]byte, 16))
			copy(f.SrcAddr, data)
		}
	case ipfixFieldDestIPv6Addr:
		if len(data) == 16 {
			f.DstAddr = net.IP(make([]byte, 16))
			copy(f.DstAddr, data)
		}
	case ipfixFieldSourceTransPort:
		if len(data) == 2 {
			f.SrcPort = binary.BigEndian.Uint16(data)
		}
	case ipfixFieldDestTransPort:
		if len(data) == 2 {
			f.DstPort = binary.BigEndian.Uint16(data)
		}
	case ipfixFieldProtocolID:
		if len(data) >= 1 {
			f.Protocol = data[0]
		}
	case ipfixFieldOctetDeltaCount:
		f.Bytes = readUintN(data)
	case ipfixFieldPacketDeltaCount:
		f.Packets = readUintN(data)
	case ipfixFieldTCPControlBits:
		if len(data) >= 1 {
			f.TCPFlags = data[len(data)-1] // may be 1 or 2 bytes; use last byte
		}
	case ipfixFieldIPClassOfService:
		if len(data) >= 1 {
			f.ToS = data[0]
		}
	case ipfixFieldIngressInterface:
		f.InputIface = uint32(readUintN(data))
	case ipfixFieldEgressInterface:
		f.OutputIface = uint32(readUintN(data))
	case ipfixFieldBgpSourceAS:
		f.SrcAS = uint32(readUintN(data))
	case ipfixFieldBgpDestAS:
		f.DstAS = uint32(readUintN(data))
	case ipfixFieldFlowStartSysUp:
		if len(data) == 4 {
			ctx.flowStartSysUp = binary.BigEndian.Uint32(data)
			ctx.hasStartSysUp = true
		}
	case ipfixFieldFlowEndSysUp:
		if len(data) == 4 {
			ctx.flowEndSysUp = binary.BigEndian.Uint32(data)
			ctx.hasEndSysUp = true
		}
	case ipfixFieldFlowStartMilli:
		if len(data) == 8 {
			ctx.flowStartMilli = binary.BigEndian.Uint64(data)
			ctx.hasStartMilli = true
		}
	case ipfixFieldFlowEndMilli:
		if len(data) == 8 {
			ctx.flowEndMilli = binary.BigEndian.Uint64(data)
			ctx.hasEndMilli = true
		}
	case ipfixFieldTCPRetransmissionCount:
		f.Retransmissions = uint32(readUintN(data))
	case ipfixFieldTCPSynTotalCount:
		// SYN count can inform quality analysis; store as informational.
		// Currently no dedicated field — could be used for SYN flood detection.
	case ipfixFieldTCPOutOfOrderCount:
		f.OutOfOrder = uint32(readUintN(data))
	case ipfixFieldPacketLossCount:
		f.PacketLoss = uint32(readUintN(data))
	case ipfixFieldRTPJitter:
		f.JitterMicros = int64(readUintN(data))
	}
}
