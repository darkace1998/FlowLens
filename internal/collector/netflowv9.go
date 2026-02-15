package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// NetFlow v9 field type IDs (RFC 3954).
const (
	nfv9FieldInBytes        = 1
	nfv9FieldInPkts         = 2
	nfv9FieldProtocol       = 4
	nfv9FieldSrcTos         = 5
	nfv9FieldTCPFlags       = 6
	nfv9FieldL4SrcPort      = 7
	nfv9FieldIPv4SrcAddr    = 8
	nfv9FieldSrcMask        = 9
	nfv9FieldInputSNMP      = 10
	nfv9FieldL4DstPort      = 11
	nfv9FieldIPv4DstAddr    = 12
	nfv9FieldDstMask        = 13
	nfv9FieldOutputSNMP     = 14
	nfv9FieldIPv4NextHop    = 15
	nfv9FieldSrcAS          = 16
	nfv9FieldDstAS          = 17
	nfv9FieldLastSwitched   = 21
	nfv9FieldFirstSwitched  = 22
	nfv9FieldIPv6SrcAddr    = 27
	nfv9FieldIPv6DstAddr    = 28
	nfv9FieldIPv6FlowLabel  = 31
	nfv9FieldDirection      = 61
	nfv9FieldIPv6NextHop    = 62
)

// nfv9HeaderSize is the size of the NetFlow v9 packet header in bytes.
const nfv9HeaderSize = 20

// nfv9TemplateField describes one field in a NetFlow v9 template record.
type nfv9TemplateField struct {
	Type   uint16
	Length uint16
}

// nfv9Template holds a cached NetFlow v9 template record.
type nfv9Template struct {
	Fields []nfv9TemplateField
	Size   int // total bytes per data record
}

// NFV9TemplateCache stores NetFlow v9 templates keyed by (sourceID, templateID).
type NFV9TemplateCache struct {
	mu        sync.RWMutex
	templates map[nfv9TemplateCacheKey]*nfv9Template
}

type nfv9TemplateCacheKey struct {
	SourceID   uint32
	TemplateID uint16
}

// NewNFV9TemplateCache creates a new template cache.
func NewNFV9TemplateCache() *NFV9TemplateCache {
	return &NFV9TemplateCache{
		templates: make(map[nfv9TemplateCacheKey]*nfv9Template),
	}
}

func (c *NFV9TemplateCache) get(sourceID uint32, templateID uint16) *nfv9Template {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.templates[nfv9TemplateCacheKey{sourceID, templateID}]
}

func (c *NFV9TemplateCache) set(sourceID uint32, templateID uint16, tmpl *nfv9Template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.templates[nfv9TemplateCacheKey{sourceID, templateID}] = tmpl
}

// DecodeNetFlowV9 decodes a raw NetFlow v9 UDP payload into a slice of Flow records.
// The template cache is used to store and look up templates. exporterIP is the
// source address of the UDP packet.
func DecodeNetFlowV9(data []byte, exporterIP net.IP, cache *NFV9TemplateCache) ([]model.Flow, error) {
	if len(data) < nfv9HeaderSize {
		return nil, fmt.Errorf("packet too short for NetFlow v9 header: %d bytes", len(data))
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 9 {
		return nil, fmt.Errorf("expected NetFlow version 9, got %d", version)
	}

	count := binary.BigEndian.Uint16(data[2:4])
	sysUptime := binary.BigEndian.Uint32(data[4:8])
	unixSecs := binary.BigEndian.Uint32(data[8:12])
	_ = binary.BigEndian.Uint32(data[12:16]) // sequence number
	sourceID := binary.BigEndian.Uint32(data[16:20])

	baseTime := time.Unix(int64(unixSecs), 0)
	_ = count // count is the number of FlowSet records in the packet (RFC 3954)

	var flows []model.Flow
	offset := nfv9HeaderSize

	for offset+4 <= len(data) {
		flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
		flowSetLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if flowSetLen < 4 || offset+flowSetLen > len(data) {
			break // malformed or truncated
		}

		setData := data[offset+4 : offset+flowSetLen]

		switch {
		case flowSetID == 0:
			// Template FlowSet
			parseNFV9Templates(setData, sourceID, cache)
		case flowSetID == 1:
			// Options Template FlowSet — skip for now
		default:
			// Data FlowSet (flowSetID >= 256)
			if flowSetID >= 256 {
				decoded := decodeNFV9DataFlowSet(setData, sourceID, flowSetID, cache, exporterIP, baseTime, sysUptime)
				flows = append(flows, decoded...)
			}
		}

		offset += flowSetLen
		// FlowSets are padded to 4-byte boundary
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	return flows, nil
}

// parseNFV9Templates parses a Template FlowSet and stores templates in the cache.
func parseNFV9Templates(data []byte, sourceID uint32, cache *NFV9TemplateCache) {
	offset := 0
	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+fieldCount*4 > len(data) {
			break
		}

		tmpl := &nfv9Template{
			Fields: make([]nfv9TemplateField, fieldCount),
		}

		for i := 0; i < fieldCount; i++ {
			fType := binary.BigEndian.Uint16(data[offset : offset+2])
			fLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			tmpl.Fields[i] = nfv9TemplateField{Type: fType, Length: fLen}
			tmpl.Size += int(fLen)
			offset += 4
		}

		cache.set(sourceID, templateID, tmpl)
	}
}

// nfv9RecordContext holds per-record state for FirstSwitched/LastSwitched calculation.
type nfv9RecordContext struct {
	firstSwitched    uint32
	lastSwitched     uint32
	hasFirst, hasLast bool
}

// decodeNFV9DataFlowSet decodes data records in a Data FlowSet using the cached template.
func decodeNFV9DataFlowSet(data []byte, sourceID uint32, templateID uint16,
	cache *NFV9TemplateCache, exporterIP net.IP, baseTime time.Time, sysUptime uint32) []model.Flow {

	tmpl := cache.get(sourceID, templateID)
	if tmpl == nil || tmpl.Size == 0 {
		return nil // no template yet
	}

	var flows []model.Flow
	offset := 0

	for offset+tmpl.Size <= len(data) {
		f := model.Flow{
			Timestamp:  baseTime,
			ExporterIP: exporterIP,
		}
		ctx := &nfv9RecordContext{}

		for _, field := range tmpl.Fields {
			if offset+int(field.Length) > len(data) {
				return flows
			}

			fieldData := data[offset : offset+int(field.Length)]
			applyNFV9Field(&f, field.Type, fieldData, ctx)
			offset += int(field.Length)
		}

		// Calculate duration and timestamp from switched times.
		if ctx.hasFirst && ctx.hasLast && ctx.lastSwitched >= ctx.firstSwitched {
			f.Duration = time.Duration(ctx.lastSwitched-ctx.firstSwitched) * time.Millisecond
		}
		if ctx.hasLast && sysUptime >= ctx.lastSwitched {
			elapsed := time.Duration(sysUptime-ctx.lastSwitched) * time.Millisecond
			f.Timestamp = baseTime.Add(-elapsed)
		}

		flows = append(flows, f)
	}

	return flows
}

// applyNFV9Field maps a single NetFlow v9 field value to the Flow struct.
func applyNFV9Field(f *model.Flow, fieldType uint16, data []byte, ctx *nfv9RecordContext) {
	switch fieldType {
	case nfv9FieldIPv4SrcAddr:
		if len(data) == 4 {
			f.SrcAddr = net.IP(make([]byte, 4))
			copy(f.SrcAddr, data)
		}
	case nfv9FieldIPv4DstAddr:
		if len(data) == 4 {
			f.DstAddr = net.IP(make([]byte, 4))
			copy(f.DstAddr, data)
		}
	case nfv9FieldIPv6SrcAddr:
		if len(data) == 16 {
			f.SrcAddr = net.IP(make([]byte, 16))
			copy(f.SrcAddr, data)
		}
	case nfv9FieldIPv6DstAddr:
		if len(data) == 16 {
			f.DstAddr = net.IP(make([]byte, 16))
			copy(f.DstAddr, data)
		}
	case nfv9FieldL4SrcPort:
		if len(data) == 2 {
			f.SrcPort = binary.BigEndian.Uint16(data)
		}
	case nfv9FieldL4DstPort:
		if len(data) == 2 {
			f.DstPort = binary.BigEndian.Uint16(data)
		}
	case nfv9FieldProtocol:
		if len(data) >= 1 {
			f.Protocol = data[0]
		}
	case nfv9FieldInBytes:
		f.Bytes = readUintN(data)
	case nfv9FieldInPkts:
		f.Packets = readUintN(data)
	case nfv9FieldTCPFlags:
		if len(data) >= 1 {
			f.TCPFlags = data[0]
		}
	case nfv9FieldSrcTos:
		if len(data) >= 1 {
			f.ToS = data[0]
		}
	case nfv9FieldInputSNMP:
		f.InputIface = uint32(readUintN(data))
	case nfv9FieldOutputSNMP:
		f.OutputIface = uint32(readUintN(data))
	case nfv9FieldSrcAS:
		f.SrcAS = uint32(readUintN(data))
	case nfv9FieldDstAS:
		f.DstAS = uint32(readUintN(data))
	case nfv9FieldFirstSwitched:
		if len(data) == 4 {
			ctx.firstSwitched = binary.BigEndian.Uint32(data)
			ctx.hasFirst = true
		}
	case nfv9FieldLastSwitched:
		if len(data) == 4 {
			ctx.lastSwitched = binary.BigEndian.Uint32(data)
			ctx.hasLast = true
		}
	}
}

// readUintN reads a big-endian unsigned integer of 1, 2, 4, or 8 bytes.
func readUintN(data []byte) uint64 {
	switch len(data) {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(data))
	case 4:
		return uint64(binary.BigEndian.Uint32(data))
	case 8:
		return binary.BigEndian.Uint64(data)
	default:
		return 0
	}
}
