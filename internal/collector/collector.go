package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
)

// FlowHandler is a callback invoked for each batch of decoded flow records.
type FlowHandler func(flows []model.Flow)

// Collector listens for NetFlow/IPFIX packets on UDP and decodes them.
type Collector struct {
	cfg        config.CollectorConfig
	handler    FlowHandler
	conn       *net.UDPConn
	nfv9Cache  *NFV9TemplateCache
	ipfixCache *IPFIXTemplateCache
}

// New creates a new Collector with the given config and flow handler.
func New(cfg config.CollectorConfig, handler FlowHandler) *Collector {
	return &Collector{
		cfg:        cfg,
		handler:    handler,
		nfv9Cache:  NewNFV9TemplateCache(),
		ipfixCache: NewIPFIXTemplateCache(),
	}
}

// Start begins listening for NetFlow packets on the configured UDP port.
// It blocks until the connection is closed or an unrecoverable error occurs.
func (c *Collector) Start() error {
	addr := &net.UDPAddr{Port: c.cfg.NetFlowPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	c.conn = conn

	if err := conn.SetReadBuffer(c.cfg.BufferSize); err != nil {
		logging.Default().Warn("Failed to set UDP read buffer to %d: %v", c.cfg.BufferSize, err)
	}

	logging.Default().Info("Collector listening on UDP :%d (NetFlow v5/v9/IPFIX)", c.cfg.NetFlowPort)

	buf := make([]byte, c.cfg.BufferSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if the connection was closed intentionally.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logging.Default().Error("UDP read error: %v", err)
			continue
		}

		// Copy data so buffer can be reused immediately.
		data := make([]byte, n)
		copy(data, buf[:n])

		exporterIP := remoteAddr.IP

		flows, err := c.decodePacket(data, exporterIP)
		if err != nil {
			logging.Default().Warn("Failed to decode flow from %s: %v", remoteAddr, err)
			continue
		}

		if c.handler != nil && len(flows) > 0 {
			c.handler(flows)
		}
	}
}

// decodePacket auto-detects the NetFlow/IPFIX version and dispatches to the appropriate decoder.
func (c *Collector) decodePacket(data []byte, exporterIP net.IP) ([]model.Flow, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	version := binary.BigEndian.Uint16(data[0:2])

	switch version {
	case 5:
		return DecodeNetFlowV5(data, exporterIP)
	case 9:
		return DecodeNetFlowV9(data, exporterIP, c.nfv9Cache)
	case 10:
		return DecodeIPFIX(data, exporterIP, c.ipfixCache)
	default:
		return nil, fmt.Errorf("unsupported NetFlow/IPFIX version: %d", version)
	}
}

// Stop closes the UDP connection, causing Start to return.
func (c *Collector) Stop() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Addr returns the local address the collector is listening on,
// or nil if the collector has not been started.
func (c *Collector) Addr() net.Addr {
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return nil
}
