package collector

import (
	"errors"
	"log"
	"net"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
)

// FlowHandler is a callback invoked for each batch of decoded flow records.
type FlowHandler func(flows []model.Flow)

// Collector listens for NetFlow/IPFIX packets on UDP and decodes them.
type Collector struct {
	cfg     config.CollectorConfig
	handler FlowHandler
	conn    *net.UDPConn
}

// New creates a new Collector with the given config and flow handler.
func New(cfg config.CollectorConfig, handler FlowHandler) *Collector {
	return &Collector{
		cfg:     cfg,
		handler: handler,
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
		log.Printf("warning: failed to set UDP read buffer to %d: %v", c.cfg.BufferSize, err)
	}

	log.Printf("Collector listening on UDP :%d (NetFlow v5)", c.cfg.NetFlowPort)

	buf := make([]byte, c.cfg.BufferSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if the connection was closed intentionally.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Copy data so buffer can be reused immediately.
		data := make([]byte, n)
		copy(data, buf[:n])

		exporterIP := remoteAddr.IP

		flows, err := DecodeNetFlowV5(data, exporterIP)
		if err != nil {
			log.Printf("Failed to decode NetFlow v5 from %s: %v", remoteAddr, err)
			continue
		}

		if c.handler != nil && len(flows) > 0 {
			c.handler(flows)
		}
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
