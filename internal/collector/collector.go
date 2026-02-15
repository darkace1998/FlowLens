package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

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
	conns      []*net.UDPConn
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

// Start begins listening for NetFlow/IPFIX packets on the configured UDP ports.
// It listens on both NetFlowPort and IPFIXPort (if configured and different).
// It blocks until all connections are closed or an unrecoverable error occurs.
func (c *Collector) Start() error {
	ports := []int{c.cfg.NetFlowPort}
	if c.cfg.IPFIXPort > 0 && c.cfg.IPFIXPort != c.cfg.NetFlowPort {
		ports = append(ports, c.cfg.IPFIXPort)
	}

	for _, port := range ports {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			// Close any already-opened connections on failure.
			for _, prev := range c.conns {
				prev.Close()
			}
			c.conns = nil
			return err
		}
		if err := conn.SetReadBuffer(c.cfg.BufferSize); err != nil {
			logging.Default().Warn("Failed to set UDP read buffer to %d on port %d: %v", c.cfg.BufferSize, port, err)
		}
		c.conns = append(c.conns, conn)
		logging.Default().Info("Collector listening on UDP :%d (NetFlow v5/v9/IPFIX)", port)
	}

	// Run a read loop for each connection; block until all finish.
	var wg sync.WaitGroup
	errCh := make(chan error, len(c.conns))
	for _, conn := range c.conns {
		wg.Add(1)
		go func(conn *net.UDPConn) {
			defer wg.Done()
			if err := c.readLoop(conn); err != nil {
				errCh <- err
			}
		}(conn)
	}
	wg.Wait()
	close(errCh)

	// Return the first error, if any.
	for err := range errCh {
		return err
	}
	return nil
}

// readLoop reads and processes packets from a single UDP connection.
func (c *Collector) readLoop(conn *net.UDPConn) error {
	buf := make([]byte, c.cfg.BufferSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
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

// Stop closes all UDP connections, causing Start to return.
func (c *Collector) Stop() {
	for _, conn := range c.conns {
		conn.Close()
	}
}

// Addr returns the local address of the first listener,
// or nil if the collector has not been started.
func (c *Collector) Addr() net.Addr {
	if len(c.conns) > 0 {
		return c.conns[0].LocalAddr()
	}
	return nil
}

// Addrs returns the local addresses of all listeners.
func (c *Collector) Addrs() []net.Addr {
	addrs := make([]net.Addr, len(c.conns))
	for i, conn := range c.conns {
		addrs[i] = conn.LocalAddr()
	}
	return addrs
}
