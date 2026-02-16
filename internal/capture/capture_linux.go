//go:build linux

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

// startCapture opens an AF_PACKET raw socket on the specified device and reads
// packets until Stop is called.
func (s *Source) startCapture(device string, snapLen int) error {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("capture: interface %q: %w", device, err)
	}

	// Open an AF_PACKET socket in raw mode (ETH_P_ALL = 0x0003).
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("capture: socket: %w", err)
	}

	// Bind to the specific interface.
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("capture: bind to %s: %w", device, err)
	}

	// Set a read timeout so we can check the stop channel periodically.
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("capture: set timeout: %w", err)
	}

	logger().Info("Capture started on %s (%s, snaplen=%d)", device, s.InterfaceName(), snapLen)

	s.wg.Add(1)
	defer s.wg.Done()

	buf := make([]byte, snapLen)
	for {
		select {
		case <-s.stopCh:
			syscall.Close(fd)
			logger().Info("Capture stopped on %s", device)
			return nil
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// Timeout is expected; just loop and check stopCh.
			if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
				continue
			}
			logger().Warn("Capture read error on %s: %v", device, err)
			continue
		}

		if n > 0 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			s.ProcessPacket(pkt, time.Now())
		}
	}
}

// htons converts a uint16 from host to network byte order (big-endian).
func htons(v uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return binary.NativeEndian.Uint16(buf)
}
