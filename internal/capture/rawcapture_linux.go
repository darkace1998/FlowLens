//go:build linux

package capture

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// runRawCapture opens an AF_PACKET socket on the specified device and reads
// packets, calling handler for each. It blocks until stopCh is closed.
func runRawCapture(device string, snapLen int, handler func(data []byte, ts time.Time), stopCh <-chan struct{}) error {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("capture: interface %q: %w", device, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("capture: socket: %w", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("capture: bind to %s: %w", device, err)
	}

	tv := syscall.Timeval{Sec: 1, Usec: 0}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("capture: set timeout: %w", err)
	}

	logger().Info("Raw capture started on %s (snaplen=%d)", device, snapLen)

	buf := make([]byte, snapLen)
	for {
		select {
		case <-stopCh:
			syscall.Close(fd)
			logger().Info("Raw capture stopped on %s", device)
			return nil
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
				continue
			}
			logger().Warn("Raw capture read error on %s: %v", device, err)
			continue
		}

		if n > 0 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			handler(pkt, time.Now())
		}
	}
}
