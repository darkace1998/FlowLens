//go:build !linux

package capture

import (
	"fmt"
	"runtime"
)

// startCapture is a stub for platforms that do not support AF_PACKET raw sockets.
func (s *Source) startCapture(device string, snapLen int) error {
	return fmt.Errorf("capture: raw packet capture is not supported on %s (requires Linux AF_PACKET)", runtime.GOOS)
}
