//go:build !linux

package capture

import (
	"fmt"
	"runtime"
	"time"
)

// runRawCapture is a stub for platforms that do not support AF_PACKET raw sockets.
func runRawCapture(device string, snapLen int, handler func(data []byte, ts time.Time), stopCh <-chan struct{}) error {
	return fmt.Errorf("capture: raw packet capture is not supported on %s (requires Linux AF_PACKET)", runtime.GOOS)
}
