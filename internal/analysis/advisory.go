package analysis

import (
	"fmt"
	"time"
)

// Severity represents the severity level of an advisory.
type Severity int

const (
	INFO     Severity = iota // Informational observation
	WARNING                  // Requires attention
	CRITICAL                 // Immediate action recommended
)

// String returns the human-readable severity name.
func (s Severity) String() string {
	switch s {
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case CRITICAL:
		return "CRITICAL"
	default:
		return fmt.Sprintf("Severity(%d)", int(s))
	}
}

// Advisory represents a single analysis finding.
type Advisory struct {
	Severity    Severity
	Timestamp   time.Time
	Title       string
	Description string
	Action      string // Suggested remediation action
}
