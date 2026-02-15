package storage

import (
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

// Storage defines the interface for persisting and querying flow records.
type Storage interface {
	// Insert stores one or more flow records.
	Insert(flows []model.Flow) error

	// Recent returns flow records from the last duration d, up to limit results.
	// If limit is 0, all matching records are returned.
	Recent(d time.Duration, limit int) ([]model.Flow, error)

	// Close releases any resources held by the storage backend.
	Close() error
}
