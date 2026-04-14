// Package watcher ingests DNS query events and persists them as observations.
package watcher

import (
	"context"
	"strings"
	"time"

	"github.com/belotserkovtsev/split-engine/internal/storage"
)

// Event is a normalized DNS observation.
type Event struct {
	Domain    string
	Peer      string
	Timestamp time.Time
}

// Observation is returned after successful ingest; nil for empty/filtered events.
type Observation struct {
	Domain string
	Peer   string
}

// Ingest normalizes an event and upserts it into storage.
// Returns nil, nil for empty domains.
func Ingest(ctx context.Context, s *storage.Store, e Event) (*Observation, error) {
	domain := strings.TrimRight(strings.ToLower(strings.TrimSpace(e.Domain)), ".")
	if domain == "" {
		return nil, nil
	}

	if err := s.UpsertDomain(ctx, domain, e.Peer, e.Timestamp); err != nil {
		return nil, err
	}
	return &Observation{Domain: domain, Peer: e.Peer}, nil
}
