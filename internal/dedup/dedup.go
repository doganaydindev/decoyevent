// Package dedup counts repeated event ids inside a time window.
package dedup

import (
	"sync"
	"time"
)

// StatusAccepted is the first sighting of an id inside the window.
const StatusAccepted = "accepted"

// StatusDuplicate is a repeated id inside the window.
const StatusDuplicate = "duplicate"

// Clock supplies the time used to expire entries.
type Clock interface {
	Now() time.Time
}

// Result is the outcome of observing one id.
type Result struct {
	Status string
	Count  uint64
	First  time.Time
	Last   time.Time
}

// Store is an in-memory dedup table.
type Store struct {
	mu     sync.Mutex
	window time.Duration
	clock  Clock
	items  map[string]item
}

type item struct {
	count uint64
	first time.Time
	last  time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// New returns a store. A non-positive window becomes 24 hours. A nil clock uses the system clock.
func New(window time.Duration, clock Clock) *Store {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if clock == nil {
		clock = systemClock{}
	}
	return &Store{window: window, clock: clock, items: map[string]item{}}
}

// Observe records id and reports whether it is new inside the window.
func (s *Store) Observe(id string) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now().UTC()
	rec, ok := s.items[id]
	if !ok || now.Sub(rec.last) > s.window {
		rec = item{count: 1, first: now, last: now}
		s.items[id] = rec
		return Result{Status: StatusAccepted, Count: 1, First: now, Last: now}
	}
	rec.count++
	rec.last = now
	s.items[id] = rec
	return Result{Status: StatusDuplicate, Count: rec.count, First: rec.first, Last: now}
}
