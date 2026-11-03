package dedup

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) set(t time.Time) {
	f.mu.Lock()
	f.t = t
	f.mu.Unlock()
}

func TestDedupFirstStays(t *testing.T) {
	start := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: start}
	s := New(24*time.Hour, clk)
	first := s.Observe("lab-ssh-1")
	if first.Status != StatusAccepted || first.Count != 1 || !first.First.Equal(first.Last) {
		t.Fatalf("%+v", first)
	}
	clk.set(start.Add(time.Hour))
	second := s.Observe("lab-ssh-1")
	if second.Status != StatusDuplicate || second.Count != 2 || !second.First.Equal(first.First) {
		t.Fatalf("%+v", second)
	}
	if !second.Last.Equal(start.Add(time.Hour)) {
		t.Fatalf("last %s", second.Last)
	}
}

func TestDedupWindowExpiry(t *testing.T) {
	start := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: start}
	s := New(24*time.Hour, clk)
	s.Observe("lab-ssh-1")
	clk.set(start.Add(24*time.Hour + time.Second))
	again := s.Observe("lab-ssh-1")
	if again.Status != StatusAccepted || again.Count != 1 {
		t.Fatalf("%+v", again)
	}
	if !again.First.Equal(again.Last) {
		t.Fatal("expired id kept the old first timestamp")
	}
}

func TestDedupConcurrent(t *testing.T) {
	s := New(time.Hour, &fakeClock{t: time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)})
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			s.Observe("lab-ssh-1")
		}()
	}
	wg.Wait()
	if s.items["lab-ssh-1"].count != 2 {
		t.Fatalf("count %d", s.items["lab-ssh-1"].count)
	}
}

func TestApplySQLite(t *testing.T) {
	path := t.TempDir() + "/state.db"
	start := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: start}
	first, err := Apply(path, "lab-ssh-1", 24*time.Hour, clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusAccepted || first.Count != 1 {
		t.Fatalf("%+v", first)
	}
	clk.set(start.Add(time.Minute))
	second, err := Apply(path, "lab-ssh-1", 24*time.Hour, clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != StatusDuplicate || second.Count != 2 || !second.First.Equal(first.First) {
		t.Fatalf("%+v", second)
	}
	clk.set(start.Add(time.Minute).Add(24*time.Hour + time.Second))
	again, err := Apply(path, "lab-ssh-1", 24*time.Hour, clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != StatusAccepted || again.Count != 1 {
		t.Fatalf("%+v", again)
	}
}

func TestApplyRollsBackWhenDeliveryFails(t *testing.T) {
	path := t.TempDir() + "/state.db"
	clk := &fakeClock{t: time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)}
	_, err := Apply(path, "lab-ssh-1", 24*time.Hour, clk, func(Result) error {
		return errors.New("siem down")
	})
	if err == nil || err.Error() != "siem down" {
		t.Fatal(err)
	}
	got, err := Apply(path, "lab-ssh-1", 24*time.Hour, clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusAccepted || got.Count != 1 {
		t.Fatalf("failed delivery was counted: %+v", got)
	}
}
