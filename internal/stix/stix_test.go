package stix

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/doganaydin/decoyevent/internal/event"
)

func TestSTIXIDStable(t *testing.T) {
	a, err := IndicatorID("lab-ssh-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := IndicatorID("lab-ssh-1")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a != "indicator--68733f5b-d39b-53da-9953-548ec518b586" {
		t.Fatalf("id %s", a)
	}
}

func TestSTIXIPv6Pattern(t *testing.T) {
	ev := event.Event{
		ID: "v6", Time: time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC),
		SrcIP: "2001:db8::1", DstPort: 22, Protocol: "tcp", Action: "scan",
		AttackVersion: "15", Technique: "T1046", Severity: 5,
	}
	got, err := Format(event.Record{Event: ev, Count: 1, Status: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`[ipv6-addr:value = '2001:db8::1']`)) {
		t.Fatalf("%s", got)
	}
	if bytes.Contains(got, []byte("ipv4-addr")) {
		t.Fatal("ipv4 pattern on an ipv6 event")
	}
}

func TestLoginGolden(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/login.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := event.Prepare(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Format(event.Record{Event: ev, Count: 1, Status: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../testdata/login.stix.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}
