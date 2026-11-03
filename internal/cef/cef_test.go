package cef

import (
	"os"
	"strings"
	"testing"

	"github.com/doganaydin/decoyevent/internal/event"
)

func TestCEFHeaderPipeEscape(t *testing.T) {
	rec := event.Record{
		Event: event.Event{
			ID: "n", Protocol: `a\b|c`, Action: "d", Severity: 3,
			SrcIP: "192.0.2.1", DstPort: 1, AttackVersion: "15",
		},
		Count: 1, Status: "accepted",
	}
	got := Format(rec)
	if !strings.Contains(got, `a\\b\|c d`) {
		t.Fatal(got)
	}
}

func TestCEFExtensionEscapesEqualsAndNewline(t *testing.T) {
	if got := escapeExt("a=b\nc"); got != `a\=b\nc` {
		t.Fatalf("%q", got)
	}
	rec := event.Record{
		Event: event.Event{
			ID: "n", Protocol: "ssh", Action: "login", Severity: 8,
			SrcIP: "203.0.113.10", DstPort: 22, AttackVersion: "15",
			Message: "a=b",
		},
		Count: 1, Status: "accepted",
	}
	if !strings.Contains(Format(rec), `msg=a\=b`) {
		t.Fatal(Format(rec))
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
	got := Format(event.Record{Event: ev, Count: 1, Status: "accepted"})
	want, err := os.ReadFile("../../testdata/login.cef")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
