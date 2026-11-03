package event

import (
	"strings"
	"testing"
)

func TestRejectSecret(t *testing.T) {
	body := `{"id":"lab-ssh-1","time":"2026-11-02T16:00:00Z","src_ip":"203.0.113.10","dst_port":22,"protocol":"ssh","action":"login","password":"nope"}`
	_, err := Parse([]byte(body))
	if err == nil || !strings.Contains(err.Error(), ErrSecret.Error()) {
		t.Fatal(err)
	}
	nested := `{"id":"lab-ssh-1","time":"2026-11-02T16:00:00Z","src_ip":"203.0.113.10","dst_port":22,"protocol":"ssh","action":"login","extra":{"Pass":"nope"}}`
	_, err = Parse([]byte(nested))
	if err == nil || !strings.Contains(err.Error(), ErrSecret.Error()) {
		t.Fatal(err)
	}
}

func TestRejectUnknownField(t *testing.T) {
	body := `{"id":"lab-ssh-1","time":"2026-11-02T16:00:00Z","src_ip":"203.0.113.10","dst_port":22,"protocol":"ssh","action":"login","extra":1}`
	_, err := Parse([]byte(body))
	if err == nil || !strings.Contains(err.Error(), ErrUnknownField.Error()) {
		t.Fatal(err)
	}
}

func TestRejectTooLarge(t *testing.T) {
	raw := make([]byte, maxBody+1)
	_, err := Parse(raw)
	if err != ErrTooLarge {
		t.Fatal(err)
	}
}

func TestRejectFractionalPort(t *testing.T) {
	body := `{"id":"lab-ssh-1","time":"2026-11-02T16:00:00Z","src_ip":"203.0.113.10","dst_port":22.5,"protocol":"ssh","action":"login"}`
	_, err := Parse([]byte(body))
	if err == nil || !strings.Contains(err.Error(), ErrInvalid.Error()) {
		t.Fatal(err)
	}
}
