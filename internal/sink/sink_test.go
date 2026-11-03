package sink

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	now := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
	err = Syslog(t.Context(), "udp://"+pc.LocalAddr().String(), "CEF:0|Decoyevent|decoyevent|1.0|T1110|ssh login|8|src=203.0.113.10\n", 8, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "<131>") {
		t.Fatalf("priority: %s", got)
	}
	if !strings.Contains(got, "decoyevent: CEF:0|Decoyevent|") {
		t.Fatal(got)
	}
	if strings.Contains(got, "\n") {
		t.Fatal("udp datagram should be one line")
	}
}

func TestSyslogRejectsBadAddress(t *testing.T) {
	if err := Syslog(t.Context(), "10.0.0.5:514", "CEF:0|x", 3, time.Now()); err == nil {
		t.Fatal("scheme was optional")
	}
}
