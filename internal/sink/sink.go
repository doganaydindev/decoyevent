// Package sink delivers a formatted event to a SIEM or a webhook receiver.
package sink

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/doganaydin/decoyevent/internal/sign"
)

// Post sends body to endpoint and sets the signature header. Redirects are not followed.
func Post(ctx context.Context, endpoint, contentType string, body []byte, signatureHex string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(sign.Header, "sha256="+signatureHex)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post %s: %s", endpoint, resp.Status)
	}
	return nil
}

// Syslog sends a CEF line to a udp:// or tcp:// address using RFC 3164 framing.
func Syslog(ctx context.Context, address, cefLine string, cefSeverity int, now time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("syslog address: %w", err)
	}
	if u.Scheme != "udp" && u.Scheme != "tcp" || u.Host == "" {
		return fmt.Errorf("syslog address must be udp://host:port or tcp://host:port")
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "decoyevent"
	}
	line := frame(cefLine, cefSeverity, host, now)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, u.Scheme, u.Host)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := line
	if u.Scheme == "tcp" {
		payload += "\n"
	}
	_, err = io.WriteString(conn, payload)
	return err
}

func frame(cefLine string, cefSeverity int, host string, now time.Time) string {
	pri := 16*8 + syslogSeverity(cefSeverity)
	msg := strings.TrimRight(cefLine, "\n")
	return fmt.Sprintf("<%d>%s %s decoyevent: %s", pri, now.UTC().Format("Jan _2 15:04:05"), host, msg)
}

func syslogSeverity(cefSeverity int) int {
	switch {
	case cefSeverity >= 9:
		return 2
	case cefSeverity >= 8:
		return 3
	case cefSeverity >= 5:
		return 4
	default:
		return 5
	}
}
