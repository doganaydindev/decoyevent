// Package stix renders a decoy event as one STIX 2.1 indicator.
package stix

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/doganaydin/decoyevent/internal/event"
	"github.com/doganaydin/decoyevent/internal/mitre"
)

// Namespace is the UUID v5 namespace for indicator ids. It is not an IANA registration.
const Namespace = "a3b0c1d2-e3f4-4516-87a9-b0c1d2e3f405"

// Format returns the indented indicator JSON, including a trailing newline.
func Format(rec event.Record) ([]byte, error) {
	id, err := IndicatorID(rec.Event.ID)
	if err != nil {
		return nil, err
	}
	when := rec.Event.Time.UTC().Format(time.RFC3339)
	kind := "ipv4-addr"
	if strings.Contains(rec.Event.SrcIP, ":") {
		kind = "ipv6-addr"
	}
	ind := indicator{
		Type:        "indicator",
		SpecVersion: "2.1",
		ID:          id,
		Created:     when,
		Modified:    when,
		Name:        rec.Event.Protocol + " " + rec.Event.Action + " via decoyevent",
		Pattern:     "[" + kind + ":value = '" + escapePattern(rec.Event.SrcIP) + "']",
		PatternType: "stix",
		ValidFrom:   when,
		Confidence:  mitre.Confidence(rec.Event.Technique),
	}
	if rec.Event.Technique != "" {
		ind.IndicatorTypes = []string{"malicious-activity"}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ind); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// IndicatorID is the stable indicator-- UUID for an event id.
func IndicatorID(eventID string) (string, error) {
	ns, err := parseUUID(Namespace)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(append(ns[:], []byte("decoyevent|"+eventID)...))
	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x50
	id[8] = (id[8] & 0x3f) | 0x80
	return "indicator--" + formatUUID(id), nil
}

type indicator struct {
	Type           string   `json:"type"`
	SpecVersion    string   `json:"spec_version"`
	ID             string   `json:"id"`
	Created        string   `json:"created"`
	Modified       string   `json:"modified"`
	Name           string   `json:"name"`
	Pattern        string   `json:"pattern"`
	PatternType    string   `json:"pattern_type"`
	ValidFrom      string   `json:"valid_from"`
	IndicatorTypes []string `json:"indicator_types,omitempty"`
	Confidence     int      `json:"confidence"`
}

func escapePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		return out, fmt.Errorf("namespace uuid")
	}
	copy(out[:], raw)
	return out, nil
}

func formatUUID(id [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}
