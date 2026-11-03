// Package cef renders a decoy event as one CEF line.
package cef

import (
	"strconv"
	"strings"

	"github.com/doganaydin/decoyevent/internal/event"
)

// Format returns one CEF syslog line, including the trailing newline.
func Format(rec event.Record) string {
	sig := rec.Event.Technique
	if sig == "" {
		sig = "UNMAPPED"
	}
	name := rec.Event.Protocol + " " + rec.Event.Action
	head := strings.Join([]string{
		"CEF:0",
		escapeHeader("Decoyevent"),
		escapeHeader("decoyevent"),
		escapeHeader("1.0"),
		escapeHeader(sig),
		escapeHeader(name),
		strconv.Itoa(rec.Event.Severity),
	}, "|")
	ext := []string{"src=" + escapeExt(rec.Event.SrcIP)}
	if rec.Event.DstIP != "" {
		ext = append(ext, "dst="+escapeExt(rec.Event.DstIP))
	}
	ext = append(ext,
		"dpt="+strconv.Itoa(rec.Event.DstPort),
		"proto="+escapeExt(rec.Event.Protocol),
		"act="+escapeExt(rec.Event.Action),
	)
	if rec.Event.Sensor != "" {
		ext = append(ext, "dvchost="+escapeExt(rec.Event.Sensor))
	}
	if rec.Event.Message != "" {
		ext = append(ext, "msg="+escapeExt(rec.Event.Message))
	}
	if rec.Event.Decoy != "" {
		ext = append(ext, "cs1Label=decoy", "cs1="+escapeExt(rec.Event.Decoy))
	}
	ext = append(ext,
		"cs2Label=eventId",
		"cs2="+escapeExt(rec.Event.ID),
		"cs3Label=attack",
		"cs3="+escapeExt(rec.Event.AttackVersion),
		"cnt="+strconv.FormatUint(rec.Count, 10),
		"outcome="+escapeExt(rec.Status),
	)
	return head + "|" + strings.Join(ext, " ") + "\n"
}

func escapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

func escapeExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
