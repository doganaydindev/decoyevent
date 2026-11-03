// Package event parses a decoy interaction and encodes the webhook body.
package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/doganaydin/decoyevent/internal/mitre"
)

const maxBody = 1 << 20

// ErrSecret is returned when the input contains a credential field.
var ErrSecret = errors.New("secret field")

// ErrTooLarge is returned when the body exceeds 1 MiB.
var ErrTooLarge = errors.New("event too large")

// ErrInvalid is returned when the event is not usable.
var ErrInvalid = errors.New("invalid event")

// ErrUnknownField is returned when the object contains a field outside the schema.
var ErrUnknownField = errors.New("unknown field")

// Event is one decoy interaction after validation and labeling.
type Event struct {
	ID            string
	Time          time.Time
	SrcIP         string
	DstIP         string
	DstPort       int
	Protocol      string
	Action        string
	Sensor        string
	Decoy         string
	Message       string
	AttackVersion string
	Technique     string
	Severity      int
}

// Record is an event plus the dedup outcome carried into every output format.
type Record struct {
	Event  Event
	Status string
	Count  uint64
}

// Parse validates raw JSON and returns an unlabeled event.
func Parse(raw []byte) (Event, error) {
	buf, err := limited(raw)
	if err != nil {
		return Event{}, err
	}
	if err := rejectShape(buf); err != nil {
		return Event{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	var in input
	if err := dec.Decode(&in); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Event{}, fmt.Errorf("%w: %s", ErrUnknownField, unknownField(err))
		}
		return Event{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return Event{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return in.event()
}

// Label sets the ATT&CK version, technique, and severity on e.
func Label(e *Event) {
	e.AttackVersion = mitre.Version
	if id, ok := mitre.Lookup(e.Protocol, e.Action); ok {
		e.Technique = id
	} else {
		e.Technique = ""
	}
	e.Severity = mitre.Severity(e.Technique)
}

// Prepare parses raw and labels the event.
func Prepare(raw []byte) (Event, error) {
	e, err := Parse(raw)
	if err != nil {
		return Event{}, err
	}
	Label(&e)
	return e, nil
}

// MarshalWebhook encodes rec as the canonical JSON body. The result has no trailing newline.
func MarshalWebhook(rec Record) ([]byte, error) {
	p := payload{
		ID:            rec.Event.ID,
		Time:          rec.Event.Time.UTC().Format(time.RFC3339),
		SrcIP:         rec.Event.SrcIP,
		DstIP:         rec.Event.DstIP,
		DstPort:       rec.Event.DstPort,
		Protocol:      rec.Event.Protocol,
		Action:        rec.Event.Action,
		Sensor:        rec.Event.Sensor,
		Decoy:         rec.Event.Decoy,
		Message:       rec.Event.Message,
		AttackVersion: rec.Event.AttackVersion,
		Technique:     rec.Event.Technique,
		Severity:      rec.Event.Severity,
		Count:         rec.Count,
		Status:        rec.Status,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

type payload struct {
	ID            string `json:"id"`
	Time          string `json:"time"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip,omitempty"`
	DstPort       int    `json:"dst_port"`
	Protocol      string `json:"protocol"`
	Action        string `json:"action"`
	Sensor        string `json:"sensor,omitempty"`
	Decoy         string `json:"decoy,omitempty"`
	Message       string `json:"message,omitempty"`
	AttackVersion string `json:"attack_version"`
	Technique     string `json:"technique,omitempty"`
	Severity      int    `json:"severity"`
	Count         uint64 `json:"count"`
	Status        string `json:"status"`
}

type input struct {
	ID       string  `json:"id"`
	Time     string  `json:"time"`
	SrcIP    string  `json:"src_ip"`
	DstIP    *string `json:"dst_ip"`
	DstPort  *port   `json:"dst_port"`
	Protocol string  `json:"protocol"`
	Action   string  `json:"action"`
	Sensor   *string `json:"sensor"`
	Decoy    *string `json:"decoy"`
	Message  *string `json:"message"`
}

func (in input) event() (Event, error) {
	if err := token(in.ID, 1, 128, idPattern, "id"); err != nil {
		return Event{}, err
	}
	ts, err := time.Parse(time.RFC3339, in.Time)
	if err != nil {
		return Event{}, fmt.Errorf("%w: time", ErrInvalid)
	}
	src, err := ip(in.SrcIP, "src_ip")
	if err != nil {
		return Event{}, err
	}
	if in.DstPort == nil {
		return Event{}, fmt.Errorf("%w: dst_port", ErrInvalid)
	}
	if err := token(in.Protocol, 1, 32, namePattern, "protocol"); err != nil {
		return Event{}, err
	}
	if err := token(in.Action, 1, 32, namePattern, "action"); err != nil {
		return Event{}, err
	}
	e := Event{
		ID:       in.ID,
		Time:     ts.UTC(),
		SrcIP:    src,
		DstPort:  int(*in.DstPort),
		Protocol: in.Protocol,
		Action:   in.Action,
	}
	if in.DstIP != nil {
		dst, err := ip(*in.DstIP, "dst_ip")
		if err != nil {
			return Event{}, err
		}
		e.DstIP = dst
	}
	if in.Sensor != nil {
		if err := token(*in.Sensor, 1, 64, idPattern, "sensor"); err != nil {
			return Event{}, err
		}
		e.Sensor = *in.Sensor
	}
	if in.Decoy != nil {
		if err := token(*in.Decoy, 1, 64, idPattern, "decoy"); err != nil {
			return Event{}, err
		}
		e.Decoy = *in.Decoy
	}
	if in.Message != nil {
		if utf8.RuneCountInString(*in.Message) > 256 {
			return Event{}, fmt.Errorf("%w: message", ErrInvalid)
		}
		for _, r := range *in.Message {
			if unicode.IsControl(r) {
				return Event{}, fmt.Errorf("%w: message", ErrInvalid)
			}
		}
		e.Message = *in.Message
	}
	return e, nil
}

type port int

func (p *port) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] == '"' || bytes.Equal(b, []byte("null")) {
		return fmt.Errorf("%w: dst_port", ErrInvalid)
	}
	if bytes.ContainsAny(b, ".eE+") {
		return fmt.Errorf("%w: dst_port", ErrInvalid)
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: dst_port", ErrInvalid)
	}
	*p = port(n)
	return nil
}

func limited(raw []byte) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(bytes.NewReader(raw), maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxBody {
		return nil, ErrTooLarge
	}
	return buf, nil
}

func rejectShape(buf []byte) error {
	var generic any
	if err := json.Unmarshal(buf, &generic); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: object required", ErrInvalid)
	}
	if err := walkSecrets(generic); err != nil {
		return err
	}
	for k, v := range obj {
		if !allowed[k] {
			return fmt.Errorf("%w: %s", ErrUnknownField, k)
		}
		switch v.(type) {
		case map[string]any, []any:
			return fmt.Errorf("%w: %s", ErrInvalid, k)
		}
	}
	return nil
}

func walkSecrets(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if forbidden[strings.ToLower(k)] {
				return fmt.Errorf("%w: %s", ErrSecret, strings.ToLower(k))
			}
			if err := walkSecrets(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := walkSecrets(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func token(v string, min, max int, re *regexp.Regexp, field string) error {
	n := utf8.RuneCountInString(v)
	if n < min || n > max || !re.MatchString(v) {
		return fmt.Errorf("%w: %s", ErrInvalid, field)
	}
	return nil
}

func ip(v, field string) (string, error) {
	if strings.Contains(v, "%") || net.ParseIP(v) == nil {
		return "", fmt.Errorf("%w: %s", ErrInvalid, field)
	}
	return v, nil
}

func unknownField(err error) string {
	const mark = `unknown field "`
	s := err.Error()
	i := strings.Index(s, mark)
	if i < 0 {
		return s
	}
	s = s[i+len(mark):]
	j := strings.IndexByte(s, '"')
	if j < 0 {
		return s
	}
	return s[:j]
}

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	namePattern = regexp.MustCompile(`^[a-z0-9._-]+$`)
	allowed     = map[string]bool{
		"id": true, "time": true, "src_ip": true, "dst_ip": true, "dst_port": true,
		"protocol": true, "action": true, "sensor": true, "decoy": true, "message": true,
	}
	forbidden = map[string]bool{
		"password": true, "pass": true, "passwd": true, "secret": true,
		"token": true, "authorization": true, "cookie": true, "set-cookie": true,
	}
)
