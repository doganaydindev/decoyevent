// Command decoyevent turns one decoy interaction into a webhook body, a CEF line, or a STIX indicator.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/doganaydin/decoyevent/internal/cef"
	"github.com/doganaydin/decoyevent/internal/dedup"
	"github.com/doganaydin/decoyevent/internal/event"
	"github.com/doganaydin/decoyevent/internal/sign"
	"github.com/doganaydin/decoyevent/internal/sink"
	"github.com/doganaydin/decoyevent/internal/stix"
)

// main reads one JSON event from stdin and writes the selected format.
func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv("DECOYEVENT_SECRET")))
}

type options struct {
	cmd    string
	state  string
	post   string
	syslog string
	ndjson bool
	help   bool
}

func run(args []string, in io.Reader, out, errw io.Writer, secret string) int {
	opt, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(errw, err)
		fmt.Fprint(errw, usage)
		return 2
	}
	if opt.help || opt.cmd == "help" {
		fmt.Fprint(errw, usage)
		return 0
	}
	needsSecret := opt.cmd == "webhook" || opt.post != ""
	if needsSecret && secret == "" {
		fmt.Fprintln(errw, "missing DECOYEVENT_SECRET")
		return 2
	}
	if opt.ndjson {
		return runNDJSON(opt, in, out, errw, secret)
	}
	raw, err := io.ReadAll(io.LimitReader(in, 1<<20+1))
	if err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	ev, err := event.Prepare(raw)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	emit := func(res dedup.Result) error {
		rec := event.Record{Event: ev, Status: res.Status, Count: res.Count}
		return deliver(opt, rec, secret, out, errw)
	}
	if opt.state == "" {
		fmt.Fprintln(errw, "dedup disabled")
		if err := emit(dedup.Result{Status: dedup.StatusAccepted, Count: 1}); err != nil {
			fmt.Fprintln(errw, err)
			return 2
		}
		return 0
	}
	if _, err := dedup.Apply(opt.state, ev.ID, 24*time.Hour, nil, emit); err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	return 0
}

func runNDJSON(opt options, in io.Reader, out, errw io.Writer, secret string) int {
	var db *dedup.DB
	if opt.state == "" {
		fmt.Fprintln(errw, "dedup disabled")
	} else {
		opened, err := dedup.Open(opt.state, 24*time.Hour, nil)
		if err != nil {
			fmt.Fprintln(errw, err)
			return 2
		}
		defer opened.Close()
		db = opened
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20+1)
	failed := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if err := one(opt, db, []byte(line), secret, out, errw); err != nil {
			fmt.Fprintf(errw, "line %d: %v\n", lineNo, err)
			failed = true
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	if failed {
		return 2
	}
	return 0
}

func one(opt options, db *dedup.DB, raw []byte, secret string, out, errw io.Writer) error {
	ev, err := event.Prepare(raw)
	if err != nil {
		return err
	}
	emit := func(res dedup.Result) error {
		rec := event.Record{Event: ev, Status: res.Status, Count: res.Count}
		return deliver(opt, rec, secret, out, errw)
	}
	if db == nil {
		return emit(dedup.Result{Status: dedup.StatusAccepted, Count: 1})
	}
	_, err = db.Apply(ev.ID, emit)
	return err
}

func deliver(opt options, rec event.Record, secret string, out, errw io.Writer) error {
	body, err := format(opt.cmd, rec)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if opt.syslog != "" {
		if err := sink.Syslog(ctx, opt.syslog, string(body), rec.Event.Severity, time.Now()); err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
	}
	var sig string
	if secret != "" {
		sig = sign.Sign([]byte(secret), body)
	}
	if opt.post != "" {
		if err := sink.Post(ctx, opt.post, "application/json", body, sig); err != nil {
			return err
		}
	}
	written := body
	if opt.ndjson && (len(written) == 0 || written[len(written)-1] != '\n') {
		written = append(append([]byte{}, body...), '\n')
	}
	if _, err := out.Write(written); err != nil {
		return err
	}
	if sig != "" && (opt.cmd == "webhook" || opt.post != "") {
		fmt.Fprintf(errw, "%s: sha256=%s\n", sign.Header, sig)
	}
	return nil
}

func format(cmd string, rec event.Record) ([]byte, error) {
	switch cmd {
	case "webhook":
		return event.MarshalWebhook(rec)
	case "cef":
		return []byte(cef.Format(rec)), nil
	case "stix":
		return stix.Format(rec)
	default:
		return nil, fmt.Errorf("unknown command %q", cmd)
	}
}

func parseArgs(args []string) (options, error) {
	if len(args) == 0 {
		return options{}, fmt.Errorf("missing command")
	}
	var opt options
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			opt.help = true
		case a == "--ndjson":
			opt.ndjson = true
		case a == "--state" || a == "--post" || a == "--syslog":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s needs a value", a)
			}
			i++
			switch a {
			case "--state":
				opt.state = args[i]
			case "--post":
				opt.post = args[i]
			case "--syslog":
				opt.syslog = args[i]
			}
		case strings.HasPrefix(a, "--state="), strings.HasPrefix(a, "--post="), strings.HasPrefix(a, "--syslog="):
			key, val, _ := strings.Cut(a, "=")
			if val == "" {
				return options{}, fmt.Errorf("%s needs a value", key)
			}
			switch key {
			case "--state":
				opt.state = val
			case "--post":
				opt.post = val
			case "--syslog":
				opt.syslog = val
			}
		case strings.HasPrefix(a, "-"):
			return options{}, fmt.Errorf("unknown flag %s", a)
		default:
			if opt.cmd != "" {
				return options{}, fmt.Errorf("unexpected argument %s", a)
			}
			opt.cmd = a
		}
	}
	if opt.help && opt.cmd == "" {
		opt.cmd = "help"
		return opt, nil
	}
	switch opt.cmd {
	case "webhook", "cef", "stix":
	case "":
		return options{}, fmt.Errorf("missing command")
	default:
		return options{}, fmt.Errorf("unknown command %q", opt.cmd)
	}
	if opt.syslog != "" && opt.cmd != "cef" {
		return options{}, fmt.Errorf("--syslog is only valid with cef")
	}
	if opt.post != "" && opt.cmd == "cef" {
		return options{}, fmt.Errorf("cef is sent with --syslog, not --post")
	}
	if opt.syslog != "" && opt.post != "" {
		return options{}, fmt.Errorf("choose either --syslog or --post")
	}
	return opt, nil
}

const usage = `decoyevent formats decoy interactions from stdin.

Usage:
  decoyevent webhook [--state db] [--post URL] [--ndjson]
  decoyevent cef [--state db] [--syslog udp://host:514] [--ndjson]
  decoyevent stix [--state db] [--post URL] [--ndjson]

webhook writes a signed JSON body. cef writes one CEF line. stix writes one STIX 2.1 indicator.
The body is always written to stdout. --post and --syslog also deliver it.
Set DECOYEVENT_SECRET to the HMAC key. The secret is not accepted as a flag.
--post requires the key and sends X-Decoyevent-Signature. Syslog has no signature.
--state is a SQLite database. The same id inside 24 hours increments a counter.
A failed delivery does not save that counter. Without --state, stderr says dedup is off.
Without --ndjson, stdin is one JSON object. With --ndjson, each line is one object.
A bad line is reported and the next line is still processed.
`
