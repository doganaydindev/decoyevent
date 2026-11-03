package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/doganaydin/decoyevent/internal/sign"
)

func TestCLIWebhookSecret(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/login.json")
	if err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	code := run([]string{"webhook"}, bytes.NewReader(raw), &out, &errw, "")
	if code != 2 {
		t.Fatalf("exit %d stderr %s", code, errw.String())
	}
	if !strings.Contains(errw.String(), "missing DECOYEVENT_SECRET") {
		t.Fatal(errw.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestCLIWebhookSignsStdout(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/login.json")
	if err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	code := run([]string{"webhook"}, bytes.NewReader(raw), &out, &errw, "lab-secret")
	if code != 0 {
		t.Fatalf("exit %d stderr %s", code, errw.String())
	}
	if !sign.Verify([]byte("lab-secret"), out.Bytes(), signatureLine(errw.String())) {
		t.Fatalf("stdout did not verify\n%s\n%s", out.String(), errw.String())
	}
	want, err := os.ReadFile("../../testdata/login.webhook.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("got %s\nwant %s", out.Bytes(), want)
	}
}

func TestREADMEMatchesCEFGolden(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("../../testdata/login.cef")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "```text\nCEF:0|"
	i := strings.Index(string(readme), marker)
	if i < 0 {
		t.Fatal("README has no CEF fence")
	}
	rest := string(readme)[i+len("```text\n"):]
	j := strings.Index(rest, "```")
	if j < 0 {
		t.Fatal("CEF fence is not closed")
	}
	if rest[:j] != string(golden) {
		t.Fatalf("fence %q\ngolden %q", rest[:j], golden)
	}
}

func TestCLIStateFile(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/login.json")
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/state.db"
	var first, second bytes.Buffer
	if code := run([]string{"cef", "--state", path}, bytes.NewReader(raw), &first, ioDiscard{}, ""); code != 0 {
		t.Fatal(code)
	}
	if code := run([]string{"cef", "--state", path}, bytes.NewReader(raw), &second, ioDiscard{}, ""); code != 0 {
		t.Fatal(code)
	}
	if !bytes.Contains(first.Bytes(), []byte("cnt=1 outcome=accepted")) {
		t.Fatal(first.String())
	}
	if !bytes.Contains(second.Bytes(), []byte("cnt=2 outcome=duplicate")) {
		t.Fatal(second.String())
	}
}

func TestCLIPostsWebhook(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/login.json")
	if err != nil {
		t.Fatal(err)
	}
	var gotBody, gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotSig = r.Header.Get(sign.Header)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	var out, errw bytes.Buffer
	code := run([]string{"webhook", "--post", srv.URL}, bytes.NewReader(raw), &out, &errw, "lab-secret")
	if code != 0 {
		t.Fatalf("exit %d stderr %s", code, errw.String())
	}
	if gotBody != out.String() {
		t.Fatalf("posted %s\nstdout %s", gotBody, out.String())
	}
	if !sign.Verify([]byte("lab-secret"), out.Bytes(), gotSig) {
		t.Fatalf("receiver signature %s", gotSig)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func signatureLine(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, sign.Header+": ") {
			return strings.TrimPrefix(line, sign.Header+": ")
		}
	}
	return ""
}
