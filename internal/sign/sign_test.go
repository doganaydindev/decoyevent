package sign

import "testing"

func TestSignVector(t *testing.T) {
	body := []byte(`{"id":"lab-ssh-1","time":"2026-11-02T16:00:00Z","src_ip":"203.0.113.10","dst_port":22,"protocol":"ssh","action":"login"}`)
	const want = "a2abe963152952a171b5acd0c8bbdadc18711484b10ef534ce97b467c4330b1b"
	if got := Sign([]byte("lab-secret"), body); got != want {
		t.Fatalf("got %s", got)
	}
	if !Verify([]byte("lab-secret"), body, want) {
		t.Fatal("verify rejected the vector")
	}
	if !Verify([]byte("lab-secret"), body, "sha256="+want) {
		t.Fatal("verify rejected the header form")
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	body := []byte(`{"id":"lab-ssh-1","time":"2026-11-02T16:00:00Z","src_ip":"203.0.113.10","dst_port":22,"protocol":"ssh","action":"login"}`)
	sig := Sign([]byte("lab-secret"), body)
	body[0] = 'x'
	if Verify([]byte("lab-secret"), body, sig) {
		t.Fatal("tampered body was accepted")
	}
	if Verify([]byte("lab-secret"), body, "zzzz") {
		t.Fatal("non-hex signature was accepted")
	}
}
