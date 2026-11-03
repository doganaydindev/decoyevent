package mitre

import "testing"

func TestLookupMissesSIPInvite(t *testing.T) {
	if id, ok := Lookup("sip", "invite"); ok || id != "" {
		t.Fatalf("sip/invite labeled %q ok=%v", id, ok)
	}
}

func TestLookupSSHLogin(t *testing.T) {
	id, ok := Lookup("ssh", "login")
	if !ok || id != "T1110" {
		t.Fatalf("got %q %v", id, ok)
	}
	if Severity(id) != 8 || Confidence(id) != 75 {
		t.Fatalf("severity %d confidence %d", Severity(id), Confidence(id))
	}
	if Severity("") != 3 || Confidence("") != 40 {
		t.Fatal("unmapped scores")
	}
}
