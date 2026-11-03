package mitre

import (
	"strings"
	"testing"
)

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

func TestLookupTable(t *testing.T) {
	want := map[string]string{
		"tcp/scan":       "T1046",
		"udp/scan":       "T1046",
		"ssh/login":      "T1110",
		"ftp/login":      "T1110",
		"telnet/login":   "T1110",
		"smtp/login":     "T1110",
		"imap/login":     "T1110",
		"pop3/login":     "T1110",
		"mysql/login":    "T1110",
		"mssql/login":    "T1110",
		"postgres/login": "T1110",
		"mongodb/login":  "T1110",
		"redis/login":    "T1110",
		"ldap/login":     "T1110",
		"smb/login":      "T1110",
		"vnc/login":      "T1110",
		"rdp/login":      "T1021.001",
		"rdp/session":    "T1021.001",
		"smb/session":    "T1021.002",
		"ssh/session":    "T1021.004",
		"vnc/session":    "T1021.005",
		"winrm/session":  "T1021.006",
		"http/request":   "T1071.001",
		"ftp/request":    "T1071.002",
		"smtp/request":   "T1071.003",
		"dns/request":    "T1071.004",
		"http/login":     "T1078",
		"token/use":      "T1078",
		"token/file":     "T1005",
	}
	if len(want) != len(table) {
		t.Fatalf("table has %d rows, test lists %d", len(table), len(want))
	}
	scores := map[string][2]int{
		"T1046":     {5, 60},
		"T1071.001": {5, 60},
		"T1071.002": {5, 60},
		"T1071.003": {5, 60},
		"T1071.004": {5, 60},
		"T1110":     {8, 75},
		"T1021.001": {8, 75},
		"T1021.002": {8, 75},
		"T1021.004": {8, 75},
		"T1021.005": {8, 75},
		"T1021.006": {8, 75},
		"T1078":     {9, 90},
		"T1005":     {9, 90},
	}
	for pair, id := range want {
		proto, action, _ := strings.Cut(pair, "/")
		got, ok := Lookup(proto, action)
		if !ok || got != id {
			t.Fatalf("%s: got %q ok=%v", pair, got, ok)
		}
		if Severity(got) != scores[got][0] || Confidence(got) != scores[got][1] {
			t.Fatalf("%s scores %d %d", got, Severity(got), Confidence(got))
		}
	}
}
