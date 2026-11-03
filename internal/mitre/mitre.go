// Package mitre is the fixed ATT&CK label table used by decoyevent.
package mitre

// Version is the ATT&CK release this table was written against.
const Version = "15"

// Lookup returns the technique for a protocol and action pair.
func Lookup(protocol, action string) (string, bool) {
	id, ok := table[protocol+"/"+action]
	return id, ok
}

// Severity is the CEF severity for a technique, from 0 to 10.
func Severity(technique string) int {
	switch technique {
	case "T1046", "T1071.001", "T1071.002", "T1071.003", "T1071.004":
		return 5
	case "T1110", "T1021.001", "T1021.002", "T1021.004", "T1021.005", "T1021.006":
		return 8
	case "T1078", "T1005":
		return 9
	default:
		return 3
	}
}

// Confidence is the STIX confidence for a technique, from 0 to 100.
func Confidence(technique string) int {
	switch technique {
	case "T1046", "T1071.001", "T1071.002", "T1071.003", "T1071.004":
		return 60
	case "T1110", "T1021.001", "T1021.002", "T1021.004", "T1021.005", "T1021.006":
		return 75
	case "T1078", "T1005":
		return 90
	default:
		return 40
	}
}

var table = map[string]string{
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
