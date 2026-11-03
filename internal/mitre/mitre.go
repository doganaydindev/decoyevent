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
	case "T1046", "T1071.001":
		return 5
	case "T1110", "T1021.001", "T1021.004":
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
	case "T1046", "T1071.001":
		return 60
	case "T1110", "T1021.001", "T1021.004":
		return 75
	case "T1078", "T1005":
		return 90
	default:
		return 40
	}
}

var table = map[string]string{
	"tcp/scan":     "T1046",
	"ssh/login":    "T1110",
	"ftp/login":    "T1110",
	"mysql/login":  "T1110",
	"rdp/login":    "T1021.001",
	"ssh/session":  "T1021.004",
	"http/request": "T1071.001",
	"http/login":   "T1078",
	"token/use":    "T1078",
	"token/file":   "T1005",
}
