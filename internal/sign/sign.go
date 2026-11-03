// Package sign computes and checks HMAC-SHA256 webhook signatures.
package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Header is the HTTP header that carries the signature.
const Header = "X-Decoyevent-Signature"

// Sign returns the hex-encoded HMAC-SHA256 of body under secret.
func Sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify reports whether sig matches the HMAC of body. sig may be hex or the header value.
func Verify(secret, body []byte, sig string) bool {
	sig = strings.TrimPrefix(strings.TrimSpace(sig), "sha256=")
	got, err := hex.DecodeString(sig)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}
