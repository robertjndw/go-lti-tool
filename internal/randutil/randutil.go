// Package randutil provides a shared random-token helper used across the SDK.
package randutil

import (
	"crypto/rand"
	"encoding/base64"
)

// Token returns a URL-safe random string of n bytes encoded as unpadded base64url.
func Token(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
