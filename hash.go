package auth

import (
	"crypto/sha1"
	"fmt"
)

// Hash is a convenience function that appends the password along with any other passed
// salts to return an SHA1 hash.
func Hash(password string, salts ...string) string {
	h := sha1.New()
	h.Write([]byte(password))
	for _, s := range salts {
		h.Write([]byte(s))
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
