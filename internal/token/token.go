package token

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// GenerateSecret creates a new random secret and its bcrypt hash.
// Returns (plaintext, hash, error). The plaintext should be shown to the user once.
func GenerateSecret() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)

	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return plaintext, string(hash), nil
}

// HashSecret creates a bcrypt hash from a plaintext secret.
func HashSecret(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Validate checks a token (format: tunnel_id:secret) against stored hashes.
// lookupHash should return the bcrypt hash for the given tunnel ID, or "" if not found.
func Validate(tok string, lookupHash func(id string) string) (tunnelID string, valid bool) {
	parts := strings.SplitN(tok, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}

	id, secret := parts[0], parts[1]
	hash := lookupHash(id)
	if hash == "" {
		return "", false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		return "", false
	}

	return id, true
}

// FormatToken combines a tunnel ID and plaintext secret into a token string.
func FormatToken(tunnelID, secret string) string {
	return tunnelID + ":" + secret
}
