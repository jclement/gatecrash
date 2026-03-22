package token

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateSecret(t *testing.T) {
	plain1, hash1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if plain1 == "" {
		t.Fatal("plaintext should not be empty")
	}
	if hash1 == "" {
		t.Fatal("hash should not be empty")
	}

	// Each call should produce a unique secret
	plain2, hash2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if plain1 == plain2 {
		t.Fatal("secrets should be unique")
	}
	if hash1 == hash2 {
		t.Fatal("hashes should be unique")
	}
}

func TestHashSecret(t *testing.T) {
	hash, err := HashSecret("my-test-secret")
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	// bcrypt hashes start with $2a$ or $2b$
	if hash[0] != '$' {
		t.Fatalf("hash should look like bcrypt: %s", hash)
	}
}

func TestValidate(t *testing.T) {
	plain, hash, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	lookup := func(id string) string {
		if id == "web-app" {
			return hash
		}
		return ""
	}

	tok := FormatToken("web-app", plain)

	id, valid := Validate(tok, lookup)
	if !valid {
		t.Fatal("token should be valid")
	}
	if id != "web-app" {
		t.Fatalf("got tunnel ID %q, want %q", id, "web-app")
	}
}

func TestValidateInvalid(t *testing.T) {
	_, hash, _ := GenerateSecret()
	lookup := func(id string) string {
		if id == "web-app" {
			return hash
		}
		return ""
	}

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no-colon", "just-a-string"},
		{"wrong-secret", "web-app:wrongsecret"},
		{"unknown-tunnel", "nonexistent:somesecret"},
		{"empty-id", ":secret"},
		{"empty-secret", "tunnel:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid := Validate(tt.token, lookup)
			if valid {
				t.Fatalf("token %q should be invalid", tt.token)
			}
		})
	}
}

func TestFormatToken(t *testing.T) {
	tok := FormatToken("my-tunnel", "my-secret")
	if tok != "my-tunnel:my-secret" {
		t.Fatalf("unexpected token format: %s", tok)
	}
}

func TestValidate_MultipleColons(t *testing.T) {
	// Token "id:secret:extra" — SplitN with n=2 means the secret portion is "secret:extra".
	// We hash "secret:extra" and expect Validate to match it.
	secret := "secret:extra"
	hash, err := HashSecret(secret)
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}

	lookup := func(id string) string {
		if id == "id" {
			return hash
		}
		return ""
	}

	tok := "id:secret:extra"
	tunnelID, valid := Validate(tok, lookup)
	if !valid {
		t.Fatal("token with multiple colons should be valid (everything after first colon is the secret)")
	}
	if tunnelID != "id" {
		t.Fatalf("got tunnel ID %q, want %q", tunnelID, "id")
	}
}

func TestValidate_WhitespaceToken(t *testing.T) {
	// Token with leading/trailing whitespace: " id:secret "
	// Validate does NOT trim whitespace, so the id becomes " id" and secret becomes "secret ".
	secret := "secret "
	hash, err := HashSecret(secret)
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}

	lookup := func(id string) string {
		if id == " id" {
			return hash
		}
		return ""
	}

	tok := " id:secret "
	tunnelID, valid := Validate(tok, lookup)
	if !valid {
		t.Fatal("whitespace token should be valid when lookup matches the untrimmed id")
	}
	if tunnelID != " id" {
		t.Fatalf("got tunnel ID %q, want %q", tunnelID, " id")
	}
}

func TestHashSecret_Empty(t *testing.T) {
	hash, err := HashSecret("")
	if err != nil {
		t.Fatalf("HashSecret with empty string: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	// Verify the result is valid bcrypt by checking it with CompareHashAndPassword
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("")); err != nil {
		t.Fatalf("bcrypt hash of empty string should be valid: %v", err)
	}
}

func TestHashSecret_LongInput(t *testing.T) {
	// Go's bcrypt returns an error for inputs exceeding 72 bytes.
	longInput := strings.Repeat("a", 300)
	_, err := HashSecret(longInput)
	if err == nil {
		t.Fatal("HashSecret with 300+ char input should return an error (bcrypt rejects inputs over 72 bytes)")
	}

	// A 72-byte input should still succeed (at the boundary).
	boundaryInput := strings.Repeat("b", 72)
	hash, err := HashSecret(boundaryInput)
	if err != nil {
		t.Fatalf("HashSecret with 72-byte input should not error: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(boundaryInput)); err != nil {
		t.Fatalf("hash should match the 72-byte input: %v", err)
	}
}

func TestFormatToken_Empty(t *testing.T) {
	tok := FormatToken("", "")
	if tok != ":" {
		t.Fatalf("FormatToken(\"\", \"\") = %q, want %q", tok, ":")
	}
}

func TestFormatToken_WithColons(t *testing.T) {
	tok := FormatToken("my:id", "my:secret")
	expected := "my:id:my:secret"
	if tok != expected {
		t.Fatalf("FormatToken(\"my:id\", \"my:secret\") = %q, want %q", tok, expected)
	}
	// Verify the result contains the colons from both id and secret
	if !strings.Contains(tok, "my:id") {
		t.Fatal("formatted token should contain the id with colon")
	}
	if !strings.Contains(tok, "my:secret") {
		t.Fatal("formatted token should contain the secret with colon")
	}
}

func TestGenerateSecret_HashMatchesPlaintext(t *testing.T) {
	plaintext, hash, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	// Verify that bcrypt.CompareHashAndPassword succeeds with the returned plaintext and hash
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)); err != nil {
		t.Fatalf("hash from GenerateSecret should match its plaintext: %v", err)
	}
}
