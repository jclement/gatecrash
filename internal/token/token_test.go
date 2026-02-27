package token

import (
	"testing"
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
