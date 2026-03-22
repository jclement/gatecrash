package server

import (
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert([]string{"localhost", "example.com"})
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in chain")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestGenerateSelfSignedCertSingleHost(t *testing.T) {
	cert, err := generateSelfSignedCert([]string{"myhost.local"})
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}
