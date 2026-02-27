package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"log/slog"
	"time"

	"github.com/caddyserver/certmagic"
)

// setupTLS configures CertMagic for automatic HTTPS.
// If ACME fails, falls back to a self-signed certificate.
func (s *Server) setupTLS() (*tls.Config, error) {
	hosts := s.cfg.AllHostnames()

	if len(hosts) == 0 {
		slog.Info("no hostnames configured, TLS disabled")
		return nil, nil
	}

	if s.cfg.TLS.ACMEEmail == "" {
		slog.Warn("no ACME email configured, using self-signed certificate")
		return selfSignedTLSConfig(hosts)
	}

	// Configure CertMagic
	certmagic.DefaultACME.Email = s.cfg.TLS.ACMEEmail
	certmagic.DefaultACME.Agreed = true

	if s.cfg.TLS.Staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		slog.Info("using Let's Encrypt staging CA")
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: s.cfg.TLS.CertDir}

	magic := certmagic.NewDefault()

	if err := magic.ManageSync(context.Background(), hosts); err != nil {
		slog.Warn("ACME failed, falling back to self-signed certificate", "error", err)
		return selfSignedTLSConfig(hosts)
	}

	slog.Info("TLS configured via ACME", "hosts", hosts)
	return magic.TLSConfig(), nil
}

// selfSignedTLSConfig generates a self-signed TLS certificate for the given hosts.
func selfSignedTLSConfig(hosts []string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Gatecrash (self-signed)"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	slog.Info("TLS configured with self-signed certificate", "hosts", hosts)

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}
