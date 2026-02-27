package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/caddyserver/certmagic"
)

// setupTLS configures TLS for the server.
//
// CertMagic with on-demand TLS is always enabled. Certificates are obtained
// automatically via Let's Encrypt when new hostnames arrive via SNI.
// Known hostnames from config are pre-provisioned at startup.
// A self-signed certificate is used as a fallback if ACME fails.
//
// ACME email is optional — Let's Encrypt works without one, though
// it's recommended for expiration notices.
//
// Returns nil if no hostnames are configured and no ACME email is set
// (dev/local mode — plain HTTP only on :8080).
func (s *Server) setupTLS() (*tls.Config, error) {
	hosts := s.cfg.AllHostnames()
	hasACME := s.cfg.TLS.ACMEEmail != ""

	// Nothing configured → HTTP only (dev mode)
	if !hasACME && len(hosts) == 0 {
		slog.Info("no hostnames or ACME configured, TLS disabled (HTTP only on :8080)")
		return nil, nil
	}

	// Configure CertMagic
	if hasACME {
		certmagic.DefaultACME.Email = s.cfg.TLS.ACMEEmail
	}
	certmagic.DefaultACME.Agreed = true

	if s.cfg.TLS.Staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		slog.Info("using Let's Encrypt staging CA")
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: s.cfg.TLS.CertDir}

	// Enable on-demand TLS — certificates obtained during TLS handshake
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: s.onDemandDecision,
	}

	magic := certmagic.NewDefault()

	// Pre-provision certificates for known hostnames
	if len(hosts) > 0 {
		if err := magic.ManageSync(context.Background(), hosts); err != nil {
			slog.Warn("ACME pre-provisioning failed, will try on-demand", "error", err)
		} else {
			slog.Info("TLS pre-provisioned via ACME", "hosts", hosts)
		}
	} else {
		slog.Info("TLS configured with on-demand certificates (no hostnames pre-provisioned)")
	}

	// Build TLS config from CertMagic, with self-signed fallback
	tlsConfig := magic.TLSConfig()

	fallbackCert, err := generateSelfSignedCert([]string{"localhost"})
	if err != nil {
		return nil, fmt.Errorf("generating fallback cert: %w", err)
	}

	origGetCert := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := origGetCert(hello)
		if err == nil {
			return cert, nil
		}
		slog.Debug("ACME cert unavailable, using self-signed fallback",
			"hostname", hello.ServerName, "error", err)
		return fallbackCert, nil
	}

	return tlsConfig, nil
}

// onDemandDecision controls which hostnames get on-demand certificates.
// If hostnames are configured, only allow those. If no hostnames are configured
// (discovery mode), allow any hostname — useful for first-time setup where the
// user points a domain at the server before configuring tunnels.
func (s *Server) onDemandDecision(_ context.Context, name string) error {
	configured := s.cfg.AllHostnames()

	// Discovery mode: no hostnames configured, allow any
	if len(configured) == 0 {
		slog.Info("on-demand TLS: issuing certificate for new hostname", "hostname", name)
		return nil
	}

	// Check if hostname is in our config
	for _, h := range configured {
		if h == name {
			return nil
		}
	}

	return fmt.Errorf("hostname %q not configured", name)
}

// generateSelfSignedCert creates a self-signed ECDSA certificate.
func generateSelfSignedCert(hosts []string) (*tls.Certificate, error) {
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
		DNSNames:     hosts,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
