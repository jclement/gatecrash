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
	"os"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// setupTLS configures TLS for the server.
//
// In production, CertMagic with on-demand TLS is always enabled — even with
// zero configuration. When a new hostname arrives via SNI, a Let's Encrypt
// certificate is obtained automatically. Known hostnames from config are
// pre-provisioned at startup. A self-signed certificate is the fallback if
// ACME can't reach the domain.
//
// In dev mode with no hostnames configured, a self-signed certificate is used.
func (s *Server) setupTLS() (*tls.Config, error) {
	hosts := s.cfg.AllHostnames()

	// Dev mode with nothing configured → self-signed cert for localhost
	if s.version == "dev" && len(hosts) == 0 {
		slog.Info("dev mode, no hostnames configured, using self-signed certificate")
		cert, err := generateSelfSignedCert([]string{"localhost"})
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	}

	// Ensure cert storage directory exists
	if err := os.MkdirAll(s.cfg.TLS.CertDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating cert directory %s: %w", s.cfg.TLS.CertDir, err)
	}

	// Wire CertMagic logging through slog
	cmLogger := newCertMagicLogger()

	// Configure CertMagic
	if s.cfg.TLS.ACMEEmail != "" {
		certmagic.DefaultACME.Email = s.cfg.TLS.ACMEEmail
		slog.Info("ACME email configured", "email", s.cfg.TLS.ACMEEmail)
	}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Logger = cmLogger.Named("acme")

	ca := certmagic.LetsEncryptProductionCA
	if s.cfg.TLS.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}
	certmagic.DefaultACME.CA = ca
	slog.Info("TLS ACME configuration",
		"ca", ca,
		"staging", s.cfg.TLS.Staging,
		"cert_dir", s.cfg.TLS.CertDir,
	)

	certmagic.Default.Storage = &certmagic.FileStorage{Path: s.cfg.TLS.CertDir}
	certmagic.Default.Logger = cmLogger

	// Enable on-demand TLS — certificates obtained during TLS handshake
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: s.onDemandDecision,
	}

	magic := certmagic.NewDefault()

	// Pre-provision certificates for known hostnames
	if len(hosts) > 0 {
		slog.Info("pre-provisioning TLS certificates", "hosts", hosts)
		if err := magic.ManageSync(context.Background(), hosts); err != nil {
			slog.Warn("ACME pre-provisioning failed, will try on-demand",
				"error", err,
				"hosts", hosts,
			)
		} else {
			slog.Info("TLS certificates pre-provisioned via ACME", "hosts", hosts)
		}
	} else {
		slog.Info("TLS configured with on-demand certificates (no hostnames pre-provisioned)")
	}

	// Build TLS config from CertMagic, with self-signed fallback
	tlsConfig := magic.TLSConfig()

	// CertMagic only sets the ACME TLS-ALPN-01 challenge protocol in NextProtos.
	// Browsers require h2 and http/1.1 for normal HTTPS to work.
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2", "http/1.1")

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
		slog.Warn("ACME cert unavailable, using self-signed fallback",
			"hostname", hello.ServerName, "error", err)
		return fallbackCert, nil
	}

	return tlsConfig, nil
}

// onDemandDecision controls which hostnames get on-demand certificates.
// Only configured hostnames are allowed — prevents abuse from arbitrary domains.
func (s *Server) onDemandDecision(_ context.Context, name string) error {
	configured := s.cfg.AllHostnames()

	for _, h := range configured {
		if h == name {
			slog.Info("on-demand TLS: issuing certificate", "hostname", name)
			return nil
		}
	}

	slog.Warn("on-demand TLS: rejected unconfigured hostname", "hostname", name)
	return fmt.Errorf("hostname %q not configured", name)
}

// newCertMagicLogger creates a *zap.Logger that forwards to the global slog logger.
func newCertMagicLogger() *zap.Logger {
	return zap.New(&slogZapCore{
		LevelEnabler: zap.NewAtomicLevelAt(zap.DebugLevel),
	})
}

// slogZapCore is a zapcore.Core that forwards log entries to slog.
type slogZapCore struct {
	zapcore.LevelEnabler
	fields []zapcore.Field
}

func (c *slogZapCore) With(fields []zapcore.Field) zapcore.Core {
	clone := &slogZapCore{
		LevelEnabler: c.LevelEnabler,
		fields:       make([]zapcore.Field, 0, len(c.fields)+len(fields)),
	}
	clone.fields = append(clone.fields, c.fields...)
	clone.fields = append(clone.fields, fields...)
	return clone
}

func (c *slogZapCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *slogZapCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	// Map zap level to slog level
	var level slog.Level
	switch {
	case entry.Level >= zapcore.ErrorLevel:
		level = slog.LevelError
	case entry.Level >= zapcore.WarnLevel:
		level = slog.LevelWarn
	case entry.Level >= zapcore.InfoLevel:
		level = slog.LevelInfo
	default:
		level = slog.LevelDebug
	}

	// Convert zap fields to slog attrs
	allFields := append(c.fields, fields...)
	attrs := make([]slog.Attr, 0, len(allFields)+1)
	if entry.LoggerName != "" {
		attrs = append(attrs, slog.String("component", entry.LoggerName))
	}
	for _, f := range allFields {
		attrs = append(attrs, zapFieldToSlogAttr(f))
	}

	args := make([]any, len(attrs))
	for i, a := range attrs {
		args[i] = a
	}
	slog.Log(context.Background(), level, entry.Message, args...)
	return nil
}

func (c *slogZapCore) Sync() error { return nil }

// zapFieldToSlogAttr converts a zap field to an slog attribute.
func zapFieldToSlogAttr(f zapcore.Field) slog.Attr {
	switch f.Type {
	case zapcore.StringType:
		return slog.String(f.Key, f.String)
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		return slog.Int64(f.Key, f.Integer)
	case zapcore.BoolType:
		return slog.Bool(f.Key, f.Integer == 1)
	case zapcore.Float64Type:
		return slog.Float64(f.Key, float64(f.Integer))
	case zapcore.DurationType:
		return slog.Duration(f.Key, time.Duration(f.Integer))
	case zapcore.TimeType:
		if f.Interface != nil {
			return slog.Time(f.Key, time.Unix(0, f.Integer).In(f.Interface.(*time.Location)))
		}
		return slog.Time(f.Key, time.Unix(0, f.Integer))
	case zapcore.ErrorType:
		if f.Interface != nil {
			return slog.String(f.Key, f.Interface.(error).Error())
		}
		return slog.String(f.Key, "<nil>")
	default:
		if f.Interface != nil {
			return slog.Any(f.Key, f.Interface)
		}
		return slog.Any(f.Key, f.String)
	}
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
