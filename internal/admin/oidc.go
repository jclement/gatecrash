package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/jclement/gatecrash/internal/config"
)

// OIDCClaims holds extracted claims from an OIDC ID token.
type OIDCClaims struct {
	Name  string
	Email string
	Raw   map[string]interface{}
}

// OIDCState holds pending OIDC auth flow state.
type OIDCState struct {
	nonce        string
	ReturnURL    string // where to redirect after auth
	purpose      string // "admin", "tunnel", "test"
	Hostname     string // for tunnel auth: the tunnel hostname
	pkceVerifier string // PKCE code verifier if enabled
	expires      time.Time
}

// Purpose returns the purpose of this OIDC auth flow.
func (s *OIDCState) Purpose() string { return s.purpose }

// OIDCProvider wraps OAuth2/OIDC operations.
type OIDCProvider struct {
	cfg       *config.OIDCConfig
	oauth2Cfg *oauth2.Config
	verifier  *gooidc.IDTokenVerifier

	mu     sync.Mutex
	states map[string]*OIDCState
}

// NewOIDCProvider creates a new OIDC provider from config.
// callbackURL is the OAuth2 redirect URI (e.g. https://admin.example.com/oidc/callback).
func NewOIDCProvider(cfg *config.OIDCConfig, callbackURL string) (*OIDCProvider, error) {
	ctx := context.Background()

	// Configure OIDC provider using the JWKS endpoint
	providerCfg := gooidc.ProviderConfig{
		IssuerURL:   "", // We don't validate issuer since user provides individual URLs
		AuthURL:     cfg.AuthURL,
		TokenURL:    cfg.TokenURL,
		JWKSURL:     cfg.CertURL,
	}

	keySet := gooidc.NewRemoteKeySet(ctx, cfg.CertURL)
	verifier := gooidc.NewVerifier("", keySet, &gooidc.Config{
		ClientID:          cfg.ClientID,
		SkipIssuerCheck:   true,
	})

	_ = providerCfg // used for documentation of available fields

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
		Scopes:      []string{"openid", "email", "profile"},
		RedirectURL: callbackURL,
	}

	p := &OIDCProvider{
		cfg:       cfg,
		oauth2Cfg: oauth2Cfg,
		verifier:  verifier,
		states:    make(map[string]*OIDCState),
	}

	go p.cleanupLoop()

	return p, nil
}

// AuthURL generates an authorization URL for initiating the OIDC flow.
// Returns the URL and the state token to validate the callback.
func (p *OIDCProvider) AuthURL(purpose, returnURL, hostname string) (authURL, state string, err error) {
	state, err = randomString(32)
	if err != nil {
		return "", "", fmt.Errorf("generating state: %w", err)
	}

	nonce, err := randomString(32)
	if err != nil {
		return "", "", fmt.Errorf("generating nonce: %w", err)
	}

	st := &OIDCState{
		nonce:     nonce,
		ReturnURL: returnURL,
		purpose:   purpose,
		Hostname:  hostname,
		expires:   time.Now().Add(5 * time.Minute),
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
	}

	if p.cfg.UsePKCE {
		verifier, err := randomString(64)
		if err != nil {
			return "", "", fmt.Errorf("generating PKCE verifier: %w", err)
		}
		st.pkceVerifier = verifier

		// S256 challenge
		h := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	p.mu.Lock()
	p.states[state] = st
	p.mu.Unlock()

	return p.oauth2Cfg.AuthCodeURL(state, opts...), state, nil
}

// Exchange validates the state and exchanges the authorization code for claims.
// callbackURL should match the redirect_uri used when initiating the flow.
func (p *OIDCProvider) Exchange(ctx context.Context, state, code, callbackURL string) (*OIDCClaims, *OIDCState, error) {
	p.mu.Lock()
	st, ok := p.states[state]
	if ok {
		delete(p.states, state)
	}
	p.mu.Unlock()

	if !ok {
		return nil, nil, fmt.Errorf("invalid or expired state")
	}
	if time.Now().After(st.expires) {
		return nil, nil, fmt.Errorf("state expired")
	}

	// Use the callback URL that was used for this specific flow
	cfgCopy := *p.oauth2Cfg
	if callbackURL != "" {
		cfgCopy.RedirectURL = callbackURL
	}

	var opts []oauth2.AuthCodeOption
	if p.cfg.UsePKCE && st.pkceVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", st.pkceVerifier))
	}

	token, err := cfgCopy.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, st, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, st, fmt.Errorf("no id_token in response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, st, fmt.Errorf("ID token verification: %w", err)
	}

	// Verify nonce
	if idToken.Nonce != st.nonce {
		return nil, st, fmt.Errorf("nonce mismatch")
	}

	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, st, fmt.Errorf("extracting claims: %w", err)
	}

	claims := &OIDCClaims{Raw: rawClaims}

	nameClaim := p.cfg.NameClaim
	if nameClaim == "" {
		nameClaim = "name"
	}
	emailClaim := p.cfg.EmailClaim
	if emailClaim == "" {
		emailClaim = "email"
	}

	if v, ok := rawClaims[nameClaim].(string); ok {
		claims.Name = v
	}
	if v, ok := rawClaims[emailClaim].(string); ok {
		claims.Email = v
	}

	return claims, st, nil
}

// MatchesClaim checks if claims contain a specific claim name with a specific value.
// Returns true if claimName is empty (no filter configured).
func MatchesClaim(claims map[string]interface{}, claimName, claimValue string) bool {
	if claimName == "" {
		return true
	}

	val, ok := claims[claimName]
	if !ok {
		return false
	}

	switch v := val.(type) {
	case string:
		return v == claimValue
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == claimValue {
				return true
			}
		}
	case float64:
		return fmt.Sprintf("%g", v) == claimValue
	case bool:
		return fmt.Sprintf("%v", v) == claimValue
	}

	return false
}

// UpdateConfig updates the OIDC provider configuration and rebuilds internal state.
func (p *OIDCProvider) UpdateConfig(cfg *config.OIDCConfig, callbackURL string) {
	ctx := context.Background()

	keySet := gooidc.NewRemoteKeySet(ctx, cfg.CertURL)
	verifier := gooidc.NewVerifier("", keySet, &gooidc.Config{
		ClientID:        cfg.ClientID,
		SkipIssuerCheck: true,
	})

	p.cfg = cfg
	p.oauth2Cfg = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
		Scopes:      []string{"openid", "email", "profile"},
		RedirectURL: callbackURL,
	}
	p.verifier = verifier
}

func (p *OIDCProvider) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for k, v := range p.states {
			if now.After(v.expires) {
				delete(p.states, k)
			}
		}
		p.mu.Unlock()
	}
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ActorString formats the OIDC user identity for audit logging.
func (c *OIDCClaims) ActorString() string {
	if c.Name != "" && c.Email != "" {
		return fmt.Sprintf("%s <%s>", c.Name, c.Email)
	}
	if c.Email != "" {
		return c.Email
	}
	if c.Name != "" {
		return c.Name
	}
	return "OIDC User"
}

// GetClaimValue returns a claim value as a string, using the configured claim name.
func (c *OIDCClaims) GetClaimValue(claimName string) string {
	if claimName == "" {
		return c.Email
	}
	if val, ok := c.Raw[claimName]; ok {
		return fmt.Sprintf("%v", val)
	}
	return ""
}


