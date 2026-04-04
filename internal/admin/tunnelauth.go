package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tunnelAuthCookieName = "gatecrash_tunnel_auth"
	tunnelAuthDuration   = 8 * time.Hour
)

// tunnelAuthClaims holds OIDC claims in the tunnel auth JWT.
type tunnelAuthClaims struct {
	jwt.RegisteredClaims
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	RawClaims string `json:"raw_claims,omitempty"` // JSON-encoded claims map
}

// TunnelAuthSession manages OIDC-based sessions for protected tunnels.
type TunnelAuthSession struct {
	secret []byte
}

// NewTunnelAuthSession creates a new tunnel auth session manager with a purpose-derived key.
func NewTunnelAuthSession(secret string) *TunnelAuthSession {
	return &TunnelAuthSession{secret: DeriveKey(secret, "tunnel-auth")}
}

// CreateSession sets a tunnel auth cookie scoped to the given hostname.
func (t *TunnelAuthSession) CreateSession(w http.ResponseWriter, claims *OIDCClaims, hostname string) error {
	rawJSON, err := json.Marshal(claims.Raw)
	if err != nil {
		rawJSON = []byte("{}")
	}

	tc := tunnelAuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tunnelAuthDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gatecrash-tunnel",
			Subject:   hostname,
		},
		Name:      claims.Name,
		Email:     claims.Email,
		RawClaims: string(rawJSON),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tc)
	signed, err := token.SignedString(t.secret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     tunnelAuthCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(tunnelAuthDuration.Seconds()),
	})

	return nil
}

// ValidateSession checks if the request has a valid tunnel auth session for the given hostname.
// Returns the claims if valid.
func (t *TunnelAuthSession) ValidateSession(r *http.Request, hostname string) (*OIDCClaims, bool) {
	cookie, err := r.Cookie(tunnelAuthCookieName)
	if err != nil {
		return nil, false
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &tunnelAuthClaims{}, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}
		return t.secret, nil
	})
	if err != nil {
		return nil, false
	}

	claims, ok := token.Claims.(*tunnelAuthClaims)
	if !ok || !token.Valid {
		return nil, false
	}

	if claims.Issuer != "gatecrash-tunnel" {
		return nil, false
	}

	// Verify hostname matches to prevent cross-tunnel session reuse
	if claims.Subject != hostname {
		return nil, false
	}

	// Reconstruct OIDCClaims
	oidcClaims := &OIDCClaims{
		Name:  claims.Name,
		Email: claims.Email,
		Raw:   make(map[string]interface{}),
	}
	if claims.RawClaims != "" {
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(claims.RawClaims), &raw); err == nil {
			oidcClaims.Raw = raw
		}
	}

	return oidcClaims, true
}
