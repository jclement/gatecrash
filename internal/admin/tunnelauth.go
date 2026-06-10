package admin

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tunnelCookieName      = "gatecrash_tunnel"
	tunnelSessionDuration = 8 * time.Hour
)

// tunnelClaims is the JWT for a per-hostname tunnel session. It records which
// user authenticated so the tunnel can authorize them and inject identity
// headers. Bound to the hostname (Subject) to prevent cross-tunnel reuse.
type tunnelClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid,omitempty"`
	Role   string `json:"role,omitempty"`
}

// TunnelSession manages per-hostname authenticated sessions for protected
// tunnels, established via the cross-host handoff from the admin login.
type TunnelSession struct {
	secret []byte
}

// NewTunnelSession creates a tunnel session manager with a purpose-derived key.
func NewTunnelSession(secret string) *TunnelSession {
	return &TunnelSession{secret: DeriveKey(secret, "tunnel-session")}
}

// CreateSession sets a tunnel session cookie scoped to the hostname, recording
// the authenticated user.
func (t *TunnelSession) CreateSession(w http.ResponseWriter, hostname, userID, role string) error {
	claims := tunnelClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tunnelSessionDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gatecrash-tunnel",
			Subject:   hostname,
		},
		UserID: userID,
		Role:   role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(t.secret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     tunnelCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(tunnelSessionDuration.Seconds()),
	})
	return nil
}

// ValidateSession returns the authenticated user for a tunnel hostname, if any.
func (t *TunnelSession) ValidateSession(r *http.Request, hostname string) (userID, role string, ok bool) {
	cookie, err := r.Cookie(tunnelCookieName)
	if err != nil {
		return "", "", false
	}
	token, err := jwt.ParseWithClaims(cookie.Value, &tunnelClaims{}, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}
		return t.secret, nil
	})
	if err != nil {
		return "", "", false
	}
	claims, valid := token.Claims.(*tunnelClaims)
	if !valid || !token.Valid || claims.Issuer != "gatecrash-tunnel" || claims.Subject != hostname {
		return "", "", false
	}
	return claims.UserID, claims.Role, true
}
