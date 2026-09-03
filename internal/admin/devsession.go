//go:build dev

package admin

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueDevSession mints a session cookie for the no-auth dev bypass. Unlike the
// normal issue path it sets Secure:false so the cookie survives plain-HTTP dev
// serving (browsers withhold Secure cookies over http://), and it also injects
// the cookie into the current request so the same request is authenticated (and
// gets a consistent CSRF token) without waiting for a browser round-trip. It is
// dev-build-only and must never exist in a released binary.
func (sm *SessionManager) IssueDevSession(w http.ResponseWriter, r *http.Request, userID, role, sid string) error {
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gatecrash",
		},
		Actor: userID,
		Role:  role,
		SID:   sid,
		Epoch: sm.currentEpoch(userID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sm.secret)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	}
	http.SetCookie(w, cookie)
	// Authenticate the current request too: replace any existing session cookie
	// so sessionUser/CSRF in this same request see the dev session.
	stripSessionCookie(r)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signed})
	return nil
}

// stripSessionCookie removes any existing session cookie from the request so a
// re-issued dev cookie isn't shadowed by a stale one.
func stripSessionCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			continue
		}
		r.AddCookie(c)
	}
}
