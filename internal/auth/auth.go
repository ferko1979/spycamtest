// Package auth provides a simple bearer-token scheme for the local agent
// API. The token is generated once, persisted by the caller in the agent's
// config file, and required on every agent endpoint. This replaces the
// former hard-coded password compiled into the binary.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// GenerateToken returns a cryptographically random 256-bit token as hex.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Equal reports whether two tokens match, in constant time, so comparison
// does not leak length/content via timing.
func Equal(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// TokenFromRequest extracts a token from either the Authorization: Bearer
// header or the X-Agent-Token header.
func TokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return strings.TrimSpace(h[len("bearer "):])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Agent-Token"))
}

// Middleware wraps a handler, rejecting requests whose token does not match
// want. OPTIONS (CORS preflight) requests are passed through so the browser
// can complete preflight before sending the real, authenticated request.
func Middleware(want string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		if !Equal(TokenFromRequest(r), want) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
