package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateTokenUnique(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateToken()
	if a == b {
		t.Error("tokens should be unique")
	}
	if len(a) != 64 {
		t.Errorf("token hex length = %d, want 64", len(a))
	}
}

func TestEqual(t *testing.T) {
	if !Equal("abc", "abc") {
		t.Error("equal tokens should match")
	}
	if Equal("abc", "abd") {
		t.Error("different tokens should not match")
	}
	if Equal("", "") {
		t.Error("empty tokens must never match")
	}
}

func TestTokenFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer tok123")
	if got := TokenFromRequest(r); got != "tok123" {
		t.Errorf("bearer parse = %q", got)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("X-Agent-Token", "tok456")
	if got := TokenFromRequest(r2); got != "tok456" {
		t.Errorf("x-agent-token parse = %q", got)
	}
}

func TestMiddleware(t *testing.T) {
	called := false
	h := Middleware("secret", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	// Missing token -> 401.
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/scan", nil))
	if w.Code != 401 || called {
		t.Errorf("missing token should 401, code=%d called=%v", w.Code, called)
	}

	// Correct token -> passes.
	called = false
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/scan", nil)
	r.Header.Set("Authorization", "Bearer secret")
	h(w, r)
	if w.Code != 200 || !called {
		t.Errorf("valid token should pass, code=%d called=%v", w.Code, called)
	}

	// OPTIONS preflight -> passes without token.
	called = false
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("OPTIONS", "/scan", nil))
	if !called {
		t.Error("OPTIONS preflight should pass through")
	}
}
