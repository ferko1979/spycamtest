package license

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Client verifies a single code against the license server.
type Client struct {
	ServerURL    string // base URL, e.g. https://license.example.com
	DeviceID     string
	AppVersion   string
	PinnedPubKey string // base64; if set, the response key must match exactly
	HTTP         *http.Client
	// MaxSkew bounds how old IssuedAt may be, to reject replayed responses.
	MaxSkew time.Duration
}

// ErrKeyMismatch means the server's signing key did not match the pinned key.
var ErrKeyMismatch = errors.New("license server public key mismatch")

// VerifyCode posts the code and returns verified Claims. The signature, the
// echoed nonce, the pinned key (if any) and response freshness are all checked.
func (c Client) VerifyCode(ctx context.Context, code string) (Claims, error) {
	if c.ServerURL == "" {
		return Claims{}, errors.New("no license server configured")
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	skew := c.MaxSkew
	if skew <= 0 {
		skew = 10 * time.Minute
	}

	nonce := RandomNonce()
	reqBody, _ := json.Marshal(VerifyRequest{
		Code: code, DeviceID: c.DeviceID, AppVersion: c.AppVersion, Nonce: nonce,
	})
	url := trimSlash(c.ServerURL) + "/api/verify"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return Claims{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return Claims{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Claims{}, fmt.Errorf("license server HTTP %d", resp.StatusCode)
	}

	var sr SignedResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return Claims{}, err
	}

	// Pin check first: refuse a key we don't trust before trusting its sig.
	if c.PinnedPubKey != "" && sr.PublicKey != c.PinnedPubKey {
		return Claims{}, ErrKeyMismatch
	}
	if !VerifySignature(sr.PublicKey, sr.Claims, sr.Signature) {
		return Claims{}, errors.New("invalid license signature")
	}

	var claims Claims
	if err := json.Unmarshal(sr.Claims, &claims); err != nil {
		return Claims{}, err
	}
	if claims.Nonce != nonce {
		return Claims{}, errors.New("nonce mismatch (possible replay)")
	}
	if age := time.Since(claims.IssuedAt); age > skew || age < -skew {
		return Claims{}, errors.New("stale license response")
	}
	return claims, nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
