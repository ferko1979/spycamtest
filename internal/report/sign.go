package report

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Signature is a detached signature over a report's canonical JSON, plus the
// public key needed to verify it. This makes a work-verifier report
// tamper-evident: a consumer can confirm it was produced by the agent
// holding the private key and not altered afterward.
type Signature struct {
	Algo      string `json:"algo"`       // "ed25519"
	PublicKey string `json:"public_key"` // base64 (std)
	Value     string `json:"signature"`  // base64 (std) over SigningPayload
}

// GenerateSeed returns a base64 32-byte Ed25519 seed for persisting in
// config. The private key is derived from it at runtime.
func GenerateSeed() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seed), nil
}

// keyFromSeed derives an Ed25519 private key from a base64 seed.
func keyFromSeed(seedB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid seed length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SigningPayload is the exact byte sequence that gets signed: the report
// with its Signature field cleared, marshaled canonically. Keeping this
// separate from JSON() ensures signing and verification agree.
func (r Report) SigningPayload() ([]byte, error) {
	r.Signature = nil
	return json.Marshal(r)
}

// Sign computes and attaches an Ed25519 signature using the given base64
// seed. After signing, r.Signature is populated.
func (r *Report) Sign(seedB64 string) error {
	if seedB64 == "" {
		return errors.New("no signing seed configured")
	}
	priv, err := keyFromSeed(seedB64)
	if err != nil {
		return err
	}
	payload, err := r.SigningPayload()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	pub := priv.Public().(ed25519.PublicKey)
	r.Signature = &Signature{
		Algo:      "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

// Verify checks a report's attached signature against its own content and
// embedded public key. Returns true only if the signature is valid.
func (r Report) Verify() bool {
	if r.Signature == nil || r.Signature.Algo != "ed25519" {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(r.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		return false
	}
	payload, err := r.SigningPayload()
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}
