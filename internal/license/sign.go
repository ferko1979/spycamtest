package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// GenerateKeypair returns a new base64 (seed, publicKey) pair. The seed is the
// server's secret; the public key is what clients pin to verify responses.
func GenerateKeypair() (seedB64, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	seed := priv.Seed()
	return base64.StdEncoding.EncodeToString(seed), base64.StdEncoding.EncodeToString(pub), nil
}

// PrivFromSeed derives the private key from a base64 seed.
func PrivFromSeed(seedB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid seed length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PubB64 returns the base64 public key for a private key.
func PubB64(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// signClaims marshals+signs claims, returning the raw bytes and base64
// signature.
func signClaims(priv ed25519.PrivateKey, payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

// VerifySignature checks that sigB64 is a valid signature over payload by the
// key pubB64.
func VerifySignature(pubB64 string, payload []byte, sigB64 string) bool {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}
