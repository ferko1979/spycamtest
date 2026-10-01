// Package license implements feature entitlement for the agent: license codes
// map to services ("features"), a central server verifies codes and returns a
// signed entitlement, and the client re-verifies on each run and periodically
// while running. Responses are Ed25519-signed so a rogue local server cannot
// grant features, and the client keeps the last-known entitlement for a grace
// window if the server is briefly unreachable.
package license

import (
	"encoding/json"
	"time"
)

// Feature identifiers — the "services" a license can unlock.
const (
	FeatureScan       = "scan"        // passive network discovery
	FeatureActiveScan = "active_scan" // active TCP sweep + fingerprinting
	FeatureCameras    = "cameras"     // camera-detection view
	FeatureActivity   = "activity"    // activity tracking + work reports
	FeatureAlerts     = "alerts"      // new-device/camera webhook alerts
	FeatureSigning    = "signing"     // Ed25519-signed reports
)

// AllFeatures lists every known feature (useful for an "all" plan).
func AllFeatures() []string {
	return []string{FeatureScan, FeatureActiveScan, FeatureCameras, FeatureActivity, FeatureAlerts, FeatureSigning}
}

// VerifyRequest is what the client POSTs to the server.
type VerifyRequest struct {
	Code       string `json:"code"`
	DeviceID   string `json:"device_id"`
	AppVersion string `json:"app_version,omitempty"`
	Nonce      string `json:"nonce"` // echoed back in Claims to prevent replay
}

// Claims is the server's verdict for one code. It is serialized once, signed,
// and transmitted verbatim (see SignedResponse.Claims) so verification never
// depends on re-marshaling.
type Claims struct {
	Code     string    `json:"code"`
	Valid    bool      `json:"valid"`
	Plan     string    `json:"plan,omitempty"`
	Features []string  `json:"features,omitempty"`
	DeviceID string    `json:"device_id,omitempty"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires"`
	Nonce    string    `json:"nonce"`
	Reason   string    `json:"reason,omitempty"`
}

// SignedResponse carries the exact signed Claims bytes plus the signature and
// the signing public key. The signature is over the raw Claims bytes.
type SignedResponse struct {
	Claims    json.RawMessage `json:"claims"`
	Algo      string          `json:"algo"`
	PublicKey string          `json:"public_key"`
	Signature string          `json:"signature"`
}

// Has reports whether a feature list contains a feature.
func Has(features []string, feature string) bool {
	for _, f := range features {
		if f == feature {
			return true
		}
	}
	return false
}
