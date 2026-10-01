// Command license-server is the central license verification server for the
// SpyCam agent. It loads license codes from a JSON file, signs verification
// responses with an Ed25519 key (generated on first run), and exposes:
//
//	POST /api/verify   verify a code + bind a device, returns a signed entitlement
//	GET  /api/pubkey   the public key clients should pin
//	GET  /healthz
//
// Licenses file format (code -> entitlement):
//
//	{
//	  "PRO-XXXX-1111": {"plan":"pro","features":["scan","active_scan","cameras"],"max_devices":3},
//	  "BIZ-YYYY-2222": {"plan":"business","features":["scan","active_scan","cameras","activity","alerts","signing"],"expires":"2027-01-01T00:00:00Z"}
//	}
//
// Device bindings are written back into the licenses file as devices connect.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"spycam-tray-agent/internal/license"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	licensesPath := flag.String("licenses", "licenses.json", "path to licenses JSON file")
	keyPath := flag.String("key", "license-key.seed", "path to Ed25519 signing seed (created if missing)")
	adminToken := flag.String("admin-token", os.Getenv("LICENSE_ADMIN_TOKEN"), "admin API bearer token (or LICENSE_ADMIN_TOKEN env); empty disables the admin API")
	flag.Parse()

	seed := loadOrCreateSeed(*keyPath)
	licenses := loadLicenses(*licensesPath)

	store, err := license.NewStore(licenses, seed)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	if *adminToken != "" {
		store.SetAdminToken(*adminToken)
		log.Printf("admin API enabled")
	} else {
		log.Printf("admin API disabled (set -admin-token or LICENSE_ADMIN_TOKEN to enable)")
	}

	// Persist device bindings back to disk (debounced by a mutex).
	var saveMu sync.Mutex
	store.SetPersistHook(func(m map[string]*license.License) {
		saveMu.Lock()
		defer saveMu.Unlock()
		saveLicenses(*licensesPath, m)
	})

	log.Printf("license server listening on %s", *addr)
	log.Printf("PUBLIC KEY (pin this in clients): %s", store.PublicKey())
	log.Printf("loaded %d license code(s) from %s", len(licenses), *licensesPath)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           store.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func loadOrCreateSeed(path string) string {
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return string(b)
	}
	seed, pub, err := license.GenerateKeypair()
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		log.Fatalf("write key: %v", err)
	}
	log.Printf("generated new signing key at %s (public key %s)", path, pub)
	return seed
}

func loadLicenses(path string) map[string]*license.License {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("licenses file %s not found; starting empty", path)
			return map[string]*license.License{}
		}
		log.Fatalf("read licenses: %v", err)
	}
	var m map[string]*license.License
	if err := json.Unmarshal(b, &m); err != nil {
		log.Fatalf("parse licenses: %v", err)
	}
	if m == nil {
		m = map[string]*license.License{}
	}
	return m
}

func saveLicenses(path string, m map[string]*license.License) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Printf("marshal licenses: %v", err)
		return
	}
	tmp := filepath.Join(filepath.Dir(path), ".licenses.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("write licenses tmp: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("rename licenses: %v", err)
	}
}
