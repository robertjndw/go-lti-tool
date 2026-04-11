// basic-launch demonstrates the minimal LTI 1.3 OIDC launch flow using only
// the core packages. No LTI Advantage service imports are needed.
//
// Run:
//
//	go run ./examples/basic-launch
//
// Then register the tool in your LMS with:
//   - Login Initiation URL: http://localhost:8080/oidc/login
//   - Launch/Redirect URL:  http://localhost:8080/lti/launch
//   - JWKS URL:             http://localhost:8080/.well-known/jwks.json
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/jwks"
	"github.com/robertjndw/go-lti/launch"
	"github.com/robertjndw/go-lti/login"
)

// --- In-memory datastore for the example ---

type exampleStore struct {
	reg *lti.Registration
}

func (s *exampleStore) FindRegistrationByIssuer(_ context.Context, issuer string) (*lti.Registration, error) {
	if s.reg.Issuer == issuer {
		return s.reg, nil
	}
	return nil, lti.ErrRegistrationNotFound
}

func (s *exampleStore) FindDeployment(_ context.Context, _, _ string) (*lti.Deployment, error) {
	return &lti.Deployment{DeploymentID: "1"}, nil
}

func main() {
	// Generate a 2048-bit RSA key pair for the tool.
	// In production, load the key from a secure secret store.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	// Build a registration. In production, read these values from config.
	reg := &lti.Registration{
		Issuer:         "https://canvas.instructure.com",     // Replace with your LMS issuer
		ClientID:       "your-client-id",                     // Replace with your client ID
		KeySetURL:      "https://canvas.instructure.com/api/lti/security/jwks",
		AuthLoginURL:   "https://canvas.instructure.com/api/lti/authorize_redirect",
		AuthTokenURL:   "https://canvas.instructure.com/login/oauth2/token",
		ToolPrivateKey: privateKey,
		KID:            "key-1",
	}

	store := &exampleStore{reg: reg}
	nonces := lti.NewMemoryNonceStore()
	launches := lti.NewMemoryLaunchDataStore()
	ks := jwks.FromRegistration(reg)

	loginCfg := login.Config{
		Datastore:  store,
		NonceStore: nonces,
	}
	launchCfg := launch.Config{
		Datastore:   store,
		NonceStore:  nonces,
		LaunchStore: launches,
	}

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", login.Handler(loginCfg))
	mux.Handle("/lti/launch", launch.Handler(launchCfg, http.HandlerFunc(handleLaunch)))
	mux.Handle("/.well-known/jwks.json", ks.Handler())

	log.Println("LTI tool listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	ld, ok := launch.FromContext(r.Context())
	if !ok {
		http.Error(w, "no launch data in context", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	summary := map[string]any{
		"launch_id":    ld.LaunchID,
		"user":         ld.Claims.Subject,
		"name":         ld.Claims.Name,
		"email":        ld.Claims.Email,
		"roles":        ld.Claims.Roles,
		"message_type": ld.Claims.MessageType,
		"context":      ld.Claims.Context,
		"has_ags":      ld.HasAGS(),
		"has_nrps":     ld.HasNRPS(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(summary); err != nil {
		log.Printf("failed to write response: %v", err)
	}
	fmt.Fprintf(w, "<!-- launch_id: %s -->\n", ld.LaunchID)
}
