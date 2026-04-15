// basic-launch demonstrates the minimal LTI 1.3 OIDC launch flow using the
// top-level Tool type. No sub-package imports are needed for the launch flow.
//
// It also exposes a Dynamic Registration endpoint so that a compatible platform
// can register the tool automatically instead of requiring manual configuration.
//
// Run:
//
//	go run ./examples/basic-launch
//
// For manual registration, configure your LMS with:
//   - Login Initiation URL: http://localhost:8080/oidc/login
//   - Launch/Redirect URL:  http://localhost:8080/lti/launch
//   - JWKS URL:             http://localhost:8080/.well-known/jwks.json
//
// For dynamic registration, point your LMS to:
//
//	http://localhost:8080/lti/registration
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
)

func main() {
	// Generate a 2048-bit RSA key pair for the tool.
	// In production, load the key from a secure secret store.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	// Build a registration. In production, read these values from config.
	reg := lti.Registration{
		Issuer:         "https://canvas.instructure.com", // Replace with your LMS issuer
		ClientID:       "your-client-id",                 // Replace with your client ID
		KeySetURL:      "https://canvas.instructure.com/api/lti/security/jwks",
		AuthLoginURL:   "https://canvas.instructure.com/api/lti/authorize_redirect",
		AuthTokenURL:   "https://canvas.instructure.com/login/oauth2/token",
		ToolPrivateKey: privateKey,
		KID:            "key-1",
	}

	store := lti.NewMemoryStore()
	if err := store.AddRegistration(context.Background(), reg); err != nil {
		log.Fatalf("failed to add registration: %v", err)
	}
	// Accept any deployment ID for this example.
	if err := store.AddDeployment(context.Background(), reg.Issuer, lti.Deployment{DeploymentID: "1"}); err != nil {
		log.Fatalf("failed to add deployment: %v", err)
	}

	tool := lti.NewTool(
		lti.WithDataStore(store),
		lti.WithKeySet(jwks.FromRegistration(&reg)),
	)

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", tool.HandleLogin())
	mux.Handle("/lti/launch", tool.HandleLaunch(http.HandlerFunc(handleLaunch)))
	mux.Handle("/.well-known/jwks.json", tool.HandleJWKS())
	// Dynamic Registration lets compatible platforms register this tool
	// automatically. The platform opens this URL (with an openid_configuration
	// query param) and the handler negotiates the registration on the tool's
	// behalf, storing the result in the same datastore used by HandleLogin and
	// HandleLaunch.
	mux.Handle("/lti/registration", tool.HandleDynamicRegistration(lti.ToolProfile{
		Name:   "Go LTI Tool",
		Domain: "http://localhost:8080",
		// Local LMS development often runs over plain HTTP.
		AllowInsecureOpenIDConfigURL: true,
		KID:                          "key-1", // Must match the KID used in jwks.FromRegistration above.

		// LTI endpoint paths — appended to Domain when building absolute URIs.
		LoginPath:      "/oidc/login",
		JWKSPath:       "/.well-known/jwks.json",
		TargetLinkPath: "/lti/launch",
		RedirectPaths:  []string{"/lti/launch"},

		// Standard OIDC claims the tool needs from the platform.
		Claims: []string{"sub", "email", "name", "given_name", "family_name"},

		// LTI Advantage service scopes. Request only the scopes your tool uses.
		Scopes: []string{
			"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
			"https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
			"https://purl.imsglobal.org/spec/lti-ags/scope/score",
			"https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
		},

		// Optional: expose a deep-linking placement so instructors can add
		// content items from within the LMS course editor.
		Messages: []lti.ToolMessage{
			{
				Type:          "LtiDeepLinkingRequest",
				TargetLinkURI: "http://localhost:8080/lti/launch",
				Label:         "Go LTI Tool — Add Content",
				Placements:    []string{"ContentArea", "LinkSelection"},
			},
		},

		// Optional metadata shown in the platform's admin UI.
		Description: "Example Go LTI 1.3 tool built with github.com/robertjndw/go-lti.",
	}))

	log.Println("LTI tool listening on :8080")
	log.Println("Dynamic Registration link http://localhost:8080/lti/registration")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	ld, ok := lti.LaunchFromContext(r.Context())
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
