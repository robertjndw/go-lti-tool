// deep-linking demonstrates handling an LtiDeepLinkingRequest and returning
// content items (LTI resource links) to the platform.
//
// Flow:
//  1. Platform sends the user to /oidc/login (deep link variant).
//  2. Platform POSTs an id_token with message_type=LtiDeepLinkingRequest.
//  3. Tool renders a content picker UI (simplified here to a static list).
//  4. User selects content; tool builds a signed JWT and POSTs it back.
//
// Run:
//
//	go run ./examples/deep-linking
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/advantage/deeplink"
	"github.com/robertjndw/go-lti/jwks"
)

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

var tool *lti.Tool

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	reg := &lti.Registration{
		Issuer:         "https://canvas.instructure.com",
		ClientID:       "your-client-id",
		KeySetURL:      "https://canvas.instructure.com/api/lti/security/jwks",
		AuthLoginURL:   "https://canvas.instructure.com/api/lti/authorize_redirect",
		AuthTokenURL:   "https://canvas.instructure.com/login/oauth2/token",
		ToolPrivateKey: privateKey,
		KID:            "key-1",
	}

	store := &exampleStore{reg: reg}
	tool = lti.NewTool(
		lti.WithDataStore(store),
		lti.WithKeySet(jwks.FromRegistration(reg)),
	)

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", tool.HandleLogin())
	mux.Handle("/lti/launch", tool.HandleLaunch(http.HandlerFunc(handleDeepLink)))
	// Content picker: user selects content and we submit the deep link response.
	mux.HandleFunc("/content-picker", handleContentPicker)
	mux.Handle("/.well-known/jwks.json", tool.HandleJWKS())

	log.Println("Deep linking example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// handleDeepLink renders a simple content picker for deep linking launches.
func handleDeepLink(w http.ResponseWriter, r *http.Request) {
	ld, ok := lti.FromContext(r.Context())
	if !ok {
		http.Error(w, "no launch data", http.StatusInternalServerError)
		return
	}

	if !ld.IsDeepLinkLaunch() {
		// Regular resource launch — just show launch info.
		fmt.Fprintf(w, "Resource launch for user %s\n", ld.Claims.Subject)
		return
	}

	// Show a simple content picker.
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Select Content</title></head>
<body>
<h1>Select content to add to your course</h1>
<form action="/content-picker?launch_id=%s" method="POST">
  <button name="resource" value="quiz-1">Add Quiz 1</button>
  <button name="resource" value="quiz-2">Add Quiz 2</button>
  <button name="resource" value="lesson-1">Add Lesson 1</button>
</form>
</body>
</html>`, ld.LaunchID)
}

// handleContentPicker processes the content selection and returns the deep link response.
func handleContentPicker(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	launchID := r.URL.Query().Get("launch_id")
	resource := r.FormValue("resource")

	// Restore the launch data from cache.
	ld, err := tool.GetLaunchData(r.Context(), launchID)
	if err != nil {
		http.Error(w, "launch not found or expired", http.StatusBadRequest)
		return
	}

	builder, err := deeplink.NewFromLaunch(ld)
	if err != nil {
		http.Error(w, fmt.Sprintf("deep link error: %v", err), http.StatusInternalServerError)
		return
	}

	// Map the selected resource to a content item.
	resources := []deeplink.Resource{
		deeplink.NewLTIResourceLink(
			fmt.Sprintf("Content: %s", resource),
			fmt.Sprintf("https://tool.example.com/resource/%s", resource),
		),
	}

	html, err := builder.ResponseFormHTML(resources)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}
