// grades demonstrates submitting a learner grade back to the platform via LTI
// Advantage Assignment & Grade Services (AGS) after a resource link launch.
//
// This example builds on basic-launch and additionally:
//   - Creates or finds the line item for this resource link
//   - Submits a score for the launching user
//   - Reads back the results
//
// Run:
//
//	go run ./examples/grades
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/advantage/ags"
	"github.com/robertjndw/go-lti/jwks"
	"github.com/robertjndw/go-lti/launch"
	"github.com/robertjndw/go-lti/login"
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
	nonces := lti.NewMemoryNonceStore()
	launches := lti.NewMemoryLaunchDataStore()
	ks := jwks.FromRegistration(reg)

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", login.Handler(login.Config{Datastore: store, NonceStore: nonces}))
	mux.Handle("/lti/launch", launch.Handler(
		launch.Config{Datastore: store, NonceStore: nonces, LaunchStore: launches},
		http.HandlerFunc(handleLaunch),
	))
	mux.Handle("/.well-known/jwks.json", ks.Handler())

	log.Println("Grades example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	ld, ok := launch.FromContext(r.Context())
	if !ok {
		http.Error(w, "no launch data", http.StatusInternalServerError)
		return
	}

	if !ld.HasAGS() {
		fmt.Fprintln(w, "Launch does not include AGS — no grading available.")
		return
	}

	// Build the AGS service.
	agsService, err := ags.NewFromLaunch(ld)
	if err != nil {
		http.Error(w, fmt.Sprintf("AGS init failed: %v", err), http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	// Find or create the line item for this resource.
	lineitem, err := agsService.FindOrCreateLineitem(ctx, ags.Lineitem{
		Label:        "Example Quiz",
		ScoreMaximum: 100,
		ResourceID:   "quiz-1",
		Tag:          "quiz",
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get line item: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("using line item: %s (%s)", lineitem.Label, lineitem.ID)

	// Submit a score for the launching user (85/100 for this example).
	score := ags.Score{
		UserID:           ld.Claims.Subject,
		ScoreGiven:       85,
		ScoreMaximum:     100,
		Comment:          "Great work!",
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}
	if err := agsService.SubmitScore(ctx, lineitem.ID, score); err != nil {
		log.Printf("SubmitScore warning: %v", err)
		// Non-fatal: the tool still launched successfully.
	} else {
		log.Printf("submitted score %.0f/%.0f for user %s", score.ScoreGiven, score.ScoreMaximum, score.UserID)
	}

	// Read results back.
	results, err := agsService.GetResults(ctx, lineitem.ID)
	if err != nil {
		log.Printf("GetResults warning: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]any{ //nolint:errcheck
		"user":     ld.Claims.Subject,
		"lineitem": lineitem,
		"score":    score,
		"results":  results,
	})
}
