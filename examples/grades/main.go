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

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/ags"
	"github.com/robertjndw/go-lti-tool/jwks"
)

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

	store := lti.NewMemoryStore()
	if err := store.AddRegistration(context.TODO(), *reg); err != nil {
		log.Fatalf("failed to add registration: %v", err)
	}
	if err := store.AddDeployment(context.TODO(), reg.Issuer, lti.Deployment{DeploymentID: "your-deployment-id"}); err != nil {
		log.Fatalf("failed to add deployment: %v", err)
	}
	tool := lti.NewTool(
		lti.WithDataStore(store),
		lti.WithKeySet(jwks.FromRegistration(reg)),
	)

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", tool.HandleLogin())
	mux.Handle("/lti/launch", tool.HandleLaunch(http.HandlerFunc(handleLaunch)))
	mux.Handle("/.well-known/jwks.json", tool.HandleJWKS())

	log.Println("Grades example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	ld, ok := lti.LaunchFromContext(r.Context())
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
		ScoreGiven:       ags.Float64(85),
		ScoreMaximum:     ags.Float64(100),
		Comment:          "Great work!",
		ActivityProgress: ags.ActivityProgressCompleted,
		GradingProgress:  ags.GradingProgressFullyGraded,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}
	if err := agsService.SubmitScore(ctx, lineitem.ID, score); err != nil {
		log.Printf("SubmitScore warning: %v", err)
		// Non-fatal: the tool still launched successfully.
	} else {
		log.Printf("submitted score %.0f/%.0f for user %s", *score.ScoreGiven, *score.ScoreMaximum, score.UserID)
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
