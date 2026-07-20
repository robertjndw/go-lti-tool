// complete demonstrates a full LTI 1.3 + LTI Advantage tool that handles all
// message types and uses all three LTI Advantage services:
//
//   - OIDC launch flow (login initiation + JWT validation)
//   - JWKS endpoint for the tool's public keys
//   - Assignment & Grade Services (AGS) — submit scores, manage line items
//   - Names & Role Provisioning Services (NRPS) — fetch course roster
//   - Deep Linking — return content items to the platform
//
// Run:
//
//	go run ./examples/complete
//
// Register in your LMS:
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
	"time"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/ags"
	"github.com/robertjndw/go-lti-tool/advantage/deeplink"
	"github.com/robertjndw/go-lti-tool/advantage/nrps"
	"github.com/robertjndw/go-lti-tool/jwks"
)

// --- App ---

type app struct {
	tool *lti.Tool
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	reg := &lti.Registration{
		Issuer:         "https://canvas.instructure.com", // Replace
		ClientID:       "your-client-id",                 // Replace
		KeySetURL:      "https://canvas.instructure.com/api/lti/security/jwks",
		AuthLoginURL:   "https://canvas.instructure.com/api/lti/authorize_redirect",
		AuthTokenURL:   "https://canvas.instructure.com/login/oauth2/token",
		ToolPrivateKey: privateKey,
		KID:            "tool-key-1",
	}

	ds := lti.NewMemoryStore()
	if err := ds.AddRegistration(context.TODO(), *reg); err != nil {
		log.Fatalf("failed to add registration: %v", err)
	}
	if err := ds.AddDeployment(context.TODO(), reg.Issuer, lti.Deployment{DeploymentID: "your-deployment-id"}); err != nil {
		log.Fatalf("failed to add deployment: %v", err)
	}

	tool := lti.NewTool(
		lti.WithDataStore(ds),
		lti.WithKeySet(jwks.FromRegistration(reg)),
	)
	a := &app{tool: tool}

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", tool.HandleLogin())
	mux.Handle("/lti/launch", tool.HandleLaunch(http.HandlerFunc(a.handleLaunch)))
	mux.Handle("/.well-known/jwks.json", tool.HandleJWKS())
	mux.HandleFunc("/content-picker", a.handleContentPicker)

	log.Println("Complete LTI tool listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// handleLaunch dispatches to the appropriate handler based on message type.
func (a *app) handleLaunch(w http.ResponseWriter, r *http.Request) {
	ld, ok := lti.LaunchFromContext(r.Context())
	if !ok {
		http.Error(w, "no launch data", http.StatusInternalServerError)
		return
	}

	log.Printf("launch: type=%s user=%s deployment=%s",
		ld.Claims.MessageType, ld.Claims.Subject, ld.Claims.DeploymentID)

	switch {
	case ld.IsDeepLinkLaunch():
		a.handleDeepLinkLaunch(w, r, ld)
	case ld.IsResourceLaunch():
		a.handleResourceLaunch(w, r, ld)
	default:
		http.Error(w, "unsupported message type: "+ld.Claims.MessageType, http.StatusBadRequest)
	}
}

// handleResourceLaunch handles LtiResourceLinkRequest launches.
func (a *app) handleResourceLaunch(w http.ResponseWriter, r *http.Request, ld *lti.Launch) {
	ctx := r.Context()
	resp := map[string]any{
		"launch_id": ld.LaunchID,
		"user":      ld.Claims.Subject,
		"name":      ld.Claims.Name,
		"email":     ld.Claims.Email,
		"roles":     ld.Claims.Roles,
		"has_ags":   ld.HasAGS(),
		"has_nrps":  ld.HasNRPS(),
	}

	// Fetch the roster if NRPS is available.
	if ld.HasNRPS() {
		nrpsService, err := nrps.NewFromLaunch(ld)
		if err == nil {
			members, err := nrpsService.GetMembers(ctx)
			if err == nil {
				resp["roster_count"] = len(members)
			} else {
				log.Printf("NRPS GetMembers: %v", err)
			}
		}
	}

	// Submit a grade if AGS is available.
	if ld.HasAGS() {
		agsService, err := ags.NewFromLaunch(ld)
		if err == nil {
			li, err := agsService.FindOrCreateLineitem(ctx, ags.Lineitem{
				Label:        "Auto-graded Activity",
				ScoreMaximum: 10,
				ResourceID:   "activity-1",
			})
			if err == nil {
				score := ags.Score{
					UserID:           ld.Claims.Subject,
					ScoreGiven:       ags.Float64(8),
					ScoreMaximum:     ags.Float64(10),
					ActivityProgress: ags.ActivityProgressCompleted,
					GradingProgress:  ags.GradingProgressFullyGraded,
					Timestamp:        time.Now().UTC().Format(time.RFC3339),
				}
				if err := agsService.SubmitScore(ctx, li.ID, score); err != nil {
					log.Printf("SubmitScore: %v", err)
				} else {
					resp["grade_submitted"] = true
				}
			} else {
				log.Printf("FindOrCreateLineitem: %v", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("write response: %v", err)
	}
}

// handleDeepLinkLaunch renders a content picker for deep linking launches.
func (a *app) handleDeepLinkLaunch(w http.ResponseWriter, _ *http.Request, ld *lti.Launch) {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Add Content</title></head>
<body>
<h1>Select content for your course</h1>
<ul>
  <li><a href="/content-picker?launch_id=%s&resource=quiz-1">Quiz 1: Introduction</a></li>
  <li><a href="/content-picker?launch_id=%s&resource=quiz-2">Quiz 2: Advanced</a></li>
  <li><a href="/content-picker?launch_id=%s&resource=lesson-1">Lesson 1: Fundamentals</a></li>
</ul>
</body>
</html>`, ld.LaunchID, ld.LaunchID, ld.LaunchID)
}

// handleContentPicker processes a content selection and returns the deep link response.
func (a *app) handleContentPicker(w http.ResponseWriter, r *http.Request) {
	launchID := r.URL.Query().Get("launch_id")
	resource := r.URL.Query().Get("resource")

	ld, err := a.tool.GetLaunch(r.Context(), launchID)
	if err != nil {
		http.Error(w, "launch not found or expired", http.StatusBadRequest)
		return
	}

	builder, err := deeplink.NewFromLaunch(ld)
	if err != nil {
		http.Error(w, fmt.Sprintf("deep link error: %v", err), http.StatusBadRequest)
		return
	}

	resources := []deeplink.Resource{
		deeplink.NewLTIResourceLinkWithGrade(
			fmt.Sprintf("Content: %s", resource),
			fmt.Sprintf("https://tool.example.com/resource/%s", resource),
			deeplink.LineItemProperty{
				Label:        fmt.Sprintf("Grade for %s", resource),
				ScoreMaximum: 100,
			},
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
