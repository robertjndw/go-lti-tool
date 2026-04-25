// moodle demonstrates the full LTI 1.3 Advantage feature set against a local
// Moodle instance. It covers:
//
//   - Dynamic Registration  — Moodle auto-configures the tool
//   - Resource Link Launch  — standard OIDC flow with identity / context display
//   - Deep Linking          — content picker that adds graded or plain resources
//   - NRPS                  — course roster fetched from Moodle on every launch
//   - AGS                   — score submitted to Moodle's gradebook on launch
//
// Start Moodle first (docker compose up -d), then run the tool:
//
//	TOOL_BASE_URL=http://host.docker.internal:8080 go run ./examples/moodle
//
// Register the tool in Moodle once:
//
//	Site admin → Plugins → Activity modules → External tool → Manage tools
//	→ "configure a tool manually" or paste the dynamic registration URL:
//	http://host.docker.internal:8080/lti/registration
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	lti "github.com/robertjndw/go-lti"
	"github.com/robertjndw/go-lti/advantage/ags"
	"github.com/robertjndw/go-lti/advantage/deeplink"
	"github.com/robertjndw/go-lti/advantage/nrps"
	"github.com/robertjndw/go-lti/jwks"
)

const kid = "key-1"

// server holds the shared Tool so every handler can call tool.GetLaunch.
type server struct {
	tool    *lti.Tool
	baseURL string
}

func main() {
	baseURL := os.Getenv("TOOL_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// TOOL_INTERNAL_URL is the base URL the platform's server uses to reach the
	// tool (e.g. http://host.docker.internal:8080 when Moodle runs in Docker).
	// It is only used for the JWKS URI — all browser-facing URLs use TOOL_BASE_URL.
	// Defaults to TOOL_BASE_URL when unset.
	internalURL := os.Getenv("TOOL_INTERNAL_URL")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	store := lti.NewMemoryStore()
	tool := lti.NewTool(
		lti.WithDataStore(store),
		lti.WithKeySet(jwks.NewKeySet(map[string]*rsa.PrivateKey{kid: privateKey})),
	)

	s := &server{tool: tool, baseURL: baseURL}

	mux := http.NewServeMux()
	mux.Handle("/oidc/login", tool.HandleLogin())
	mux.Handle("/lti/launch", tool.HandleLaunch(http.HandlerFunc(s.handleLaunch)))
	mux.Handle("/.well-known/jwks.json", tool.HandleJWKS())
	mux.HandleFunc("/lti/deeplink/submit", s.handleDeepLinkSubmit)
	mux.Handle("/lti/registration", tool.HandleDynamicRegistration(lti.ToolProfile{
		Name:                         "Go LTI Demo",
		Domain:                       baseURL,
		JWKSBaseURL:                  internalURL,
		AllowInsecureOpenIDConfigURL: true,
		KID:                          kid,
		LoginPath:                    "/oidc/login",
		JWKSPath:                     "/.well-known/jwks.json",
		TargetLinkPath:               "/lti/launch",
		RedirectPaths:                []string{"/lti/launch"},
		Claims:                       []string{"sub", "email", "name", "given_name", "family_name"},
		Scopes: []string{
			lti.ScopeAGSLineitem,
			lti.ScopeAGSScore,
			lti.ScopeAGSResultReadonly,
			lti.ScopeNRPS,
		},
		Messages: []lti.ToolMessage{
			{
				Type:          "LtiDeepLinkingRequest",
				TargetLinkURI: baseURL + "/lti/launch",
				Label:         "Go LTI Demo — Add Content",
				Placements:    []string{"ContentArea", "LinkSelection"},
			},
		},
		Description: "Full LTI 1.3 Advantage demo built with github.com/robertjndw/go-lti.",
	}))

	addr := ":8080"
	log.Printf("Go LTI Demo listening on %s", addr)
	log.Printf("Dynamic registration URL: %s/lti/registration", baseURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// handleLaunch is the post-validation entry point. It dispatches on message type.
func (s *server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	ld, ok := lti.LaunchFromContext(r.Context())
	if !ok {
		http.Error(w, "missing launch context", http.StatusInternalServerError)
		return
	}

	if ld.IsDeepLinkLaunch() {
		s.handleDeepLinkPicker(w, ld)
		return
	}
	s.handleResourceLaunch(w, r, ld)
}

// ── Resource Link Launch ──────────────────────────────────────────────────────

type resourceLaunchData struct {
	LaunchID    string
	Subject     string
	Name        string
	Email       string
	Roles       []string
	Context     *lti.ContextClaim
	NRPSMembers []nrps.Member
	NRPSError   string
	AGSResult   *agsResult
	AGSError    string
	AGSNotice   string
}

type agsResult struct {
	LineitemLabel string
	ScoreGiven    float64
	ScoreMax      float64
}

func (s *server) handleResourceLaunch(w http.ResponseWriter, r *http.Request, ld *lti.Launch) {
	data := resourceLaunchData{
		LaunchID: ld.LaunchID,
		Subject:  ld.Claims.Subject,
		Name:     ld.Claims.Name,
		Email:    ld.Claims.Email,
		Roles:    ld.Claims.Roles,
		Context:  ld.Claims.Context,
	}

	// ── NRPS: fetch course roster ─────────────────────────────────────────────
	if ld.HasNRPS() {
		svc, err := nrps.NewFromLaunch(ld)
		if err != nil {
			data.NRPSError = err.Error()
		} else {
			members, err := svc.GetMembers(r.Context())
			if err != nil {
				data.NRPSError = err.Error()
			} else {
				data.NRPSMembers = members
			}
		}
	}

	// ── AGS: submit a score for the current user ──────────────────────────────
	if ld.HasAGS() {
		if !hasLearnerRole(ld.Claims.Roles) {
			data.AGSNotice = "Score submission skipped for this launch. Moodle only accepts AGS scores for gradable learner users, and this launch is not a learner role."
		} else {
			svc, err := ags.NewFromLaunch(ld)
			if err != nil {
				data.AGSError = err.Error()
			} else {
				const maxScore = 100.0
				li, err := svc.FindOrCreateLineitem(r.Context(), ags.Lineitem{
					Label:        "Go LTI Demo Score",
					ScoreMaximum: maxScore,
					ResourceID:   "go-lti-demo",
					Tag:          "go-lti-demo",
				})
				if err != nil {
					data.AGSError = fmt.Sprintf("line item: %v", err)
				} else {
					score := ags.Score{
						UserID:           ld.Claims.Subject,
						ScoreGiven:       75,
						ScoreMaximum:     maxScore,
						ActivityProgress: ags.ActivityProgressCompleted,
						GradingProgress:  ags.GradingProgressFullyGraded,
						Timestamp:        time.Now().UTC().Format(time.RFC3339),
					}
					if err := svc.SubmitScore(r.Context(), li.ID, score); err != nil {
						data.AGSError = fmt.Sprintf("submit score: %v", err)
					} else {
						data.AGSResult = &agsResult{
							LineitemLabel: li.Label,
							ScoreGiven:    score.ScoreGiven,
							ScoreMax:      maxScore,
						}
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := resourceTmpl.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

// ── Deep Linking ──────────────────────────────────────────────────────────────

func (s *server) handleDeepLinkPicker(w http.ResponseWriter, ld *lti.Launch) {
	data := struct {
		LaunchID string
		BaseURL  string
	}{
		LaunchID: ld.LaunchID,
		BaseURL:  s.baseURL,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := deepLinkPickerTmpl.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

// handleDeepLinkSubmit builds and POSTs the LtiDeepLinkingResponse back to Moodle.
// It receives the launch_id and content_type from the picker form.
func (s *server) handleDeepLinkSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	launchID := r.FormValue("launch_id")
	contentType := r.FormValue("content_type")

	ld, err := s.tool.GetLaunch(r.Context(), launchID)
	if err != nil {
		http.Error(w, fmt.Sprintf("launch not found: %v", err), http.StatusBadRequest)
		return
	}

	builder, err := deeplink.NewFromLaunch(ld)
	if err != nil {
		http.Error(w, fmt.Sprintf("deep linking unavailable: %v", err), http.StatusBadRequest)
		return
	}

	resources := buildResources(contentType, s.baseURL)

	html, err := builder.ResponseFormHTML(resources)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func buildResources(contentType, baseURL string) []deeplink.Resource {
	launchURL := baseURL + "/lti/launch"
	switch contentType {
	case "graded":
		return []deeplink.Resource{
			deeplink.NewLTIResourceLinkWithGrade(
				"Go LTI Demo — Graded Activity",
				launchURL,
				deeplink.LineItemProperty{
					Label:        "Go LTI Demo Score",
					ScoreMaximum: 100,
					ResourceID:   "go-lti-demo",
					Tag:          "go-lti-demo",
				},
			),
		}
	default:
		return []deeplink.Resource{
			deeplink.NewLTIResourceLink("Go LTI Demo — Resource", launchURL),
		}
	}
}

func hasLearnerRole(roles []string) bool {
	for _, role := range roles {
		role = strings.ToLower(role)
		if strings.HasSuffix(role, "#learner") || strings.HasSuffix(role, "/learner") || role == "learner" {
			return true
		}
	}
	return false
}

// ── HTML Templates ────────────────────────────────────────────────────────────

var resourceTmpl = template.Must(template.New("resource").Funcs(template.FuncMap{
	"shortRole": func(role string) string {
		// Extract the last path segment from a full LTI role URI.
		if idx := strings.LastIndex(role, "#"); idx >= 0 {
			return role[idx+1:]
		}
		return role
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Go LTI Demo</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; background: #f5f7fa; color: #1a1a2e; }
  .container { max-width: 860px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
  .subtitle { color: #666; font-size: 0.9rem; margin-bottom: 2rem; }
  .card { background: #fff; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.25rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  .card h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: .05em; color: #555; margin: 0 0 1rem; }
  .kv { display: grid; grid-template-columns: 160px 1fr; gap: .35rem .75rem; font-size: .9rem; }
  .kv .key { font-weight: 600; color: #444; }
  .kv .val { word-break: break-all; }
  .badge { display: inline-block; background: #e8eaf6; color: #3949ab; border-radius: 4px; padding: 1px 8px; font-size: .8rem; margin: 2px; }
  .badge.green { background: #e8f5e9; color: #2e7d32; }
  .badge.red { background: #fce4ec; color: #c62828; }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th { text-align: left; padding: .5rem .75rem; background: #f0f2f5; font-weight: 600; }
  td { padding: .45rem .75rem; border-bottom: 1px solid #f0f2f5; }
  .error { color: #c62828; font-size: .9rem; }
  .score-box { display: flex; align-items: center; gap: 1rem; }
  .score-num { font-size: 2.5rem; font-weight: 700; color: #1a73e8; }
  .score-label { color: #555; font-size: .9rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Go LTI Demo</h1>
  <p class="subtitle">Launch ID: {{.LaunchID}}</p>

  <!-- Identity -->
  <div class="card">
    <h2>Identity</h2>
    <div class="kv">
      <span class="key">Subject</span><span class="val">{{.Subject}}</span>
      <span class="key">Name</span><span class="val">{{.Name}}</span>
      <span class="key">Email</span><span class="val">{{.Email}}</span>
      <span class="key">Roles</span>
      <span class="val">{{range .Roles}}<span class="badge">{{shortRole .}}</span>{{end}}</span>
    </div>
  </div>

  <!-- Context -->
  {{if .Context}}
  <div class="card">
    <h2>Course Context</h2>
    <div class="kv">
      <span class="key">ID</span><span class="val">{{.Context.ID}}</span>
      <span class="key">Title</span><span class="val">{{.Context.Title}}</span>
      <span class="key">Label</span><span class="val">{{.Context.Label}}</span>
      <span class="key">Types</span>
      <span class="val">{{range .Context.Type}}<span class="badge">{{.}}</span>{{end}}</span>
    </div>
  </div>
  {{end}}

  <!-- AGS -->
  <div class="card">
    <h2>Assignment &amp; Grade Services</h2>
    {{if .AGSResult}}
    <div class="score-box">
      <span class="score-num">{{.AGSResult.ScoreGiven}}/{{.AGSResult.ScoreMax}}</span>
      <span class="score-label">Score submitted to<br><strong>{{.AGSResult.LineitemLabel}}</strong></span>
    </div>
    {{else if .AGSNotice}}
    <p style="color:#666">{{.AGSNotice}}</p>
    {{else if .AGSError}}
    <p class="error">{{.AGSError}}</p>
    {{else}}
    <p style="color:#888">AGS not available in this launch.</p>
    {{end}}
  </div>

  <!-- NRPS -->
  <div class="card">
    <h2>Names &amp; Role Provisioning (Roster)</h2>
    {{if .NRPSError}}
    <p class="error">{{.NRPSError}}</p>
    {{else if .NRPSMembers}}
    <table>
      <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th></tr></thead>
      <tbody>
        {{range .NRPSMembers}}
        <tr>
          <td>{{.Name}}</td>
          <td>{{.Email}}</td>
          <td>{{range .Roles}}<span class="badge">{{shortRole .}}</span>{{end}}</td>
          <td><span class="badge {{if eq .Status "Active"}}green{{else}}red{{end}}">{{.Status}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <p style="color:#888">NRPS not available in this launch.</p>
    {{end}}
  </div>
</div>
</body>
</html>`))

var deepLinkPickerTmpl = template.Must(template.New("deeplink").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Select Content — Go LTI Demo</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; background: #f5f7fa; color: #1a1a2e; }
  .container { max-width: 520px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  .subtitle { color: #666; font-size: .9rem; margin-bottom: 2rem; }
  .option { background: #fff; border: 2px solid #e0e0e0; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1rem; cursor: pointer; transition: border-color .15s; }
  .option:has(input:checked) { border-color: #1a73e8; }
  .option label { cursor: pointer; display: flex; gap: 1rem; align-items: flex-start; }
  .option input[type=radio] { margin-top: .2rem; accent-color: #1a73e8; }
  .option .title { font-weight: 600; margin-bottom: .25rem; }
  .option .desc { font-size: .875rem; color: #555; }
  .btn { display: block; width: 100%; margin-top: 1.5rem; padding: .75rem; background: #1a73e8; color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
  .btn:hover { background: #1558b0; }
</style>
</head>
<body>
<div class="container">
  <h1>Select Content</h1>
  <p class="subtitle">Choose the type of resource to add to your course.</p>
  <form method="POST" action="/lti/deeplink/submit">
    <input type="hidden" name="launch_id" value="{{.LaunchID}}">

    <div class="option">
      <label>
        <input type="radio" name="content_type" value="basic" checked>
        <div>
          <div class="title">Basic Resource</div>
          <div class="desc">A plain LTI resource link. Launches the Go LTI Demo without a gradebook column.</div>
        </div>
      </label>
    </div>

    <div class="option">
      <label>
        <input type="radio" name="content_type" value="graded">
        <div>
          <div class="title">Graded Activity (100 pts)</div>
          <div class="desc">An LTI resource link with a gradebook line item. The tool will submit a score of 75/100 on each launch.</div>
        </div>
      </label>
    </div>

    <button type="submit" class="btn">Add to Course</button>
  </form>
</div>
</body>
</html>`))
