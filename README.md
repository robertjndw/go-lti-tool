# go-lti

A Go SDK for [LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3) targeting tool implementations. Covers the full LTI Advantage surface: OIDC launch flow, Assignment & Grade Services (AGS), Names & Role Provisioning Services (NRPS), and Deep Linking.

## Features

- Framework-agnostic: exposes standard `http.Handler` — works with stdlib, chi, gin, echo, and any other router
- Core / Advantage split: import only the packages you need
- Typed LTI claims structs (no `map[string]interface{}`)
- Pluggable storage interfaces (bring your own DB, Redis, etc.)
- JWKS endpoint handler with multi-key support
- Full pagination support for AGS and NRPS

## Packages

| Package | Purpose |
|---|---|
| `github.com/robertjndw/go-lti` | Core types, interfaces, defaults |
| `.../login` | OIDC login initiation handler (step 1) |
| `.../launch` | JWT validation + launch middleware (step 2) |
| `.../jwks` | Serve the tool's public JWKS endpoint |
| `.../dynreg` | LTI Dynamic Registration handler |
| `.../advantage/ags` | Assignment & Grade Services |
| `.../advantage/nrps` | Names & Role Provisioning Services |
| `.../advantage/deeplink` | Deep Linking response builder |

## Quickstart

```go
import (
    lti "github.com/robertjndw/go-lti"
    "github.com/robertjndw/go-lti/jwks"
)

func main() {
    // Load your RSA private key (see Key Management section below).
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048) // dev only

    reg := &lti.Registration{
        Issuer:         "https://canvas.instructure.com",
        ClientID:       "your-client-id",
        KeySetURL:      "https://canvas.instructure.com/api/lti/security/jwks",
        AuthLoginURL:   "https://canvas.instructure.com/api/lti/authorize_redirect",
        AuthTokenURL:   "https://canvas.instructure.com/login/oauth2/token",
        ToolPrivateKey: privateKey,
        KID:            "key-1",
    }

    store := lti.NewMemoryStore() // swap for a DB-backed store in production
    _ = store.AddRegistration(context.Background(), *reg)
    _ = store.AddDeployment(context.Background(), reg.Issuer, lti.Deployment{DeploymentID: "your-deployment-id"})

    tool := lti.NewTool(
        lti.WithDataStore(store),
        lti.WithKeySet(jwks.FromRegistration(reg)),
    )

    mux := http.NewServeMux()
    mux.Handle("/oidc/login", tool.HandleLogin())
    mux.Handle("/lti/launch", tool.HandleLaunch(http.HandlerFunc(handleLaunch)))
    mux.Handle("/.well-known/jwks.json", tool.HandleJWKS())
    http.ListenAndServe(":8080", mux)
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
    ld, _ := lti.LaunchFromContext(r.Context())
    fmt.Fprintf(w, "Hello, %s!", ld.Claims.Name)
}
```

## LTI Advantage Services

### Assignment & Grade Services (AGS)

```go
import "github.com/robertjndw/go-lti/advantage/ags"

svc, err := ags.NewFromLaunch(ld)

// Find or create a line item.
li, err := svc.FindOrCreateLineitem(ctx, ags.Lineitem{
    Label: "Quiz 1", ScoreMaximum: 100,
})

// Submit a score.
err = svc.SubmitScore(ctx, li.ID, ags.Score{
    UserID:           ld.Claims.Subject,
    ScoreGiven:       85,
    ScoreMaximum:     100,
    ActivityProgress: ags.ActivityProgressCompleted,
    GradingProgress:  ags.GradingProgressFullyGraded,
    Timestamp:        time.Now().UTC().Format(time.RFC3339),
})
```

### Names & Role Provisioning Services (NRPS)

```go
import "github.com/robertjndw/go-lti/advantage/nrps"

svc, err := nrps.NewFromLaunch(ld)
members, err := svc.GetMembers(ctx) // pagination handled automatically
```

### Deep Linking

```go
import "github.com/robertjndw/go-lti/advantage/deeplink"

builder, err := deeplink.NewFromLaunch(ld)
html, err := builder.ResponseFormHTML([]deeplink.Resource{
    deeplink.NewLTIResourceLink("My Quiz", "https://tool.example.com/quiz/1"),
})
fmt.Fprint(w, html) // auto-submits to the platform
```

## Examples

See the [`examples/`](examples/) directory:

| Example | Description |
|---|---|
| [`basic-launch`](examples/basic-launch/) | Minimal OIDC launch (core only) |
| [`grades`](examples/grades/) | Submit grades via AGS |
| [`deep-linking`](examples/deep-linking/) | Deep linking content picker |
| [`complete`](examples/complete/) | Full LTI Advantage with all services |

## Key Management

Load your RSA private key from PEM:

```go
pemBytes, _ := os.ReadFile("private.pem")
key, err := lti.ParsePrivateKey(pemBytes)
```

Generate a new key (development only):

```go
key, _ := rsa.GenerateKey(rand.Reader, 2048)
```

## Production Checklist

- Replace `MemoryNonceStore` with a Redis/DB-backed implementation
- Replace `MemoryLaunchDataStore` with persistent storage
- Load private keys from a secret manager, not code
- Serve your JWKS endpoint over HTTPS
- Set appropriate cookie `SameSite` and `Secure` attributes for your deployment

## Commands

```bash
go build ./...          # build all packages
go test ./...           # run all tests
go vet ./...            # static analysis
```

## Reference

- [LTI 1.3 Core Spec](https://www.imsglobal.org/spec/lti/v1p3)
- [AGS Spec](https://www.imsglobal.org/spec/lti-ags/v2p0)
- [NRPS Spec](https://www.imsglobal.org/spec/lti-nrps/v2p0)
- [Deep Linking Spec](https://www.imsglobal.org/spec/lti-dl/v2p0)
- [Reference PHP Implementation](https://github.com/1EdTech/lti-1-3-php-library)
