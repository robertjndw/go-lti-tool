package launch_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
	"github.com/robertjndw/go-lti-tool/launch"
)

// Two registrations under one issuer (e.g. cloud Canvas): the launch must
// resolve the registration matching the token's aud, not an arbitrary one.
func TestLaunch_MultiRegistrationIssuer_ResolvedByAud(t *testing.T) {
	platformKey := ltitest.NewKey(t)
	toolKey := ltitest.NewKey(t)
	jwksSrv := ltitest.NewJWKSServer(t, "platform-kid-1", platformKey)

	base := ltitest.NewRegistration(toolKey, jwksSrv.URL)
	regA := *base
	regA.ClientID = "client-a"
	regB := *base
	regB.ClientID = "client-b"

	ds := lti.NewMemoryStore()
	ctx := context.Background()
	if err := ds.AddRegistration(ctx, regA); err != nil {
		t.Fatal(err)
	}
	if err := ds.AddRegistration(ctx, regB); err != nil {
		t.Fatal(err)
	}
	if err := ds.AddDeployment(ctx, base.Issuer, lti.Deployment{DeploymentID: "deploy-1"}); err != nil {
		t.Fatal(err)
	}

	nonces := lti.NewMemoryNonceStore()
	cookies := ltitest.NewCookieHandler()
	cfg := launch.Config{
		Datastore:     ds,
		NonceStore:    nonces,
		LaunchStore:   lti.NewMemoryLaunchDataStore(),
		CookieHandler: cookies,
	}

	nonce := "nonce-multireg"
	if err := nonces.StoreNonce(ctx, nonce); err != nil {
		t.Fatal(err)
	}
	state := "state-multireg"
	cookies.SetRaw("lti1p3_"+state, state)

	claims := ltitest.DefaultClaims(&regB, nonce)
	claims["aud"] = "client-b"
	token := ltitest.SignJWT(t, platformKey, "platform-kid-1", claims)

	req := ltitest.MakeLaunchRequest(t, state, token)
	ld, err := launch.ValidateLaunch(ctx, cfg, req)
	if err != nil {
		t.Fatalf("launch failed: %v", err)
	}
	if ld.Registration.ClientID != "client-b" {
		t.Errorf("resolved registration %q, want client-b", ld.Registration.ClientID)
	}
}

// A configured Leeway must be honored: an exp slightly in the past passes with
// a generous leeway but fails with the default 60s.
func TestLaunch_ConfigurableLeeway(t *testing.T) {
	f := newFixture(t)

	makeToken := func(nonce string) string {
		return f.validToken(t, nonce, func(c jwt.MapClaims) {
			c["iat"] = time.Now().Add(-3 * time.Minute).Unix()
			c["exp"] = time.Now().Add(-90 * time.Second).Unix()
		})
	}

	f.storeNonce(t, "nonce-leeway-default")
	f.setStateCookie("state-leeway-default")
	if _, err := f.validate(t, "state-leeway-default", makeToken("nonce-leeway-default")); err == nil {
		t.Error("expected failure for exp 90s in the past with default leeway")
	}

	f.storeNonce(t, "nonce-leeway-custom")
	f.setStateCookie("state-leeway-custom")
	cfg := f.cfg()
	cfg.Leeway = 3 * time.Minute
	req := ltitest.MakeLaunchRequest(t, "state-leeway-custom", makeToken("nonce-leeway-custom"))
	if _, err := launch.ValidateLaunch(context.Background(), cfg, req); err != nil {
		t.Errorf("expected success with 3m leeway, got %v", err)
	}
}

// MaxTokenAge < 0 disables the iat age check entirely.
func TestLaunch_MaxTokenAge_Disabled(t *testing.T) {
	f := newFixture(t)
	f.storeNonce(t, "nonce-noage")
	f.setStateCookie("state-noage")

	token := f.validToken(t, "nonce-noage", func(c jwt.MapClaims) {
		c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
		c["exp"] = time.Now().Add(5 * time.Minute).Unix()
	})

	cfg := f.cfg()
	cfg.MaxTokenAge = -1
	req := ltitest.MakeLaunchRequest(t, "state-noage", token)
	if _, err := launch.ValidateLaunch(context.Background(), cfg, req); err != nil {
		t.Errorf("expected success with MaxTokenAge disabled, got %v", err)
	}
}
