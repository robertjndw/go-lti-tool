package lticore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// --- MemoryStore ---

func TestMemoryStore_RegistrationRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	reg := Registration{
		Issuer:   "https://platform.example.com",
		ClientID: "client-123",
	}
	if err := store.AddRegistration(ctx, reg); err != nil {
		t.Fatalf("AddRegistration: %v", err)
	}

	got, err := store.FindRegistrationByIssuer(ctx, reg.Issuer)
	if err != nil {
		t.Fatalf("FindRegistrationByIssuer: %v", err)
	}
	if got.ClientID != reg.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, reg.ClientID)
	}
}

func TestMemoryStore_RegistrationNotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.FindRegistrationByIssuer(context.Background(), "https://unknown.example.com")
	if !errors.Is(err, ErrRegistrationNotFound) {
		t.Errorf("got %v, want ErrRegistrationNotFound", err)
	}
}

func TestMemoryStore_DeploymentRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	dep := Deployment{DeploymentID: "deploy-1"}
	issuer := "https://platform.example.com"
	if err := store.AddDeployment(ctx, issuer, dep); err != nil {
		t.Fatalf("AddDeployment: %v", err)
	}

	got, err := store.FindDeployment(ctx, issuer, dep.DeploymentID)
	if err != nil {
		t.Fatalf("FindDeployment: %v", err)
	}
	if got.DeploymentID != dep.DeploymentID {
		t.Errorf("DeploymentID = %q, want %q", got.DeploymentID, dep.DeploymentID)
	}
}

func TestMemoryStore_DeploymentNotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.FindDeployment(context.Background(), "https://platform.example.com", "unknown-deploy")
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Errorf("got %v, want ErrDeploymentNotFound", err)
	}
}

func TestMemoryStore_DeploymentIsolatedByIssuer(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	store.AddDeployment(ctx, "https://issuer-a.example.com", Deployment{DeploymentID: "deploy-1"}) //nolint:errcheck
	// Same deployment ID under a different issuer must not be found.
	_, err := store.FindDeployment(ctx, "https://issuer-b.example.com", "deploy-1")
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Errorf("got %v, want ErrDeploymentNotFound", err)
	}
}

// --- MemoryNonceStore ---

func TestMemoryNonceStore_StoreAndCheck(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryNonceStore()

	if err := store.StoreNonce(ctx, "nonce-abc"); err != nil {
		t.Fatalf("StoreNonce: %v", err)
	}

	ok, err := store.CheckNonce(ctx, "nonce-abc")
	if err != nil {
		t.Fatalf("CheckNonce: %v", err)
	}
	if !ok {
		t.Error("CheckNonce = false, want true")
	}
}

func TestMemoryNonceStore_OneTimeUse(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryNonceStore()

	store.StoreNonce(ctx, "nonce-abc") //nolint:errcheck

	first, _ := store.CheckNonce(ctx, "nonce-abc")
	if !first {
		t.Fatal("first CheckNonce should return true")
	}
	second, _ := store.CheckNonce(ctx, "nonce-abc")
	if second {
		t.Error("second CheckNonce should return false (one-time use)")
	}
}

func TestMemoryNonceStore_UnknownNonce(t *testing.T) {
	store := NewMemoryNonceStore()
	ok, err := store.CheckNonce(context.Background(), "never-stored")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("CheckNonce = true for unknown nonce, want false")
	}
}

func TestMemoryNonceStore_ExpiredNonce(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryNonceStore()
	store.ttl = 1 * time.Millisecond // access unexported field from same package

	store.StoreNonce(ctx, "expired-nonce") //nolint:errcheck
	time.Sleep(5 * time.Millisecond)

	ok, err := store.CheckNonce(ctx, "expired-nonce")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("CheckNonce = true for expired nonce, want false")
	}
}

// --- MemoryLaunchDataStore ---

func TestMemoryLaunchDataStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryLaunchDataStore()

	data := &LaunchData{
		LaunchID: "launch-1",
		Claims:   &LTIClaims{Subject: "user-42"},
	}
	if err := store.CacheLaunchData(ctx, "launch-1", data); err != nil {
		t.Fatalf("CacheLaunchData: %v", err)
	}

	got, err := store.GetLaunchData(ctx, "launch-1")
	if err != nil {
		t.Fatalf("GetLaunchData: %v", err)
	}
	if got.Claims.Subject != "user-42" {
		t.Errorf("Subject = %q, want %q", got.Claims.Subject, "user-42")
	}
}

func TestMemoryLaunchDataStore_NotFound(t *testing.T) {
	store := NewMemoryLaunchDataStore()
	_, err := store.GetLaunchData(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrLaunchNotFound) {
		t.Errorf("got %v, want ErrLaunchNotFound", err)
	}
}

func TestMemoryLaunchDataStore_OverwriteEntry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryLaunchDataStore()

	store.CacheLaunchData(ctx, "launch-1", &LaunchData{Claims: &LTIClaims{Subject: "original"}}) //nolint:errcheck
	store.CacheLaunchData(ctx, "launch-1", &LaunchData{Claims: &LTIClaims{Subject: "updated"}})  //nolint:errcheck

	got, _ := store.GetLaunchData(ctx, "launch-1")
	if got.Claims.Subject != "updated" {
		t.Errorf("Subject = %q, want %q", got.Claims.Subject, "updated")
	}
}
