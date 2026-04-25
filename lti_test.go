package lti_test

import (
	"context"
	"encoding/json"
	"testing"

	lti "github.com/robertjndw/go-lti"
)

// ── Audience JSON handling ────────────────────────────────────────────────────

// Audience must unmarshal a single string as a one-element slice.
func TestAudience_UnmarshalSingleString(t *testing.T) {
	var a lti.Audience
	if err := json.Unmarshal([]byte(`"client-123"`), &a); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(a) != 1 || a[0] != "client-123" {
		t.Errorf("Audience = %v, want [client-123]", a)
	}
}

// Audience must unmarshal a JSON array into the corresponding slice.
func TestAudience_UnmarshalArray(t *testing.T) {
	var a lti.Audience
	if err := json.Unmarshal([]byte(`["client-a","client-b"]`), &a); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(a) != 2 || a[0] != "client-a" || a[1] != "client-b" {
		t.Errorf("Audience = %v, want [client-a client-b]", a)
	}
}

// Audience.Contains must return true for a member and false for a non-member.
func TestAudience_Contains(t *testing.T) {
	a := lti.Audience{"client-a", "client-b"}
	if !a.Contains("client-a") {
		t.Error("Contains(client-a) must return true")
	}
	if !a.Contains("client-b") {
		t.Error("Contains(client-b) must return true")
	}
	if a.Contains("client-c") {
		t.Error("Contains(client-c) must return false")
	}
}

// MarshalJSON must produce a JSON array even for a single-element Audience.
func TestAudience_MarshalJSON(t *testing.T) {
	a := lti.Audience{"client-123"}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var got []string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal of marshalled audience failed: %v", err)
	}
	if len(got) != 1 || got[0] != "client-123" {
		t.Errorf("marshalled = %s, want [\"client-123\"]", data)
	}
}

// ── LaunchData helpers ────────────────────────────────────────────────────────

func TestLaunchData_HasAGS_True(t *testing.T) {
	ld := &lti.Launch{
		Claims: &lti.LTIClaims{
			AGS: &lti.AGSClaim{Lineitems: "https://platform.example.com/lineitems"},
		},
	}
	if !ld.HasAGS() {
		t.Error("HasAGS must return true when AGS claim has Lineitems URL")
	}
}

func TestLaunchData_HasAGS_False_WhenNil(t *testing.T) {
	ld := &lti.Launch{Claims: &lti.LTIClaims{}}
	if ld.HasAGS() {
		t.Error("HasAGS must return false when AGS claim is nil")
	}
}

// HasAGS must also return true when only the single lineitem URL is set (no lineitems container).
// This is a valid AGS scenario for resource-link-scoped launches.
func TestLaunchData_HasAGS_True_WhenOnlyLineitemSet(t *testing.T) {
	ld := &lti.Launch{
		Claims: &lti.LTIClaims{
			AGS: &lti.AGSClaim{Lineitem: "https://platform.example.com/lineitems/1"},
		},
	}
	if !ld.HasAGS() {
		t.Error("HasAGS must return true when AGS claim has Lineitem URL (single item, no container)")
	}
}

func TestLaunchData_HasNRPS_True(t *testing.T) {
	ld := &lti.Launch{
		Claims: &lti.LTIClaims{
			NRPS: &lti.NRPSClaim{ContextMembershipsURL: "https://platform.example.com/memberships"},
		},
	}
	if !ld.HasNRPS() {
		t.Error("HasNRPS must return true when NRPS claim has URL")
	}
}

func TestLaunchData_HasNRPS_False_WhenNil(t *testing.T) {
	ld := &lti.Launch{Claims: &lti.LTIClaims{}}
	if ld.HasNRPS() {
		t.Error("HasNRPS must return false when NRPS claim is nil")
	}
}

func TestLaunchData_HasDeepLinking_True(t *testing.T) {
	ld := &lti.Launch{
		Claims: &lti.LTIClaims{
			DeepLinkingSettings: &lti.DeepLinkingSettings{
				DeepLinkReturnURL: "https://platform.example.com/dl-return",
			},
		},
	}
	if !ld.HasDeepLinking() {
		t.Error("HasDeepLinking must return true when DeepLinkingSettings has return URL")
	}
}

func TestLaunchData_IsResourceLaunch(t *testing.T) {
	ld := &lti.Launch{Claims: &lti.LTIClaims{MessageType: lti.MessageTypeResourceLink}}
	if !ld.IsResourceLaunch() {
		t.Error("IsResourceLaunch must return true for LtiResourceLinkRequest")
	}
	if ld.IsDeepLinkLaunch() {
		t.Error("IsDeepLinkLaunch must return false for LtiResourceLinkRequest")
	}
}

func TestLaunchData_IsDeepLinkLaunch(t *testing.T) {
	ld := &lti.Launch{Claims: &lti.LTIClaims{MessageType: lti.MessageTypeDeepLinking}}
	if !ld.IsDeepLinkLaunch() {
		t.Error("IsDeepLinkLaunch must return true for LtiDeepLinkingRequest")
	}
	if ld.IsResourceLaunch() {
		t.Error("IsResourceLaunch must return false for LtiDeepLinkingRequest")
	}
}

// ── MemoryNonceStore ──────────────────────────────────────────────────────────

// StoreNonce then CheckNonce must succeed once.
func TestMemoryNonceStore_StoreAndCheck(t *testing.T) {
	s := lti.NewMemoryNonceStore()
	ctx := context.Background()

	if err := s.StoreNonce(ctx, "nonce-1"); err != nil {
		t.Fatalf("StoreNonce failed: %v", err)
	}
	ok, err := s.CheckNonce(ctx, "nonce-1")
	if err != nil {
		t.Fatalf("CheckNonce failed: %v", err)
	}
	if !ok {
		t.Error("CheckNonce must return true for a stored nonce")
	}
}

// CheckNonce must consume the nonce — a second check must return false.
func TestMemoryNonceStore_NonceIsConsumed(t *testing.T) {
	s := lti.NewMemoryNonceStore()
	ctx := context.Background()

	s.StoreNonce(ctx, "nonce-once") //nolint:errcheck
	s.CheckNonce(ctx, "nonce-once") //nolint:errcheck
	ok, _ := s.CheckNonce(ctx, "nonce-once")
	if ok {
		t.Error("CheckNonce must return false on second use (nonce replay)")
	}
}

// CheckNonce must return false for a nonce that was never stored.
func TestMemoryNonceStore_UnknownNonce(t *testing.T) {
	s := lti.NewMemoryNonceStore()
	ok, err := s.CheckNonce(context.Background(), "never-stored")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("CheckNonce must return false for unknown nonce")
	}
}

// ── MemoryLaunchDataStore ─────────────────────────────────────────────────────

// CacheLaunchData then GetLaunchData must return the same data.
func TestMemoryLaunchDataStore_CacheAndGet(t *testing.T) {
	store := lti.NewMemoryLaunchDataStore()
	ctx := context.Background()
	ld := &lti.Launch{
		LaunchID: "launch-42",
		Claims:   &lti.LTIClaims{Subject: "user-1"},
	}

	if err := store.CacheLaunchData(ctx, "launch-42", ld); err != nil {
		t.Fatalf("CacheLaunchData failed: %v", err)
	}
	got, err := store.GetLaunchData(ctx, "launch-42")
	if err != nil {
		t.Fatalf("GetLaunchData failed: %v", err)
	}
	if got.LaunchID != "launch-42" {
		t.Errorf("LaunchID = %q, want launch-42", got.LaunchID)
	}
}

// GetLaunchData must return ErrLaunchNotFound for an unknown ID.
func TestMemoryLaunchDataStore_UnknownID(t *testing.T) {
	store := lti.NewMemoryLaunchDataStore()
	_, err := store.GetLaunchData(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected ErrLaunchNotFound, got nil")
	}
}
