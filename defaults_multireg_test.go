package lti

import (
	"context"
	"errors"
	"testing"
)

// One issuer may host multiple registrations (e.g. cloud Canvas). The store
// must key by (issuer, client_id) and refuse ambiguous issuer-only lookups.
func TestMemoryStore_MultipleRegistrationsPerIssuer(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	iss := "https://canvas.instructure.com"

	if err := s.AddRegistration(ctx, Registration{Issuer: iss, ClientID: "client-a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRegistration(ctx, Registration{Issuer: iss, ClientID: "client-b"}); err != nil {
		t.Fatal(err)
	}

	reg, err := s.FindRegistration(ctx, iss, "client-b")
	if err != nil {
		t.Fatalf("FindRegistration: %v", err)
	}
	if reg.ClientID != "client-b" {
		t.Errorf("got client %q, want client-b", reg.ClientID)
	}

	if _, err := s.FindRegistration(ctx, iss, "client-c"); !errors.Is(err, ErrRegistrationNotFound) {
		t.Errorf("expected ErrRegistrationNotFound for unknown client, got %v", err)
	}

	// Issuer-only lookup is ambiguous with two registrations.
	if _, err := s.FindRegistration(ctx, iss, ""); err == nil {
		t.Error("expected error for ambiguous issuer-only lookup")
	}

	// With a single registration, issuer-only lookup still works.
	s2 := NewMemoryStore()
	_ = s2.AddRegistration(ctx, Registration{Issuer: iss, ClientID: "client-a"})
	reg, err = s2.FindRegistrationByIssuer(ctx, iss)
	if err != nil || reg.ClientID != "client-a" {
		t.Errorf("issuer-only lookup with single registration: reg=%v err=%v", reg, err)
	}
}
