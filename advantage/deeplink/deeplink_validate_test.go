package deeplink_test

import (
	"strings"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/deeplink"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
)

// newRestrictiveBuilder returns a Builder whose settings only accept a single
// ltiResourceLink item.
func newRestrictiveBuilder(t *testing.T) *deeplink.Builder {
	t.Helper()
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	settings := &lti.DeepLinkingSettings{
		DeepLinkReturnURL:                 "https://platform.example.com/dl-return",
		AcceptTypes:                       []string{"ltiResourceLink"},
		AcceptPresentationDocumentTargets: []string{"iframe"},
		AcceptMultiple:                    false,
	}
	return deeplink.New(reg, "deploy-1", settings)
}

// DL spec: content item types must be within the platform's accept_types.
func TestResponseJWT_TypeNotAccepted_Rejected(t *testing.T) {
	b := newRestrictiveBuilder(t)
	_, err := b.ResponseJWT([]deeplink.Resource{{Type: "file", Title: "notes.pdf"}})
	if err == nil {
		t.Error("expected error for type outside accept_types")
	}
}

// DL spec: multiple items must be rejected when accept_multiple is false.
func TestResponseJWT_MultipleNotAccepted_Rejected(t *testing.T) {
	b := newRestrictiveBuilder(t)
	_, err := b.ResponseJWT([]deeplink.Resource{
		deeplink.NewLTIResourceLink("Quiz 1", "https://tool.example.com/q1"),
		deeplink.NewLTIResourceLink("Quiz 2", "https://tool.example.com/q2"),
	})
	if err == nil {
		t.Error("expected error for multiple items with accept_multiple=false")
	}
}

// DL spec: optional msg/errormsg claims are included when set.
func TestResponseJWT_MsgClaims_Included(t *testing.T) {
	b := newRestrictiveBuilder(t)
	b.Msg = "1 item added"
	b.ErrorLog = "minor issue"
	tok, err := b.ResponseJWT([]deeplink.Resource{
		deeplink.NewLTIResourceLink("Quiz 1", "https://tool.example.com/q1"),
	})
	if err != nil {
		t.Fatalf("ResponseJWT failed: %v", err)
	}
	if !strings.Contains(tok, ".") {
		t.Fatal("expected a JWT")
	}
	claims, _ := parseResponseJWT(t, tok)
	if claims[lti.ClaimPrefixDL+"msg"] != "1 item added" {
		t.Errorf("msg claim missing, got %v", claims[lti.ClaimPrefixDL+"msg"])
	}
	if claims[lti.ClaimPrefixDL+"errorlog"] != "minor issue" {
		t.Errorf("errorlog claim missing, got %v", claims[lti.ClaimPrefixDL+"errorlog"])
	}
}
