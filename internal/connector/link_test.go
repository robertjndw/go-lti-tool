package connector_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/robertjndw/go-lti-tool/internal/connector"
)

func makeResponse(reqURL string, links ...string) *connector.ServiceResponse {
	h := http.Header{}
	for _, l := range links {
		h.Add("Link", l)
	}
	u, _ := url.Parse(reqURL)
	return &connector.ServiceResponse{Headers: h, RequestURL: u}
}

// Canvas packs all rels into a single comma-separated Link header.
func TestLinkURL_MultipleRelsInOneHeader(t *testing.T) {
	sr := makeResponse("https://p.example.com/lineitems",
		`<https://p.example.com/page1>; rel="first", <https://p.example.com/page3>; rel="next", <https://p.example.com/page9>; rel="last"`)
	if got := sr.NextPageURL(); got != "https://p.example.com/page3" {
		t.Errorf("NextPageURL = %q", got)
	}
}

// Multiple Link headers must all be scanned, not just the first.
func TestLinkURL_MultipleHeaders(t *testing.T) {
	sr := makeResponse("https://p.example.com/m",
		`<https://p.example.com/first>; rel="first"`,
		`<https://p.example.com/diff>; rel="differences"`)
	if got := sr.LinkURL("differences"); got != "https://p.example.com/diff" {
		t.Errorf("LinkURL(differences) = %q", got)
	}
}

// Unquoted rel parameters (rel=next) must be accepted.
func TestLinkURL_UnquotedRel(t *testing.T) {
	sr := makeResponse("https://p.example.com/m", `<https://p.example.com/n>; rel=next`)
	if got := sr.NextPageURL(); got != "https://p.example.com/n" {
		t.Errorf("NextPageURL = %q", got)
	}
}

// rel values that merely share a prefix must not match.
func TestLinkURL_PrefixDoesNotMatch(t *testing.T) {
	sr := makeResponse("https://p.example.com/m", `<https://p.example.com/n>; rel="nextish"`)
	if got := sr.NextPageURL(); got != "" {
		t.Errorf("NextPageURL = %q, want empty", got)
	}
}

// Relative Link URLs must be resolved against the request URL.
func TestLinkURL_RelativeResolved(t *testing.T) {
	sr := makeResponse("https://p.example.com/api/memberships?page=1", `</api/memberships?page=2>; rel="next"`)
	if got := sr.NextPageURL(); got != "https://p.example.com/api/memberships?page=2" {
		t.Errorf("NextPageURL = %q", got)
	}
}
