package deeplink_test

import (
	"encoding/json"
	"testing"

	lti "github.com/robertjndw/go-lti-tool"
	"github.com/robertjndw/go-lti-tool/advantage/deeplink"
	"github.com/robertjndw/go-lti-tool/internal/ltitest"
)

// newFlexibleBuilder returns a Builder whose settings can be customized per
// test via the given DeepLinkingSettings overrides.
func newFlexibleBuilder(t *testing.T, settings *lti.DeepLinkingSettings) *deeplink.Builder {
	t.Helper()
	key := ltitest.NewKey(t)
	reg := &lti.Registration{
		Issuer:         "https://platform.example.com",
		ClientID:       "client-xyz",
		ToolPrivateKey: key,
		KID:            "tool-key-1",
	}
	return deeplink.New(reg, "deploy-1", settings)
}

func defaultSettings(acceptTypes, targets []string) *lti.DeepLinkingSettings {
	return &lti.DeepLinkingSettings{
		DeepLinkReturnURL:                 "https://platform.example.com/dl-return",
		AcceptTypes:                       acceptTypes,
		AcceptPresentationDocumentTargets: targets,
		AcceptMultiple:                    true,
	}
}

// ── Round-trip serialization of new DL 2.0 fields ────────────────────────────

func TestResource_HTML_RoundTrips(t *testing.T) {
	r := deeplink.Resource{Type: "html", HTML: "<p>hi</p>"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got map[string]any
	json.Unmarshal(data, &got) //nolint:errcheck
	if got["html"] != "<p>hi</p>" {
		t.Errorf("html = %v, want <p>hi</p>", got["html"])
	}
}

// Embed must serialize as an object with an "html" property, not a string.
func TestResource_Embed_SerializesAsObject(t *testing.T) {
	r := deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Embed: &deeplink.EmbedTarget{HTML: "<iframe></iframe>"}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got map[string]any
	json.Unmarshal(data, &got) //nolint:errcheck
	embed, ok := got["embed"].(map[string]any)
	if !ok {
		t.Fatalf("embed = %v (%T), want object", got["embed"], got["embed"])
	}
	if embed["html"] != "<iframe></iframe>" {
		t.Errorf("embed.html = %v, want <iframe></iframe>", embed["html"])
	}
}

func TestResource_MediaTypeWidthHeightExpiresAt_RoundTrip(t *testing.T) {
	r := deeplink.Resource{
		Type:      "file",
		URL:       "https://tool.example.com/f.pdf",
		MediaType: "application/pdf",
		ExpiresAt: "2026-01-01T00:00:00Z",
	}
	data, _ := json.Marshal(r)
	var got map[string]any
	json.Unmarshal(data, &got) //nolint:errcheck
	if got["mediaType"] != "application/pdf" {
		t.Errorf("mediaType = %v", got["mediaType"])
	}
	if got["expiresAt"] != "2026-01-01T00:00:00Z" {
		t.Errorf("expiresAt = %v", got["expiresAt"])
	}

	img := deeplink.Resource{Type: "image", URL: "https://tool.example.com/i.png", Width: 100, Height: 200}
	data2, _ := json.Marshal(img)
	var got2 map[string]any
	json.Unmarshal(data2, &got2) //nolint:errcheck
	if got2["width"] != float64(100) || got2["height"] != float64(200) {
		t.Errorf("width/height = %v/%v, want 100/200", got2["width"], got2["height"])
	}
}

func TestResource_AvailableSubmission_RoundTrip(t *testing.T) {
	r := deeplink.Resource{
		Type: "ltiResourceLink",
		Available: &deeplink.TimeWindow{
			StartDateTime: "2026-01-01T00:00:00Z",
			EndDateTime:   "2026-02-01T00:00:00Z",
		},
		Submission: &deeplink.TimeWindow{
			StartDateTime: "2026-01-10T00:00:00Z",
			EndDateTime:   "2026-01-20T00:00:00Z",
		},
	}
	data, _ := json.Marshal(r)
	var got map[string]any
	json.Unmarshal(data, &got) //nolint:errcheck
	avail, ok := got["available"].(map[string]any)
	if !ok || avail["startDateTime"] != "2026-01-01T00:00:00Z" {
		t.Errorf("available = %v", got["available"])
	}
	sub, ok := got["submission"].(map[string]any)
	if !ok || sub["endDateTime"] != "2026-01-20T00:00:00Z" {
		t.Errorf("submission = %v", got["submission"])
	}
}

func TestResource_IframeSrc_RoundTrip(t *testing.T) {
	r := deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Iframe: &deeplink.IframeTarget{Src: "https://tool.example.com/x-embed"}}
	data, _ := json.Marshal(r)
	var got map[string]any
	json.Unmarshal(data, &got) //nolint:errcheck
	iframe, ok := got["iframe"].(map[string]any)
	if !ok || iframe["src"] != "https://tool.example.com/x-embed" {
		t.Errorf("iframe.src = %v", got["iframe"])
	}
}

// ── accept_lineitem: absent / true / explicit false ──────────────────────────

func TestDeepLinkingSettings_AcceptLineItem_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		val  *bool
		want string
	}{
		{"absent", nil, ""},
		{"true", deeplink.Bool(true), "true"},
		{"false", deeplink.Bool(false), "false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := lti.DeepLinkingSettings{AcceptLineItem: c.val}
			data, _ := json.Marshal(s)
			var got map[string]any
			json.Unmarshal(data, &got) //nolint:errcheck
			v, present := got["accept_lineitem"]
			switch c.want {
			case "":
				if present {
					t.Errorf("accept_lineitem present (%v), want absent", v)
				}
			case "true":
				if v != true {
					t.Errorf("accept_lineitem = %v, want true", v)
				}
			case "false":
				if v != false {
					t.Errorf("accept_lineitem = %v, want false", v)
				}
			}
		})
	}
}

// ── Document-target parity ───────────────────────────────────────────────────

func TestValidate_WindowTarget_AcceptedAndRejected(t *testing.T) {
	link := func() deeplink.Resource {
		return deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Window: &deeplink.WindowTarget{}}
	}
	b := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"window"}))
	if _, err := b.ResponseJWT([]deeplink.Resource{link()}); err != nil {
		t.Errorf("expected window target accepted, got %v", err)
	}

	bNoWindow := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"iframe"}))
	if _, err := bNoWindow.ResponseJWT([]deeplink.Resource{link()}); err == nil {
		t.Error("expected rejection: window not in accept_presentation_document_targets")
	}
}

func TestValidate_IframeTarget_AcceptedAndRejected(t *testing.T) {
	link := func() deeplink.Resource {
		return deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Iframe: &deeplink.IframeTarget{Src: "https://tool.example.com/x-embed"}}
	}
	b := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"iframe"}))
	if _, err := b.ResponseJWT([]deeplink.Resource{link()}); err != nil {
		t.Errorf("expected iframe target accepted, got %v", err)
	}

	bNoIframe := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"window"}))
	if _, err := bNoIframe.ResponseJWT([]deeplink.Resource{link()}); err == nil {
		t.Error("expected rejection: iframe not in accept_presentation_document_targets")
	}
}

func TestValidate_EmbedTarget_AcceptedAndRejected(t *testing.T) {
	link := func() deeplink.Resource {
		return deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Embed: &deeplink.EmbedTarget{HTML: "<x/>"}}
	}
	b := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"embed"}))
	if _, err := b.ResponseJWT([]deeplink.Resource{link()}); err != nil {
		t.Errorf("expected embed target accepted, got %v", err)
	}

	bNoEmbed := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"window"}))
	if _, err := bNoEmbed.ResponseJWT([]deeplink.Resource{link()}); err == nil {
		t.Error("expected rejection: embed not in accept_presentation_document_targets")
	}
}

// embed does not apply to ltiResourceLink per the DL 2.0 schema.
func TestValidate_EmbedOnLTIResourceLink_Rejected(t *testing.T) {
	b := newFlexibleBuilder(t, defaultSettings([]string{"ltiResourceLink"}, []string{"embed"}))
	r := deeplink.Resource{Type: "ltiResourceLink", Embed: &deeplink.EmbedTarget{HTML: "<x/>"}}
	if _, err := b.ResponseJWT([]deeplink.Resource{r}); err == nil {
		t.Error("expected rejection: embed does not apply to ltiResourceLink")
	}
}

// ── accept_media_types ────────────────────────────────────────────────────────

func TestValidate_AcceptMediaTypes_WildcardAndMismatch(t *testing.T) {
	settings := defaultSettings([]string{"file"}, nil)
	settings.AcceptMediaTypes = "image/*,application/pdf"
	b := newFlexibleBuilder(t, settings)

	png := deeplink.Resource{Type: "file", URL: "https://tool.example.com/f.png", MediaType: "image/png"}
	if _, err := b.ResponseJWT([]deeplink.Resource{png}); err != nil {
		t.Errorf("expected image/png accepted via wildcard, got %v", err)
	}

	video := deeplink.Resource{Type: "file", URL: "https://tool.example.com/f.mp4", MediaType: "video/mp4"}
	if _, err := b.ResponseJWT([]deeplink.Resource{video}); err == nil {
		t.Error("expected video/mp4 rejected: not in accept_media_types")
	}

	noMediaType := deeplink.Resource{Type: "file", URL: "https://tool.example.com/f"}
	if _, err := b.ResponseJWT([]deeplink.Resource{noMediaType}); err != nil {
		t.Errorf("expected empty MediaType to pass (no constraint to check), got %v", err)
	}
}

// ── Type-specific required fields ────────────────────────────────────────────

func TestValidate_HTMLWithoutHTML_Rejected(t *testing.T) {
	b := newFlexibleBuilder(t, defaultSettings([]string{"html"}, nil))
	r := deeplink.Resource{Type: "html"}
	if _, err := b.ResponseJWT([]deeplink.Resource{r}); err == nil {
		t.Error("expected rejection: html item without HTML")
	}
}

func TestValidate_LinkWithoutURL_Rejected(t *testing.T) {
	b := newFlexibleBuilder(t, defaultSettings([]string{"link"}, nil))
	r := deeplink.Resource{Type: "link"}
	if _, err := b.ResponseJWT([]deeplink.Resource{r}); err == nil {
		t.Error("expected rejection: link item without URL")
	}
}

func TestValidate_LTIResourceLinkWithoutURL_Accepted(t *testing.T) {
	b := newFlexibleBuilder(t, defaultSettings([]string{"ltiResourceLink"}, nil))
	r := deeplink.Resource{Type: "ltiResourceLink"}
	if _, err := b.ResponseJWT([]deeplink.Resource{r}); err != nil {
		t.Errorf("expected ltiResourceLink without URL accepted, got %v", err)
	}
}

func TestValidate_LinkIframeWithoutSrc_Rejected(t *testing.T) {
	b := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"iframe"}))
	r := deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Iframe: &deeplink.IframeTarget{}}
	if _, err := b.ResponseJWT([]deeplink.Resource{r}); err == nil {
		t.Error("expected rejection: link iframe without Src")
	}
}

func TestValidate_EmbedWithEmptyHTML_Rejected(t *testing.T) {
	b := newFlexibleBuilder(t, defaultSettings([]string{"link"}, []string{"embed"}))
	r := deeplink.Resource{Type: "link", URL: "https://tool.example.com/x", Embed: &deeplink.EmbedTarget{}}
	if _, err := b.ResponseJWT([]deeplink.Resource{r}); err == nil {
		t.Error("expected rejection: embed with empty HTML")
	}
}

// ── accept_lineitem gating ────────────────────────────────────────────────────

func TestValidate_LineItem_RejectedOnlyWhenExplicitFalse(t *testing.T) {
	withLineItem := func() deeplink.Resource {
		return deeplink.Resource{
			Type: "ltiResourceLink",
			LineItem: &deeplink.LineItemProperty{
				Label:        "Quiz 1",
				ScoreMaximum: 100,
			},
		}
	}

	t.Run("absent accept_lineitem allows LineItem", func(t *testing.T) {
		b := newFlexibleBuilder(t, defaultSettings([]string{"ltiResourceLink"}, nil))
		if _, err := b.ResponseJWT([]deeplink.Resource{withLineItem()}); err != nil {
			t.Errorf("expected LineItem accepted when accept_lineitem absent, got %v", err)
		}
	})

	t.Run("accept_lineitem true allows LineItem", func(t *testing.T) {
		settings := defaultSettings([]string{"ltiResourceLink"}, nil)
		settings.AcceptLineItem = deeplink.Bool(true)
		b := newFlexibleBuilder(t, settings)
		if _, err := b.ResponseJWT([]deeplink.Resource{withLineItem()}); err != nil {
			t.Errorf("expected LineItem accepted when accept_lineitem true, got %v", err)
		}
	})

	t.Run("accept_lineitem false rejects LineItem", func(t *testing.T) {
		settings := defaultSettings([]string{"ltiResourceLink"}, nil)
		settings.AcceptLineItem = deeplink.Bool(false)
		b := newFlexibleBuilder(t, settings)
		if _, err := b.ResponseJWT([]deeplink.Resource{withLineItem()}); err == nil {
			t.Error("expected LineItem rejected when accept_lineitem explicit false")
		}
	})
}
