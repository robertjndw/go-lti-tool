package lticore

import "testing"

func TestHasAGS(t *testing.T) {
	tests := []struct {
		name string
		ags  *AGSClaim
		want bool
	}{
		{"nil AGS", nil, false},
		{"AGS with Lineitems", &AGSClaim{Lineitems: "https://platform.example.com/lineitems"}, true},
		{"AGS with Lineitem", &AGSClaim{Lineitem: "https://platform.example.com/lineitem/1"}, true},
		{"AGS with both", &AGSClaim{Lineitems: "https://platform.example.com/lineitems", Lineitem: "https://platform.example.com/lineitem/1"}, true},
		{"AGS with neither", &AGSClaim{Scope: []string{ScopeAGSScore}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &Launch{Claims: &LTIClaims{AGS: tt.ags}}
			if got := ld.HasAGS(); got != tt.want {
				t.Errorf("HasAGS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasNRPS(t *testing.T) {
	tests := []struct {
		name string
		nrps *NRPSClaim
		want bool
	}{
		{"nil NRPS", nil, false},
		{"NRPS with URL", &NRPSClaim{ContextMembershipsURL: "https://platform.example.com/nrps"}, true},
		{"NRPS without URL", &NRPSClaim{ServiceVersions: []string{"2.0"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &Launch{Claims: &LTIClaims{NRPS: tt.nrps}}
			if got := ld.HasNRPS(); got != tt.want {
				t.Errorf("HasNRPS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasDeepLinking(t *testing.T) {
	tests := []struct {
		name     string
		settings *DeepLinkingSettings
		want     bool
	}{
		{"nil settings", nil, false},
		{"settings with return URL", &DeepLinkingSettings{DeepLinkReturnURL: "https://platform.example.com/dl-return"}, true},
		{"settings without return URL", &DeepLinkingSettings{AcceptTypes: []string{DeepLinkTypeLTIResourceLink}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &Launch{Claims: &LTIClaims{DeepLinkingSettings: tt.settings}}
			if got := ld.HasDeepLinking(); got != tt.want {
				t.Errorf("HasDeepLinking() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsResourceLaunch(t *testing.T) {
	tests := []struct {
		name        string
		messageType string
		want        bool
	}{
		{"resource link", MessageTypeResourceLink, true},
		{"deep linking", MessageTypeDeepLinking, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &Launch{Claims: &LTIClaims{MessageType: tt.messageType}}
			if got := ld.IsResourceLaunch(); got != tt.want {
				t.Errorf("IsResourceLaunch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDeepLinkLaunch(t *testing.T) {
	tests := []struct {
		name        string
		messageType string
		want        bool
	}{
		{"deep linking", MessageTypeDeepLinking, true},
		{"resource link", MessageTypeResourceLink, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &Launch{Claims: &LTIClaims{MessageType: tt.messageType}}
			if got := ld.IsDeepLinkLaunch(); got != tt.want {
				t.Errorf("IsDeepLinkLaunch() = %v, want %v", got, tt.want)
			}
		})
	}
}
