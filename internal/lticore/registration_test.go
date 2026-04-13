package lticore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestEffectiveAuthServer(t *testing.T) {
	tests := []struct {
		name       string
		reg        Registration
		wantServer string
	}{
		{
			name: "AuthServer set",
			reg: Registration{
				AuthTokenURL: "https://platform.example.com/token",
				AuthServer:   "https://auth.example.com",
			},
			wantServer: "https://auth.example.com",
		},
		{
			name: "AuthServer empty falls back to AuthTokenURL",
			reg: Registration{
				AuthTokenURL: "https://platform.example.com/token",
				AuthServer:   "",
			},
			wantServer: "https://platform.example.com/token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.reg.EffectiveAuthServer(); got != tt.wantServer {
				t.Errorf("EffectiveAuthServer() = %q, want %q", got, tt.wantServer)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	t.Run("PKCS#1 RSA key", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}
		parsed, err := ParsePrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			t.Fatalf("ParsePrivateKey: %v", err)
		}
		if parsed.N.Cmp(priv.N) != 0 {
			t.Error("parsed key modulus does not match original")
		}
	})

	t.Run("PKCS#8 RSA key", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal PKCS8: %v", err)
		}
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		parsed, err := ParsePrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			t.Fatalf("ParsePrivateKey: %v", err)
		}
		if parsed.N.Cmp(priv.N) != 0 {
			t.Error("parsed key modulus does not match original")
		}
	})

	t.Run("empty PEM returns error", func(t *testing.T) {
		if _, err := ParsePrivateKey([]byte("not a pem block")); err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("unsupported block type returns error", func(t *testing.T) {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")}
		if _, err := ParsePrivateKey(pem.EncodeToMemory(block)); err == nil {
			t.Error("expected error for CERTIFICATE block, got nil")
		}
	})

	t.Run("PKCS#8 with invalid bytes returns error", func(t *testing.T) {
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-valid-der-structure")}
		if _, err := ParsePrivateKey(pem.EncodeToMemory(block)); err == nil {
			t.Error("expected error for invalid PKCS#8 bytes, got nil")
		}
	})
}
