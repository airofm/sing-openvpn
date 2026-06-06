package openvpn

import "testing"

func TestParseOVPNAuthUserPass(t *testing.T) {
	cfg, err := ParseOVPN([]byte(`
client
remote vpn.example.com 1194
proto udp
auth-user-pass
cipher AES-256-CBC
`))
	if err != nil {
		t.Fatalf("ParseOVPN returned error: %v", err)
	}
	if !cfg.AuthUserPass {
		t.Fatal("expected auth-user-pass to be parsed")
	}
	if cfg.Cipher != "AES-256-CBC" {
		t.Fatalf("expected cipher AES-256-CBC, got %q", cfg.Cipher)
	}
}
