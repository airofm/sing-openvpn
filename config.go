package openvpn

import (
	"net/netip"

	C "github.com/airofm/sing-openvpn/internal/constant"
)

type Remote struct {
	Server        string
	Port          int
	UDP           bool
	ProtoExplicit bool // indicates if UDP/TCP was explicitly set on this remote line
}

type Config struct {
	Remotes     []Remote
	TLSCert     string
	TLSKey      string
	CACert      string
	TLSCrypt    string
	Cipher      string
	AuthNoCache bool
	Username    string
	Password    string
	IP          netip.Addr
	Mask        netip.Prefix
	MTU         int
	Dialer      C.Dialer
}
