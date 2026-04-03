package openvpn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airofm/sing-openvpn/internal/crypto"
	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/airofm/sing-openvpn/internal/packet"
	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Client struct {
	cfg        *Config
	conn       net.Conn
	isUDPConn  bool
	localSID   uint64
	remoteSID  uint64
	peerID     uint32
	packetID   uint32
	acks       []uint32
	mutex      sync.Mutex
	ackWaiters sync.Map // uint32 -> chan struct{}

	lastActivity int64 // unix timestamp in seconds

	tlsConn          *tls.Conn
	controlConn      *ControlConn
	handshakeStarted chan struct{}
	tlsCrypt         *crypto.TLSCrypt
	errChan          chan error

	// Key material from key_method_2 exchange (for PRF key derivation)
	clientPreMaster []byte // 48 bytes
	clientRandom1   []byte // 32 bytes
	clientRandom2   []byte // 32 bytes
	serverRandom1   []byte // 32 bytes
	serverRandom2   []byte // 32 bytes

	routeDelay int // seconds to wait after connection before routing is ready (from route-delay push)

	tunDevice wireguard.Device
	cipher    crypto.DataCipher

	ctx    context.Context
	cancel context.CancelFunc
}

// NewClient parses the .ovpn configuration content and initializes a new Client.
func NewClient(ovpnContent []byte, username, password string, dialer Dialer) (*Client, error) {
	cfg, err := ParseOVPN(ovpnContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ovpn content: %w", err)
	}
	cfg.Username = username
	cfg.Password = password
	cfg.Dialer = dialer

	ctx, cancel := context.WithCancel(context.Background())

	// Generate random Session ID
	var sid uint64
	binary.Read(rand.Reader, binary.BigEndian, &sid)

	c := &Client{
		cfg:              cfg,
		localSID:         sid,
		handshakeStarted: make(chan struct{}, 1),
		errChan:          make(chan error, 10),
		ctx:              ctx,
		cancel:           cancel,
	}
	c.controlConn = NewControlConn(c)

	if cfg.TLSCrypt != "" {
		tc, err := crypto.NewTLSCrypt(cfg.TLSCrypt)
		if err == nil {
			c.tlsCrypt = tc
		} else {
			log.Warnln("[OpenVPN] Failed to parse tls-crypt key: %v", err)
		}
	}

	return c, nil
}

func (c *Client) Dial(ctx context.Context) error {
	var lastErr error
	for _, remote := range c.cfg.Remotes {
		network := "udp"
		if !remote.UDP {
			network = "tcp"
		}

		// Resolve host manually to avoid net.DefaultResolver panic
		var ip netip.Addr
		var err error
		addrs, lookupErr := net.DefaultResolver.LookupHost(ctx, remote.Server)
		if lookupErr != nil || len(addrs) == 0 {
			err = fmt.Errorf("DNS lookup failed: %v", lookupErr)
		} else {
			ip, err = netip.ParseAddr(addrs[0])
		}
		if err != nil {
			log.Warnln("[OpenVPN] Failed to resolve %s: %v", remote.Server, err)
			lastErr = err
			continue
		}

		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", remote.Port))
		log.Infoln("[OpenVPN] Trying to connect to %s (%s, server: %s)", addr, network, remote.Server)

		var conn net.Conn
		if c.cfg.Dialer != nil {
			conn, err = c.cfg.Dialer.DialContext(ctx, network, addr)
		} else {
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, err = dialer.DialContext(ctx, network, addr)
		}

		if err != nil {
			log.Warnln("[OpenVPN] Failed to connect to %s: %v", addr, err)
			lastErr = err
			continue
		}

		c.conn = conn
		c.isUDPConn = remote.UDP

		// Start the read loop (runs for the lifetime of the connection)
		go c.readLoop()

		// Try handshake
		err = c.performHandshake(ctx)
		if err != nil {
			log.Warnln("[OpenVPN] Handshake failed with %s: %v", addr, err)
			c.cancel() // Stop the readLoop
			c.conn.Close()
			c.conn = nil
			// Re-create context for next attempt
			c.ctx, c.cancel = context.WithCancel(context.Background())
			lastErr = err
			continue
		}

		// Handshake successful, readLoop continues running
		break
	}

	if c.conn == nil {
		if lastErr != nil {
			return fmt.Errorf("failed to connect to any remote: %w", lastErr)
		}
		return fmt.Errorf("no remotes configured")
	}

	// 6. Initialize TUN device with negotiated parameters
	mtu := c.cfg.MTU
	if mtu == 0 {
		mtu = 1500
	}

	// Build TUN prefix from pushed IP.
	// parsePushReply sets cfg.Mask to <ip>/32 (point-to-point tun mode).
	// Fall back to /24 if Mask was never set (e.g. server did not push ifconfig).
	var prefixes []netip.Prefix
	if c.cfg.Mask.IsValid() {
		prefixes = []netip.Prefix{c.cfg.Mask}
	} else {
		prefixes = []netip.Prefix{netip.PrefixFrom(c.cfg.IP, 24)}
	}
	log.Infoln("[OpenVPN] TUN prefixes: %v", prefixes)

	var err error
	c.tunDevice, err = wireguard.NewStackDevice(prefixes, uint32(mtu))
	if err != nil {
		return err
	}

	if err := c.tunDevice.Start(); err != nil {
		return err
	}

	// Start TUN loops — route-delay wait is handled inside tunReadLoop
	go c.tunReadLoop()
	go c.pingLoop()

	return nil
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.tunDevice == nil {
		return nil, fmt.Errorf("openvpn client not fully initialized")
	}
	saddr := M.ParseSocksaddr(address)
	if !saddr.IsIP() {
		return nil, fmt.Errorf("address %s must be an IP address", address)
	}
	return c.tunDevice.DialContext(ctx, network, saddr.Unwrap())
}

func (c *Client) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if c.tunDevice == nil {
		return nil, fmt.Errorf("openvpn client not fully initialized")
	}
	saddr := M.ParseSocksaddr(address)
	if !saddr.IsIP() {
		return nil, fmt.Errorf("address %s must be an IP address", address)
	}
	return c.tunDevice.ListenPacket(ctx, saddr.Unwrap())
}

func (c *Client) isUDP() bool {
	return c.isUDPConn
}

func (c *Client) getNextPacketID() uint32 {
	return atomic.AddUint32(&c.packetID, 1) - 1
}

func (c *Client) updateActivity() {
	atomic.StoreInt64(&c.lastActivity, time.Now().Unix())
}

func (c *Client) pingLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	pingMagic := []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
	c.updateActivity() // Initialize activity
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			// Check for timeout (e.g., 60 seconds without activity)
			last := atomic.LoadInt64(&c.lastActivity)
			if time.Now().Unix()-last > 60 {
				log.Warnln("[OpenVPN] Ping timeout: no data received for 60 seconds, closing connection")
				c.errChan <- fmt.Errorf("ping timeout")
				c.Close()
				return
			}

			if c.cipher != nil {
				pingData, err := c.cipher.Encrypt(pingMagic)
				if err == nil {
					opcode := packet.OpDataV1
					if c.peerID != 0 {
						opcode = packet.OpDataV2
					}
					p := &packet.Packet{
						Opcode:  byte(opcode),
						PeerID:  c.peerID,
						Payload: pingData,
					}
					c.writePacket(p)
				}
			}
		}
	}
}

func (c *Client) Close() error {
	c.cancel()
	var err error
	if c.conn != nil {
		err = c.conn.Close()
	}
	if c.tunDevice != nil {
		if e := c.tunDevice.Close(); e != nil {
			err = e
		}
	}
	return err
}
