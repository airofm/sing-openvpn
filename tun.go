package openvpn

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/airofm/sing-openvpn/internal/packet"
)

func (c *Client) tunReadLoop() {
	log.Infoln("[OpenVPN] tunReadLoop started")
	// Note: We intentionally do NOT wait for route-delay here.
	// route-delay is intended for the client-side OS to install routes (e.g. Windows).
	// Our gvisor TUN stack has virtual routing that is ready immediately.
	// The server-side NAT/routes are ready by the time PUSH_REPLY is sent.

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	bufs := [][]byte{buf}
	sizes := []int{0}

	for {
		// Read in batches of up to 32 packets
		batchSize := 32
		if len(bufs) < batchSize {
			for i := len(bufs); i < batchSize; i++ {
				b := bufPool.Get().(*[]byte)
				bufs = append(bufs, *b)
				sizes = append(sizes, 0)
			}
		}

		n, err := c.tunDevice.Read(bufs, sizes, 0)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				log.Errorln("[OpenVPN] TUN Read error: %v", err)
				return
			}
		}

		for i := 0; i < n; i++ {
			plaintext := bufs[i][:sizes[i]]
			var ciphertext []byte
			var errEnc error

			if c.cipher != nil {
				ciphertext, errEnc = c.cipher.Encrypt(plaintext)
			} else {
				ciphertext = plaintext
			}

			if errEnc != nil {
				log.Warnln("[OpenVPN] TUN encrypt error: %v (len=%d)", errEnc, len(plaintext))
				continue
			}

			log.Debugln("[OpenVPN] TUN read %d bytes, encrypted to %d bytes", sizes[i], len(ciphertext))
			// Use DataV2 when peer-id is assigned (both GCM and CBC)
			opcode := packet.OpDataV1
			if c.peerID != 0 {
				opcode = packet.OpDataV2
			}
			p := &packet.Packet{
				Opcode:  byte(opcode),
				PeerID:  c.peerID,
				Payload: ciphertext,
			}
			c.writePacket(p)
		}
	}
}

func (c *Client) processIncomingData(data []byte) {
	var plaintext []byte
	var errDec error

	if c.cipher != nil {
		plaintext, errDec = c.cipher.Decrypt(data)
	} else {
		plaintext = data
	}

	if errDec != nil {
		dumpLen := 40
		if len(data) < dumpLen {
			dumpLen = len(data)
		}
		log.Warnln("[OpenVPN] Data decrypt error: %v (len=%d, hex=%s)", errDec, len(data), hex.EncodeToString(data[:dumpLen]))
		return
	}

	log.Infoln("[OpenVPN] TUN write: %d bytes plaintext", len(plaintext))

	pingMagic := []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
	if len(plaintext) == 16 && bytes.Equal(plaintext, pingMagic) {
		log.Infoln("[OpenVPN] Received OpenVPN ping, sending ping reply")
		if c.cipher != nil {
			pongData, pongErr := c.cipher.Encrypt(pingMagic)
			if pongErr == nil {
				opcode := packet.OpDataV1
				if c.peerID != 0 {
					opcode = packet.OpDataV2
				}
				p := &packet.Packet{
					Opcode:  byte(opcode),
					PeerID:  c.peerID,
					Payload: pongData,
				}
				c.writePacket(p)
			}
		}
		return
	}

	if len(plaintext) >= 20 && (plaintext[0]>>4) == 4 {
		srcIP := fmt.Sprintf("%d.%d.%d.%d", plaintext[12], plaintext[13], plaintext[14], plaintext[15])
		dstIP := fmt.Sprintf("%d.%d.%d.%d", plaintext[16], plaintext[17], plaintext[18], plaintext[19])
		log.Infoln("[OpenVPN] Decrypted IP in: src=%s dst=%s len=%d", srcIP, dstIP, len(plaintext))

		proto := plaintext[9]
		ipHdrLen := int(plaintext[0]&0x0f) * 4
		if proto == 17 && len(plaintext) >= ipHdrLen+4 {
			srcPort := uint16(plaintext[ipHdrLen])<<8 | uint16(plaintext[ipHdrLen+1])
			if srcPort == 53 {
				log.Infoln("[OpenVPN] DNS response in: src=%s:%d dst=%s len=%d", srcIP, srcPort, dstIP, len(plaintext))
			}
		}
	} else {
		pLen := 20
		if len(plaintext) < pLen {
			pLen = len(plaintext)
		}
		log.Debugln("[OpenVPN] Decrypted payload hex: %s", hex.EncodeToString(plaintext[:pLen]))
	}
	c.tunDevice.Write([][]byte{plaintext}, 0)
}
