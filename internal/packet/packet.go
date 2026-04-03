package packet

import (
	"encoding/binary"
	"errors"
	"sync"
)

type Packet struct {
	Opcode    byte
	KeyID     byte
	PeerID    uint32 // 3 bytes in GCM
	SessionID uint64
	RemoteSID uint64 // Remote session ID, required when ACKs are present
	PacketID  uint32
	Acks      []uint32
	Payload   []byte
}

func (p *Packet) Encode() []byte {
	if p.Opcode == OpDataV1 || p.Opcode == OpDataV2 {
		headerLen := 1
		if p.Opcode == OpDataV2 && p.PeerID != 0 {
			headerLen += 3
		}
		
		// Allocate exact buffer size
		buf := make([]byte, headerLen+len(p.Payload))
		buf[0] = (p.Opcode << 3) | (p.KeyID & 0x07)
		if headerLen > 1 {
			buf[1] = byte(p.PeerID >> 16)
			buf[2] = byte(p.PeerID >> 8)
			buf[3] = byte(p.PeerID)
		}
		copy(buf[headerLen:], p.Payload)
		return buf
	}

	// Control packets
	// All control packets have: [Opcode/KeyID (1)] [SessionID (8)] [AckCount (1)] [Acks...] [RemoteSID if acks>0] [PacketID (4, except ACK-only)] [Payload]
	ackExtra := 0
	if len(p.Acks) > 0 {
		ackExtra = 8 // Remote Session ID
	}
	packetIDSize := PacketIDSize
	if p.Opcode == OpAckV1 {
		packetIDSize = 0
	}
	buf := make([]byte, 1+SessionIDSize+1+len(p.Acks)*4+ackExtra+packetIDSize+len(p.Payload))
	buf[0] = (p.Opcode << 3) | (p.KeyID & 0x07)
	binary.BigEndian.PutUint64(buf[1:], p.SessionID)

	offset := 9
	// All control packets include the ACK array (even if length is 0)
	buf[offset] = byte(len(p.Acks))
	offset++
	for _, ack := range p.Acks {
		binary.BigEndian.PutUint32(buf[offset:], ack)
		offset += 4
	}
	if len(p.Acks) > 0 {
		binary.BigEndian.PutUint64(buf[offset:], p.RemoteSID)
		offset += 8
	}

	// All except P_ACK_V1 have PacketID
	if p.Opcode != OpAckV1 {
		binary.BigEndian.PutUint32(buf[offset:], p.PacketID)
		offset += 4
	}

	copy(buf[offset:], p.Payload)
	return buf
}

var packetPool = sync.Pool{
	New: func() any {
		return &Packet{}
	},
}

// GetPacket returns a recycled Packet object
func GetPacket() *Packet {
	p := packetPool.Get().(*Packet)
	p.Acks = p.Acks[:0] // Reset slice length but keep capacity
	return p
}

// PutPacket recycles a Packet object
func (p *Packet) PutPacket() {
	packetPool.Put(p)
}

func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 1 {
		return nil, errors.New("packet too short")
	}

	p := GetPacket()
	p.Opcode = data[0] >> 3
	p.KeyID = data[0] & 0x07
	p.PeerID = 0
	p.SessionID = 0
	p.RemoteSID = 0
	p.PacketID = 0

	if p.Opcode == OpDataV1 || p.Opcode == OpDataV2 {
		headerLen := 1
		if p.Opcode == OpDataV2 && len(data) >= 4 {
			p.PeerID = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
			headerLen += 3
		}
		p.Payload = data[headerLen:]
		return p, nil
	}

	if len(data) < 1+SessionIDSize {
		p.PutPacket()
		return nil, errors.New("control packet too short for session id")
	}

	p.SessionID = binary.BigEndian.Uint64(data[1:])
	offset := 9

	// All control packets have the ACK array
	if len(data) < offset+1 {
		p.PutPacket()
		return nil, errors.New("packet too short for ack count")
	}
	ackCount := int(data[offset])
	offset++
	if len(data) < offset+ackCount*4 {
		p.PutPacket()
		return nil, errors.New("packet too short for acks")
	}

	for i := 0; i < ackCount; i++ {
		ack := binary.BigEndian.Uint32(data[offset:])
		p.Acks = append(p.Acks, ack)
		offset += 4
	}
	if ackCount > 0 {
		if len(data) < offset+8 {
			p.PutPacket()
			return nil, errors.New("packet too short for remote session id")
		}
		p.RemoteSID = binary.BigEndian.Uint64(data[offset:])
		offset += 8
	}

	if p.Opcode != OpAckV1 {
		if len(data) < offset+PacketIDSize {
			p.PutPacket()
			return nil, errors.New("packet too short for packet id")
		}
		p.PacketID = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}

	p.Payload = data[offset:]
	return p, nil
}