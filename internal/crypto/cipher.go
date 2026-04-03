package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"

	"github.com/airofm/sing-openvpn/internal/log"
)

type DataCipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type CBCCipher struct {
	encBlock     cipher.Block
	decBlock     cipher.Block
	encHMACKey   []byte
	decHMACKey   []byte
	txPacketID   uint32
	macPoolEnc   sync.Pool
	macPoolDec   sync.Pool
	mutex        sync.Mutex
	replayWindow *ReplayWindow
}

func NewCBCCipher(encKey, decKey, encHMACKey, decHMACKey []byte) (*CBCCipher, error) {
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	return &CBCCipher{
		encBlock:     encBlock,
		decBlock:     decBlock,
		encHMACKey:   encHMACKey,
		decHMACKey:   decHMACKey,
		macPoolEnc:   sync.Pool{New: func() any { return hmac.New(sha1.New, encHMACKey) }},
		macPoolDec:   sync.Pool{New: func() any { return hmac.New(sha1.New, decHMACKey) }},
		replayWindow: NewReplayWindow(64),
	}, nil
}

func (c *CBCCipher) Encrypt(plaintext []byte) ([]byte, error) {
	c.mutex.Lock()
	pid := c.txPacketID
	c.txPacketID++
	c.mutex.Unlock()

	bs := c.encBlock.BlockSize()
	padding := bs - (4+len(plaintext))%bs
	paddedLen := 4 + len(plaintext) + padding

	// Single allocation for MAC(20) + IV(bs) + Ciphertext(paddedLen)
	result := make([]byte, 20+bs+paddedLen)
	mac := result[0:20]
	iv := result[20 : 20+bs]
	ciphertext := result[20+bs:]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint32(ciphertext[0:4], pid)
	copy(ciphertext[4:], plaintext)
	for i := 4 + len(plaintext); i < paddedLen; i++ {
		ciphertext[i] = byte(padding)
	}

	mode := cipher.NewCBCEncrypter(c.encBlock, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	h := c.macPoolEnc.Get().(hash.Hash)
	h.Reset()
	h.Write(iv)
	h.Write(ciphertext)
	calculatedMAC := h.Sum(nil)
	copy(mac, calculatedMAC)
	c.macPoolEnc.Put(h)

	log.Debugln("[OpenVPN] CBC Encrypt: pid=%d, plaintext_len=%d, padded_len=%d, result_len=%d", pid, len(plaintext), paddedLen, len(result))
	if len(ciphertext) <= 64 {
		log.Debugln("[OpenVPN] CBC Encrypt: ciphertext=%s", hex.EncodeToString(ciphertext))
	}

	return result, nil
}

func (c *CBCCipher) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 20+16 {
		return nil, errors.New("CBC data too short")
	}

	mac := data[0:20]
	iv := data[20:36]
	ciphertext := data[36:]

	h := c.macPoolDec.Get().(hash.Hash)
	h.Reset()
	h.Write(iv)
	h.Write(ciphertext)
	expectedMAC := h.Sum(nil)
	c.macPoolDec.Put(h)

	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("CBC HMAC verification failed")
	}

	if len(ciphertext)%c.decBlock.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	// In-place decryption to avoid allocations
	mode := cipher.NewCBCDecrypter(c.decBlock, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	if len(ciphertext) == 0 {
		return nil, errors.New("plaintext is empty")
	}
	padding := int(ciphertext[len(ciphertext)-1])
	if padding > c.decBlock.BlockSize() || padding > len(ciphertext) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	plaintext := ciphertext[:len(ciphertext)-padding]

	if len(plaintext) < 4 {
		return nil, errors.New("decrypted data too short for packet_id")
	}
	
	packetID := binary.BigEndian.Uint32(plaintext[0:4])
	if !c.replayWindow.Check(packetID) {
		return nil, errors.New("replayed or stale packet")
	}
	c.replayWindow.Update(packetID)

	return plaintext[4:], nil
}

type GCMCipher struct {
	encAEAD      cipher.AEAD
	decAEAD      cipher.AEAD
	encryptIV    []byte
	decryptIV    []byte
	packetID     uint32
	mutex        sync.Mutex
	replayWindow *ReplayWindow
}

func NewGCMCipher(encKey, decKey, encIV, decIV []byte) (*GCMCipher, error) {
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	encAEAD, err := cipher.NewGCM(encBlock)
	if err != nil {
		return nil, err
	}

	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	decAEAD, err := cipher.NewGCM(decBlock)
	if err != nil {
		return nil, err
	}

	return &GCMCipher{
		encAEAD:      encAEAD,
		decAEAD:      decAEAD,
		encryptIV:    encIV,
		decryptIV:    decIV,
		replayWindow: NewReplayWindow(64),
	}, nil
}

func (c *GCMCipher) Encrypt(plaintext []byte) ([]byte, error) {
	c.mutex.Lock()
	pid := c.packetID
	c.packetID++
	c.mutex.Unlock()

	nonce := make([]byte, 12)
	copy(nonce[0:4], c.encryptIV[0:4])
	binary.BigEndian.PutUint32(nonce[4:8], pid)

	// Pre-allocate the exact size: 4 (pid) + len(plaintext) + 16 (tag)
	result := make([]byte, 4, 4+len(plaintext)+16)
	binary.BigEndian.PutUint32(result[0:4], pid)

	// Seal appends the ciphertext to result, minimizing allocations
	result = c.encAEAD.Seal(result, nonce, plaintext, result[0:4])

	return result, nil
}

func (c *GCMCipher) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 4+16 {
		return nil, errors.New("data too short for GCM")
	}

	packetID := binary.BigEndian.Uint32(data[0:4])
	
	// Fast path: check replay window before expensive decryption
	if !c.replayWindow.Check(packetID) {
		return nil, errors.New("replayed or stale packet")
	}

	ciphertext := data[4:]

	nonce := make([]byte, 12)
	copy(nonce[0:4], c.decryptIV[0:4])
	binary.BigEndian.PutUint32(nonce[4:8], packetID)

	plaintext, err := c.decAEAD.Open(nil, nonce, ciphertext, data[0:4])
	if err != nil {
		return nil, err
	}

	// Update window only after successful authentication
	c.replayWindow.Update(packetID)

	return plaintext, nil
}
