package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
)

func pHash(hashFunc func() hash.Hash, secret, seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	a := seed

	for len(result) < length {
		mac := hmac.New(hashFunc, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		mac = hmac.New(hashFunc, secret)
		mac.Write(a)
		mac.Write(seed)
		result = append(result, mac.Sum(nil)...)
	}

	return result[:length]
}

func tls10PRF(secret, seed []byte, length int) []byte {
	half := (len(secret) + 1) / 2
	s1 := secret[:half]
	s2 := secret[half:]

	md5Result := pHash(md5.New, s1, seed, length)
	sha1Result := pHash(sha1.New, s2, seed, length)

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = md5Result[i] ^ sha1Result[i]
	}
	return result
}

func OpenVPNPRF(secret []byte, label string, clientSeed, serverSeed []byte,
	clientSID, serverSID *uint64, length int) []byte {

	seed := make([]byte, 0, len(label)+len(clientSeed)+len(serverSeed)+16)
	seed = append(seed, []byte(label)...)
	seed = append(seed, clientSeed...)
	seed = append(seed, serverSeed...)

	if clientSID != nil {
		sidBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(sidBuf, *clientSID)
		seed = append(seed, sidBuf...)
	}
	if serverSID != nil {
		sidBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(sidBuf, *serverSID)
		seed = append(seed, sidBuf...)
	}

	return tls10PRF(secret, seed, length)
}
