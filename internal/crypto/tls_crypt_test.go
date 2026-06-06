package crypto

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTLSCryptWrapStartsReplayPacketIDAtOne(t *testing.T) {
	var hexKey strings.Builder
	for i := 0; i < 256; i++ {
		hexKey.WriteString(hex.EncodeToString([]byte{byte(i)}))
		if (i+1)%16 == 0 {
			hexKey.WriteByte('\n')
		}
	}
	keyData := "-----BEGIN OpenVPN Static key V1-----\n" + hexKey.String() + "-----END OpenVPN Static key V1-----"

	tc, err := NewTLSCrypt(keyData)
	if err != nil {
		t.Fatalf("NewTLSCrypt returned error: %v", err)
	}

	wrapped, err := tc.Wrap([]byte{
		0x38,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00,
		0x00, 0x00, 0x00, 0x00,
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if got := binary.BigEndian.Uint32(wrapped[9:13]); got != 1 {
		t.Fatalf("expected first replay packet id to be 1, got %d", got)
	}
}
