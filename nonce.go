package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// NonceSize ...
const NonceSize int = 32

// Nonce ...
type Nonce []byte

// Validate ...
func (nonce Nonce) Validate() error {
	if len(nonce) != NonceSize {
		return fmt.Errorf("must be exactly %d bytes", NonceSize)
	}

	return nil
}

// Serialize ...
func (nonce Nonce) Serialize() []byte {
	return []byte(nonce)
}

// B64String ...
func (nonce Nonce) B64String() string {
	return base64.StdEncoding.EncodeToString(nonce)
}

// NonceFromB64String ...
func NonceFromB64String(s string) Nonce {
	decoded, _ := base64.StdEncoding.DecodeString(s)
	return decoded
}

// HexString ...
func (nonce Nonce) HexString() string {
	return hex.EncodeToString(nonce)
}

// NonceFromHexString ...
func NonceFromHexString(s string) Nonce {
	decoded, _ := hex.DecodeString(s)
	return decoded
}

// GenerateNonce ...
func GenerateNonce() (Nonce, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return Nonce(nonce), nil
}
