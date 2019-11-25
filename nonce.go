package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

const (
	// NonceSize ...
	NonceSize int = 32
)

// Nonce ...
type Nonce []byte

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
