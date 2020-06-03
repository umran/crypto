package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// PubKeySize ...
const PubKeySize = 32

// PubKey ...
type PubKey []byte

// Validate ...
func (pubKey PubKey) Validate() error {
	if len(pubKey) != PubKeySize {
		return fmt.Errorf("must be exactly %d bytes", PubKeySize)
	}

	return nil
}

// Equal ...
func (pubKey PubKey) Equal(secondary PubKey) bool {
	return bytes.Equal(pubKey, secondary)
}

// Serialize ...
func (pubKey PubKey) Serialize() []byte {
	return []byte(pubKey)
}

// B64String ...
func (pubKey PubKey) B64String() string {
	return base64.StdEncoding.EncodeToString(pubKey)
}

// PubKeyFromB64String ...
func PubKeyFromB64String(s string) (PubKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if err = PubKey(decoded).Validate(); err != nil {
		return nil, err
	}

	return decoded, nil
}

// HexString ...
func (pubKey PubKey) HexString() string {
	return hex.EncodeToString(pubKey)
}

// PubKeyFromHexString ...
func PubKeyFromHexString(s string) (PubKey, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if err = PubKey(decoded).Validate(); err != nil {
		return nil, err
	}

	return decoded, nil
}
