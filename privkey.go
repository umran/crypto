package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// PrivKeySize ...
const PrivKeySize = 64

// PrivKey ...
type PrivKey []byte

// Validate ...
func (privKey PrivKey) Validate() error {
	if len(privKey) != PrivKeySize {
		return fmt.Errorf("must be exactly %d bytes", PrivKeySize)
	}

	return nil
}

// Equal ...
func (privKey PrivKey) Equal(secondary PrivKey) bool {
	return bytes.Equal(privKey, secondary)
}

// Serialize ...
func (privKey PrivKey) Serialize() []byte {
	return []byte(privKey)
}

// B64String ...
func (privKey PrivKey) B64String() string {
	return base64.StdEncoding.EncodeToString(privKey)
}

// PrivKeyFromB64String ...
func PrivKeyFromB64String(s string) (PrivKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if err = PrivKey(decoded).Validate(); err != nil {
		return nil, err
	}

	return decoded, nil
}

// HexString ...
func (privKey PrivKey) HexString() string {
	return hex.EncodeToString(privKey)
}

// PrivKeyFromHexString ...
func PrivKeyFromHexString(s string) (PrivKey, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if err = PrivKey(decoded).Validate(); err != nil {
		return nil, err
	}

	return decoded, nil
}
