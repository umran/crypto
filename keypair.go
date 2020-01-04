package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	// PrivKeySize ...
	PrivKeySize = 64
	// PubKeySize ...
	PubKeySize = 32
)

// PrivKey ...
type PrivKey []byte

// PubKey ...
type PubKey []byte

// Validate ...
func (privKey PrivKey) Validate() error {
	if len(privKey) != PrivKeySize {
		return fmt.Errorf("must be exactly %d bytes", PrivKeySize)
	}

	return nil
}

// Validate ...
func (pubKey PubKey) Validate() error {
	if len(pubKey) != PubKeySize {
		return fmt.Errorf("must be exactly %d bytes", PubKeySize)
	}

	return nil
}

// Serialize ...
func (privKey PrivKey) Serialize() []byte {
	return []byte(privKey)
}

// Serialize ...
func (pubKey PubKey) Serialize() []byte {
	return []byte(pubKey)
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

	return decoded, nil
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

	return decoded, nil
}

// KeyPair ...
type KeyPair struct {
	privKey PrivKey
	pubKey  PubKey
}

// PubKey ...
func (kp *KeyPair) PubKey() PubKey {
	return kp.pubKey
}

// PrivKey ...
func (kp *KeyPair) PrivKey() PrivKey {
	return kp.privKey
}

// GenerateKeyPair ...
func GenerateKeyPair() (*KeyPair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	kp := &KeyPair{
		privKey: PrivKey(privKey),
		pubKey:  PubKey(pubKey),
	}

	return kp, nil
}
