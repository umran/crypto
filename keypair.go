package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
)

// PrivKey ...
type PrivKey []byte

// PubKey ...
type PubKey []byte

// HexString ...
func (privKey PrivKey) HexString() string {
	return hex.EncodeToString(privKey)
}

// HexString ...
func (pubKey PubKey) HexString() string {
	return hex.EncodeToString(pubKey)
}

// PrivKeyFromHexString ...
func PrivKeyFromHexString(s string) PrivKey {
	decoded, _ := hex.DecodeString(s)
	return decoded
}

// PubKeyFromHexString ...
func PubKeyFromHexString(s string) PubKey {
	decoded, _ := hex.DecodeString(s)
	return decoded
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
