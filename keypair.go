package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
)

// PrivKey ...
type PrivKey []byte

// PubKey ...
type PubKey []byte

// B64String ...
func (privKey PrivKey) B64String() string {
	return base64.StdEncoding.EncodeToString(privKey)
}

// PrivKeyFromB64String ...
func PrivKeyFromB64String(s string) PrivKey {
	decoded, _ := base64.StdEncoding.DecodeString(s)
	return decoded
}

// B64String ...
func (pubKey PubKey) B64String() string {
	return base64.StdEncoding.EncodeToString(pubKey)
}

// PubKeyFromB64String ...
func PubKeyFromB64String(s string) PubKey {
	decoded, _ := base64.StdEncoding.DecodeString(s)
	return decoded
}

// HexString ...
func (privKey PrivKey) HexString() string {
	return hex.EncodeToString(privKey)
}

// PrivKeyFromHexString ...
func PrivKeyFromHexString(s string) PrivKey {
	decoded, _ := hex.DecodeString(s)
	return decoded
}

// HexString ...
func (pubKey PubKey) HexString() string {
	return hex.EncodeToString(pubKey)
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
