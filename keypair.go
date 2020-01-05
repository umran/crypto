package crypto

import (
	"crypto/ed25519"
)

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
