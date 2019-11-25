package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
)

// Signature ...
type Signature []byte

// HexString ...
func (sig Signature) HexString() string {
	return hex.EncodeToString(sig)
}

// SignatureFromHexString ...
func SignatureFromHexString(s string) Signature {
	decoded, _ := hex.DecodeString(s)
	return decoded
}

// Sign ...
func Sign(privKey PrivKey, data []byte) Signature {
	return ed25519.Sign(ed25519.PrivateKey(privKey), data)
}

// Verify ...
func Verify(pubKey PubKey, data []byte, sig Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pubKey), data, sig)
}
