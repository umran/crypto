package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// SignatureSize ...
const SignatureSize = 64

// Signature ...
type Signature []byte

// Validate ...
func (sig Signature) Validate() error {
	if len(sig) != SignatureSize {
		return fmt.Errorf("must be exactly %d bytes", SignatureSize)
	}

	return nil
}

// Serialize ...
func (sig Signature) Serialize() []byte {
	return []byte(sig)
}

// B64String ...
func (sig Signature) B64String() string {
	return base64.StdEncoding.EncodeToString(sig)
}

// SignatureFromB64String ...
func SignatureFromB64String(s string) (Signature, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

// HexString ...
func (sig Signature) HexString() string {
	return hex.EncodeToString(sig)
}

// SignatureFromHexString ...
func SignatureFromHexString(s string) (Signature, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

// Sign ...
func Sign(privKey PrivKey, data []byte) Signature {
	return ed25519.Sign(ed25519.PrivateKey(privKey), data)
}

// Verify ...
func Verify(pubKey PubKey, data []byte, sig Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pubKey), data, sig)
}
