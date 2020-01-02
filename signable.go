package crypto

// Signable ...
type Signable interface {
	Sign(privKey PrivKey) Signature
	Verify(pubKey PubKey, sig Signature) bool
}
