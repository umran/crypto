package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// HashSize ...
const HashSize = 32

// Hash ...
type Hash []byte

// Validate ...
func (primary Hash) Validate() error {
	if len(primary) != HashSize {
		return fmt.Errorf("must be exactly %d bytes", HashSize)
	}

	return nil
}

// Serialize ...
func (primary Hash) Serialize() []byte {
	return []byte(primary)
}

func doubleShaSum256(data []byte) Hash {
	firstSum := sha256.Sum256(data)
	secondSum := sha256.Sum256(firstSum[:])

	return secondSum[:]
}

// Merge ...
func (primary Hash) Merge(secondary Hash) Hash {
	mergedBytes := make([]byte, 64)
	offset := 0

	for _, octet := range primary {
		mergedBytes[offset] = octet
		offset++
	}

	for _, octet := range secondary {
		mergedBytes[offset] = octet
		offset++
	}

	return doubleShaSum256(mergedBytes)
}

// Equal ...
func (primary Hash) Equal(secondary Hash) bool {
	return bytes.Equal(primary, secondary)
}

// B64String ...
func (primary Hash) B64String() string {
	return base64.StdEncoding.EncodeToString(primary)
}

// HashFromB64String ...
func HashFromB64String(s string) (Hash, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if err = Hash(decoded).Validate(); err != nil {
		return nil, err
	}

	return decoded, nil
}

// HexString ...
func (primary Hash) HexString() string {
	return hex.EncodeToString(primary)
}

// HashFromHexString ...
func HashFromHexString(s string) (Hash, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if err = Hash(decoded).Validate(); err != nil {
		return nil, err
	}

	return decoded, nil
}

// GenerateHash ...
func GenerateHash(data []byte) Hash {
	return doubleShaSum256(data)
}

// GenerateHashFromStream ...
func GenerateHashFromStream(r io.Reader) (Hash, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, r)
	if err != nil {
		return nil, err
	}

	doubleHash := sha256.Sum256(hash.Sum(nil))
	return doubleHash[:], nil
}
