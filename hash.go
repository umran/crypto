package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Hash ...
type Hash []byte

func doubleShaSum256(data []byte) []byte {
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

	var hash Hash = doubleShaSum256(mergedBytes)

	return hash
}

// Equal ...
func (primary Hash) Equal(secondary Hash) bool {
	return bytes.Equal(primary, secondary)
}

// HexString ...
func (primary Hash) HexString() string {
	return hex.EncodeToString(primary)
}

// HashFromHexString ...
func HashFromHexString(s string) Hash {
	decoded, _ := hex.DecodeString(s)
	return decoded
}

// GenerateHash ...
func GenerateHash(data []byte) Hash {
	var hash Hash = doubleShaSum256(data)

	return hash
}

// GenerateHashFromStream ...
func GenerateHashFromStream(r io.Reader) Hash {
	hash := sha256.New()
	io.Copy(hash, r)

	doubleHash := sha256.Sum256(hash.Sum(nil))
	return doubleHash[:]
}
