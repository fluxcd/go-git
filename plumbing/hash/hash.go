package hash

import (
	"crypto"
	"hash"

	// For performance reasons the cgo version is being used.
	"github.com/pjbgf/sha1cd/cgo"
)

// Hash is the same as hash.Hash.
type Hash interface {
	hash.Hash
}

func NewSha1() hash.Hash {
	// Allow users to override the default SHA1 implementation.
	if crypto.SHA1.Available() {
		return crypto.SHA1.New()
	}
	return cgo.New()
}
