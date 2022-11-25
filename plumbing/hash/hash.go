package hash

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/pjbgf/sha1cd/cgo"
)

// For performance reasons the cgo version of the collision
// detection algorithm is being used.
var sha1New = cgo.New

func RegisterHash(h crypto.Hash, f func() hash.Hash) error {
	if f == nil {
		return fmt.Errorf("cannot register hash: f is nil")
	}

	switch h {
	case crypto.SHA1:
		sha1New = f
	default:
		return fmt.Errorf("unsupported hash function: %v", h)
	}
	return nil
}

// Hash is the same as hash.Hash.
type Hash interface {
	hash.Hash
}

func NewSha1() hash.Hash {
	return sha1New()
}
