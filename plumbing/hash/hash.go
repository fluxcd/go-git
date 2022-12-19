// package hash provides a way for managing the
// underlying hash implementations used across go-git.
package hash

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/fluxcd/go-git/v5/plumbing/objectformat"
	"github.com/pjbgf/sha1cd/cgo"
)

// algos is a map of hash algorithms.
var algos = map[objectformat.ObjectFormat]func() hash.Hash{}

func init() {
	reset()
}

// reset resets the default algos value. Can be used after running tests
// that registers new algorithms to avoid side effects.
func reset() {
	// For performance reasons the cgo version of the collision
	// detection algorithm is being used.
	algos[objectformat.SHA1] = cgo.New
	algos[objectformat.SHA256] = crypto.SHA256.New
}

// RegisterHash allows for the hash algorithm used to be overriden.
// This ensures the hash selection for go-git must be explicit, when
// overriding the default value.
func RegisterHash(h objectformat.ObjectFormat, f func() hash.Hash) error {
	if f == nil {
		return fmt.Errorf("cannot register hash: f is nil")
	}

	switch h {
	case objectformat.SHA1:
		algos[h] = f
	case objectformat.SHA256:
		algos[h] = f
	default:
		return fmt.Errorf("unsupported hash function: %v", h)
	}
	return nil
}

// Hash is the same as hash.Hash. This allows consumers
// to not having to import this package alongside "hash".
type Hash interface {
	hash.Hash
}

// New returns a new Hash for the given object format.
// It panics if the hash function is not registered.
func New(h objectformat.ObjectFormat) Hash {
	hh, ok := algos[h]
	if !ok {
		panic(fmt.Sprintf("hash algorithm not registered: %s", h))
	}
	return hh()
}
