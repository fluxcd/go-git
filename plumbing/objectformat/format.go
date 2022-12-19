package objectformat

type ObjectFormat uint

const (
	SHA1 ObjectFormat = 0 + iota
	SHA256
)

func (f ObjectFormat) String() string {
	switch f {
	case SHA256:
		return "sha256"
	default:
		return "sha1"
	}
}

func (f ObjectFormat) Size() int {
	switch f {
	case SHA256:
		return 32
	default:
		return 20
	}
}

func (f ObjectFormat) HexLen() int {
	return f.Size() * 2
}
