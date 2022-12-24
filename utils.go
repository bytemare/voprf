package voprf

import (
	"crypto/subtle"
	"encoding/binary"
)

// KeyPair assembles a VOPRF key pair. The SecretKey can be used as the evaluation key for the group identified by ID.
type KeyPair struct {
	ID        Ciphersuite
	PublicKey []byte
	SecretKey []byte
}

func i2osp2(value int) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(value))

	return out
}

func lengthPrefixEncode(input []byte) []byte {
	return append(i2osp2(len(input)), input...)
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func concatenate(input ...[]byte) []byte {
	if len(input) == 1 {
		if len(input[0]) == 0 {
			return nil
		}

		return input[0]
	}

	length := 0
	for _, in := range input {
		length += len(in)
	}

	buf := make([]byte, 0, length)

	for _, in := range input {
		buf = append(buf, in...)
	}

	return buf
}

func dst(prefix string, contextString []byte) []byte {
	p := []byte(prefix)
	t := make([]byte, 0, len(p)+len(contextString))
	t = append(t, p...)
	t = append(t, contextString...)

	return t
}
