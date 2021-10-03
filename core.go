package voprf

import (
	"crypto/subtle"
	"encoding/binary"
	"github.com/bytemare/crypto/group"
	"github.com/bytemare/crypto/utils"
)

const (
	dstChallengePrefix = "Challenge-"
	dstCompositePrefix = "Composite-"
	dstFinalizePrefix  = "Finalize-"
	dstSeedPrefix      = "Seed-"
	dstContext         = "Context-"

	p256PointLength  = 33
	p256ScalarLength = 32
	p384PointLength  = 49
	p384ScalarLength = 48
	p521PointLength  = 67
	p521ScalarLength = 66
)

func scalarLength(c Ciphersuite) int {
	switch c {
	case RistrettoSha512:
		return 32
	// case Decaf448Sha512:
	//	return 56
	case P256Sha256:
		return p256ScalarLength
	case P384Sha512:
		return p384ScalarLength
	case P521Sha512:
		return p521ScalarLength
	default:
		panic("invalid suite")
	}
}

func pointLength(c Ciphersuite) int {
	switch c {
	case RistrettoSha512:
		return 32
	// case Decaf448Sha512:
	//	return 56
	case P256Sha256:
		return p256PointLength
	case P384Sha512:
		return p384PointLength
	case P521Sha512:
		return p521PointLength
	default:
		panic("invalid suite")
	}
}

func serializeScalar(s *group.Scalar, length int) []byte {
	e := s.Bytes()
	for len(e) < length {
		e = append([]byte{0x00}, e...)
	}

	return e
}

func serializePoint(e *group.Point, length int) []byte {
	p := e.Bytes()

	for len(p) < length {
		p = append([]byte{0x00}, p...)
	}

	return p
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

func (o *oprf) ccScalar(encSeed []byte, index int, blindedElement, evaluatedElement *group.Point, encCompositeDST []byte) *group.Scalar {
	input := utils.Concatenate(encSeed, i2osp2(index),
		lengthPrefixEncode(serializePoint(blindedElement, pointLength(o.id))),
		lengthPrefixEncode(serializePoint(evaluatedElement, pointLength(o.id))),
		encCompositeDST)

	return o.HashToScalar(input)
}

func (o *oprf) computeCompositesFast(k *group.Scalar, encSeed, encCompositeDST []byte, blindedElements, evaluatedElements []*group.Point) (m, z *group.Point) {
	m = o.group.Identity()

	for i, evaluated := range evaluatedElements {
		di := o.ccScalar(encSeed, i, evaluated, blindedElements[i], encCompositeDST)
		m = evaluated.Mult(di).Add(m)
	}

	return m, m.Mult(k)
}

func (o *oprf) computeCompositesClient(encSeed, encCompositeDST []byte,
	blindedElements, evaluatedElements []*group.Point) (m, z *group.Point) {
	m = o.group.Identity()
	z = o.group.Identity()

	for i, evaluated := range evaluatedElements {
		di := o.ccScalar(encSeed, i, evaluated, blindedElements[i], encCompositeDST)
		m = evaluated.Mult(di).Add(m)
		z = blindedElements[i].Mult(di).Add(z)
	}

	return m, z
}

func (o *oprf) computeComposites(k *group.Scalar, encGk []byte,
	blindedElements, evaluatedElements []*group.Point) (m, z *group.Point) {
	// DST
	encSeedDST := lengthPrefixEncode(o.dst(dstSeedPrefix))
	encCompositeDST := lengthPrefixEncode(o.dst(dstCompositePrefix))

	// build seed
	seed := o.hash.Hash(encGk, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if k != nil {
		return o.computeCompositesFast(k, encSeed, encCompositeDST, blindedElements, evaluatedElements)
	}

	return o.computeCompositesClient(encSeed, encCompositeDST, blindedElements, evaluatedElements)
}

func (o *oprf) hashTranscript(input, info, unblinded []byte) []byte {
	finalizeDST := o.dst(dstFinalizePrefix)
	encInput := lengthPrefixEncode(input)
	encInfo := lengthPrefixEncode(info)
	encElement := lengthPrefixEncode(unblinded)
	encDST := lengthPrefixEncode(finalizeDST)

	return o.hash.Hash(encInput, encInfo, encElement, encDST)
}

func (o *oprf) challenge(encPks []byte, a0, a1, a2, a3 *group.Point) *group.Scalar {
	encA0 := lengthPrefixEncode(a0.Bytes())
	encA1 := lengthPrefixEncode(a1.Bytes())
	encA2 := lengthPrefixEncode(a2.Bytes())
	encA3 := lengthPrefixEncode(a3.Bytes())
	encDST := lengthPrefixEncode(o.dst(dstChallengePrefix))
	input := utils.Concatenate(encPks, encA0, encA1, encA2, encA3, encDST)

	return o.HashToScalar(input)
}
