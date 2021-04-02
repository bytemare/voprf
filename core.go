package voprf

import (
	"crypto/subtle"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
)

const (
	dstChallengePrefix = protocol + "-Challenge-"
	dstCompositePrefix = protocol + "-Composite-"
	dstFinalizePrefix  = protocol + "-Finalize-"
	dstSeedPrefix      = protocol + "-Seed-"

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
	case Decaf448Sha512:
		return 56
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
	case Decaf448Sha512:
		return 56
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

func serializeScalar(s group.Scalar, length int) []byte {
	e := s.Bytes()
	for len(e) < length {
		e = append([]byte{0x00}, e...)
	}

	return e
}

func lengthPrefixEncode(input []byte) []byte {
	return append(encoding.I2OSP(len(input), 2), input...)
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (o *oprf) ccScalar(encSeed []byte, index int, blindedElement, evaluatedElement group.Element, encCompositeDST []byte) group.Scalar {
	input := utils.Concatenate(0, encSeed, encoding.I2OSP(index, 2),
		lengthPrefixEncode(blindedElement.Bytes()),
		lengthPrefixEncode(evaluatedElement.Bytes()),
		encCompositeDST)

	return o.group.HashToScalar(input, o.dst(hash2scalarDSTPrefix))
}

func (o *oprf) computeCompositesFast(encSeed, encCompositeDST []byte, privKey group.Scalar,
	blindedElements, evaluatedElements []group.Element) (m, z group.Element) {
	m = o.group.Identity()

	for i, blinded := range blindedElements {
		di := o.ccScalar(encSeed, i, blinded, evaluatedElements[i], encCompositeDST)
		m = blindedElements[i].Mult(di).Add(m)
	}

	return m, m.Mult(privKey)
}

func (o *oprf) computeCompositesClient(encSeed, encCompositeDST []byte,
	blindedElements, evaluatedElements []group.Element) (m, z group.Element) {
	m = o.group.Identity()
	z = o.group.Identity()

	for i, blinded := range blindedElements {
		di := o.ccScalar(encSeed, i, blinded, evaluatedElements[i], encCompositeDST)
		m = blindedElements[i].Mult(di).Add(m)
		z = evaluatedElements[i].Mult(di).Add(z)
	}

	return m, z
}

func (o *oprf) computeComposites(privKey group.Scalar, encPks []byte,
	blindedElements, evaluatedElements []group.Element) (m, z group.Element) {
	// DST
	seedDST := o.dst(dstSeedPrefix)
	encSeedDST := lengthPrefixEncode(seedDST)
	compositeDST := o.dst(dstCompositePrefix)
	encCompositeDST := lengthPrefixEncode(compositeDST)

	// build seed
	seed := o.hash.Hash(encPks, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if privKey != nil {
		return o.computeCompositesFast(encSeed, encCompositeDST, privKey, blindedElements, evaluatedElements)
	}

	return o.computeCompositesClient(encSeed, encCompositeDST, blindedElements, evaluatedElements)
}

func (o *oprf) hashTranscript(input, unblinded []byte) []byte {
	finalizeDST := o.dst(dstFinalizePrefix)
	encInput := lengthPrefixEncode(input)
	encElement := lengthPrefixEncode(unblinded)
	encDST := lengthPrefixEncode(finalizeDST)

	return o.hash.Hash(encInput, encElement, encDST)
}

func (o *oprf) proofScalar(encPks []byte, a0, a1, a2, a3 group.Element) group.Scalar {
	challengeDST := o.dst(dstChallengePrefix)
	encA0 := lengthPrefixEncode(a0.Bytes())
	encA1 := lengthPrefixEncode(a1.Bytes())
	encA2 := lengthPrefixEncode(a2.Bytes())
	encA3 := lengthPrefixEncode(a3.Bytes())
	encDST := lengthPrefixEncode(challengeDST)
	input := utils.Concatenate(0, encPks, encA0, encA1, encA2, encA3, encDST)

	return o.HashToScalar(input)
}
