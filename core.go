package voprf

import (
	"crypto/subtle"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup/group"
)

const (
	dstChallengePrefix = protocol + "-Challenge-"
	dstCompositePrefix = protocol + "-Composite-"
	dstFinalizePrefix  = protocol + "-Finalize-"
	dstSeedPrefix      = protocol + "-Seed-"
)

func lengthPrefixEncode(input []byte) []byte {
	return append(encoding.I2OSP2(uint(len(input))), input...)
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (o *oprf) ccScalar(encSeed []byte, index uint, blindedElement, evaluatedElement group.Element, encCompositeDST []byte) group.Scalar {
	return o.group.HashToScalar(encSeed, encoding.I2OSP2(index),
		lengthPrefixEncode(blindedElement.Bytes()),
		lengthPrefixEncode(evaluatedElement.Bytes()),
		encCompositeDST)
}

func (o *oprf) computeCompositesFast(encSeed, encCompositeDST []byte, privKey group.Scalar,
	blindedElements, evaluatedElements []group.Element) (m, z group.Element) {
	m = o.group.Identity()

	for i, blinded := range blindedElements {
		di := o.ccScalar(encSeed, uint(i), blinded, evaluatedElements[i], encCompositeDST)
		m = blindedElements[i].Mult(di).Add(m)
	}

	return m, m.Mult(privKey)
}

func (o *oprf) computeCompositesClient(encSeed, encCompositeDST []byte,
	blindedElements, evaluatedElements []group.Element) (m, z group.Element) {
	m = o.group.Identity()
	z = o.group.Identity()

	for i, blinded := range blindedElements {
		di := o.ccScalar(encSeed, uint(i), blinded, evaluatedElements[i], encCompositeDST)
		m = blindedElements[i].Mult(di).Add(m)
		z = evaluatedElements[i].Mult(di).Add(z)
	}

	return m, z
}

func (o *oprf) computeComposites(privKey group.Scalar, pubKey group.Element,
	blindedElements, evaluatedElements []group.Element) (m, z group.Element) {
	// DST
	seedDST := o.dst(dstSeedPrefix)
	encSeedDST := lengthPrefixEncode(seedDST)
	compositeDST := o.dst(dstCompositePrefix)
	encCompositeDST := lengthPrefixEncode(compositeDST)

	// build seed
	encPkS := lengthPrefixEncode(pubKey.Bytes())
	seed := o.hash.Hash(0, encPkS, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if privKey != nil {
		return o.computeCompositesFast(encSeed, encCompositeDST, privKey, blindedElements, evaluatedElements)
	}

	return o.computeCompositesClient(encSeed, encCompositeDST, blindedElements, evaluatedElements)
}

func (o *oprf) hashTranscript(input, unblinded, info []byte) []byte {
	finalizeDST := o.dst(dstFinalizePrefix)
	encInput := lengthPrefixEncode(input)
	encElement := lengthPrefixEncode(unblinded)
	encInfo := lengthPrefixEncode(info)
	encDST := lengthPrefixEncode(finalizeDST)

	return o.hash.Hash(o.hash.OutputSize(), encInput, encElement, encInfo, encDST)
}

func (o *oprf) proofScalar(publicKey, a0, a1, a2, a3 group.Element) group.Scalar {
	challengeDST := o.dst(dstChallengePrefix)
	encPkS := lengthPrefixEncode(publicKey.Bytes())
	encA0 := lengthPrefixEncode(a0.Bytes())
	encA1 := lengthPrefixEncode(a1.Bytes())
	encA2 := lengthPrefixEncode(a2.Bytes())
	encA3 := lengthPrefixEncode(a3.Bytes())
	encDST := lengthPrefixEncode(challengeDST)

	return o.group.HashToScalar(encPkS, encA0, encA1, encA2, encA3, encDST)
}
