package voprf

import (
	"crypto/subtle"
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup/group"
)

const (
	// todo: inconsistencies in using lower-case or upper-case first letter
	dstChallengePrefix = protocol + "-challenge-"
	dstCompositePrefix = protocol + "-composite-"
	dstFinalizePrefix  = protocol + "-Finalize-"
	dstSeedPrefix      = protocol + "-seed-"
)

func lengthPrefixEncode(input []byte) []byte {
	return append(encoding.I2OSP2(uint(len(input))), input...)
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

type eval struct {
	// Element represents the unique serialization of an Element
	Element []byte `json:"e"`

	// Proofs
	ProofC []byte `json:"c,omitempty"`
	ProofS []byte `json:"s,omitempty"`
}

// Evaluation is the type output by the Evaluate algorithm. The member proof is added only in verifiable contexts.
type Evaluation struct {
	element group.Element
	proofC  group.Scalar
	proofS  group.Scalar
}

// Encode encodes the evaluation to the given format.
func (e *Evaluation) Encode(enc encoding.Encoding) ([]byte, error) {
	if enc == 0 {
		return nil, errParamNoEncoding
	}

	ev := &eval{
		Element: e.element.Bytes(),
	}

	if e.proofC != nil {
		ev.ProofC = e.proofC.Bytes()
	}

	if e.proofS != nil {
		ev.ProofS = e.proofS.Bytes()
	}

	return enc.Encode(ev)
}

func decodeEval(g group.Group, in []byte, enc encoding.Encoding) (*Evaluation, error) {
	ev, err := enc.Decode(in, &eval{})
	if err != nil {
		return nil, fmt.Errorf("could not decode Evaluation : %w", err)
	}

	eva, ok := ev.(*eval)
	if !ok {
		return nil, errInternalDecodeEval
	}

	elm, err := g.NewElement().Decode(eva.Element)
	if err != nil {
		return nil, fmt.Errorf("could not decode element : %w", err)
	}

	var pc group.Scalar
	if len(eva.ProofC) != 0 {
		pc, err = g.NewScalar().Decode(eva.ProofC)
		if err != nil {
			return nil, err
		}
	}

	var ps group.Scalar
	if len(eva.ProofS) != 0 {
		ps, err = g.NewScalar().Decode(eva.ProofS)
		if err != nil {
			return nil, err
		}
	}

	return &Evaluation{
		element: elm,
		proofC:  pc,
		proofS:  ps,
	}, nil
}

// todo: the draft doesn't really describe what this is, and does not use it
// type batchedEvaluation struct {
// 	Elements []group.Element
// 	Proof    group.Scalar
// }

func serializeBatch(elements []group.Element) []byte {
	if len(elements) == 0 {
		return []byte{}
	}

	e0 := elements[0].Bytes()

	if len(elements) == 1 {
		return e0
	}

	out := make([]byte, 0, len(elements)*len(e0))
	copy(out, e0)

	for _, e := range elements[1:] {
		out = append(out, e.Bytes()...)
	}

	return out
}

func (o *oprf) computeCompositeFast(encSeed, encCompositeDST []byte, privKey group.Scalar, blindTokens []group.Element) (m, z group.Element) {
	m = o.group.Identity()

	for i := uint(0); i < uint(len(blindTokens)); i++ {
		di := o.group.HashToScalar(encSeed, encoding.I2OSP2(i), encCompositeDST)
		m = m.Add(blindTokens[i].Mult(di))
	}

	return m, m.Mult(privKey)
}

func (o *oprf) computeCompositeClient(encSeed, encCompositeDST []byte, blindTokens, elements []group.Element) (m, z group.Element) {
	m = o.group.Identity()
	z = o.group.Identity()

	for i := uint(0); i < uint(len(blindTokens)); i++ {
		di := o.group.HashToScalar(encSeed, encoding.I2OSP2(i), encCompositeDST)
		m = m.Add(blindTokens[i].Mult(di))
		z = z.Add(elements[i].Mult(di))
	}

	return m, z
}

func (o *oprf) computeComposite(privKey group.Scalar, pubKey group.Element,
	blindTokens, elements []group.Element) (m, z group.Element) {
	seedDST := o.dst(dstSeedPrefix)
	compositeDST := o.dst(dstCompositePrefix)
	encCompositeDST := lengthPrefixEncode(compositeDST)

	encPkS := lengthPrefixEncode(pubKey.Bytes())
	// todo: draft is not clear here: how are we supposed to encode the list of elements here ?
	encToken := lengthPrefixEncode(serializeBatch(blindTokens))
	encElement := lengthPrefixEncode(serializeBatch(elements))
	encSeedDST := lengthPrefixEncode(seedDST)
	seed := o.hash.Hash(0, encPkS, encToken, encElement, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if privKey != nil {
		return o.computeCompositeFast(encSeed, encCompositeDST, privKey, blindTokens)
	}

	return o.computeCompositeClient(encSeed, encCompositeDST, blindTokens, elements)
}

func (o *oprf) hashTranscript(input, element, info []byte) []byte {
	finalizeDST := o.dst(dstFinalizePrefix)
	encInput := lengthPrefixEncode(input)
	encElement := lengthPrefixEncode(element)
	encInfo := lengthPrefixEncode(info)
	encDST := lengthPrefixEncode(finalizeDST)

	return o.hash.Hash(o.hash.OutputSize(), encInput, encElement, encInfo, encDST)
}

func (o *oprf) proofScalar(publicKey, a1, a2, a3, a4 group.Element) group.Scalar {
	challengeDST := o.dst(dstChallengePrefix)
	encPkS := lengthPrefixEncode(publicKey.Bytes())
	encA1 := lengthPrefixEncode(a1.Bytes())
	encA2 := lengthPrefixEncode(a2.Bytes())
	encA3 := lengthPrefixEncode(a3.Bytes())
	encA4 := lengthPrefixEncode(a4.Bytes())
	encDST := lengthPrefixEncode(challengeDST)

	return o.group.HashToScalar(encPkS, encA1, encA2, encA3, encA4, encDST)
}
