package voprf

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
)

// Evaluation holds the serialised evaluated elements and serialised proof.
type Evaluation struct {
	// Elements represents the unique serialization of an Elements
	Elements [][]byte `json:"e"`

	// Proofs
	ProofC []byte `json:"c,omitempty"`
	ProofS []byte `json:"s,omitempty"`
}

// DecodeEvaluation decodes the encoded input evaluation in the specified encoding.
func DecodeEvaluation(evaluation []byte, enc encoding.Encoding) (*Evaluation, error) {
	ev, err := enc.Decode(evaluation, &Evaluation{})
	if err != nil {
		return nil, fmt.Errorf("could not decode evaluation : %w", err)
	}

	eva, ok := ev.(*Evaluation)
	if !ok {
		return nil, errInternalDecodeEval
	}

	return eva, nil
}

// Encode encodes the evaluation to the given format.
func (e *Evaluation) Encode(enc encoding.Encoding) ([]byte, error) {
	if enc == 0 {
		return nil, errParamNoEncoding
	}

	return enc.Encode(e)
}

// deserialize returns a structure with the internal representations of the evaluated elements and proofs.
func (e *Evaluation) deserialize(g group.Group) (*evaluation, error) {
	var err error

	evaluation := &evaluation{
		elements: make([]group.Element, len(e.Elements)),
	}

	for i, el := range e.Elements {
		elm, err := g.NewElement().Decode(el)
		if err != nil {
			return nil, fmt.Errorf("could not decode element : %w", err)
		}

		evaluation.elements[i] = elm
	}

	if len(e.ProofC) != 0 {
		evaluation.proofC, err = g.NewScalar().Decode(e.ProofC)
		if err != nil {
			return nil, err
		}
	}

	if len(e.ProofS) != 0 {
		evaluation.proofS, err = g.NewScalar().Decode(e.ProofS)
		if err != nil {
			return nil, err
		}
	}

	return evaluation, nil
}

// evaluation holds the evaluated elements and proofs in their internal representations.
type evaluation struct {
	elements []group.Element
	proofC   group.Scalar
	proofS   group.Scalar
}

// serialize serializes the components of the evaluation into byte arrays to be exposed in API.
func (e *evaluation) serialize() *Evaluation {
	ev := &Evaluation{
		Elements: make([][]byte, len(e.elements)),
	}

	for i, el := range e.elements {
		ev.Elements[i] = el.Bytes()
	}

	if e.proofC != nil {
		ev.ProofC = e.proofC.Bytes()
	}

	if e.proofS != nil {
		ev.ProofS = e.proofS.Bytes()
	}

	return ev
}
