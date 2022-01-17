// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"fmt"

	"github.com/bytemare/crypto/group"
)

// Evaluation holds the serialized evaluated elements and serialized proof.
type Evaluation struct {
	// Elements represents the unique serialization of an Elements
	Elements [][]byte `json:"e"`

	// Proofs
	ProofC []byte `json:"c,omitempty"`
	ProofS []byte `json:"s,omitempty"`
}

// Serialize returns a compact encoding of the Evaluation.
func (e *Evaluation) Serialize() []byte {
	ne := len(e.Elements)
	lp := len(e.Elements[0])
	s := make([]byte, 0, 2+2+ne*lp)
	s = append(s, i2osp2(ne)...)
	s = append(s, i2osp2(lp)...)

	for _, el := range e.Elements {
		s = append(s, el...)
	}

	if e.ProofC != nil && e.ProofS != nil {
		s = append(s, e.ProofC...)
		s = append(s, e.ProofS...)
	}

	return s
}

// Deserialize decodes the input into the Evaluation.
func (e *Evaluation) Deserialize(input []byte) error {
	length := len(input)
	if length < 4 {
		return errEvalSerDeMin
	}

	ne := int(uint16(input[1]) | uint16(input[0])<<8)
	lp := int(uint16(input[3]) | uint16(input[2])<<8)

	if length < 4+ne*lp {
		return errEvalSerDeElements
	}

	e.Elements = make([][]byte, ne)

	offset := 4
	for i := 0; i < ne; i++ {
		e.Elements[i] = make([]byte, lp)
		copy(e.Elements[i], input[offset:offset+lp])
		offset += lp
	}

	// if there's more than elements, there might be proof
	if offset < length {
		proof := input[offset:]
		if len(proof)&1 == 1 {
			return errEvalSerDeProofLen
		}

		offset = len(proof) / 2
		e.ProofC = make([]byte, offset)
		copy(e.ProofC, proof[:offset])
		e.ProofS = make([]byte, offset)
		copy(e.ProofS, proof[offset:])
	}

	return nil
}

// deserialize returns a structure with the internal representations of the evaluated elements and proofs.
func (e *Evaluation) deserialize(g group.Group) (*evaluation, error) {
	var err error

	eval := &evaluation{
		elements: make([]*group.Point, len(e.Elements)),
	}

	for i, el := range e.Elements {
		elm, err := g.NewElement().Decode(el)
		if err != nil {
			return nil, fmt.Errorf("could not decode element : %w", err)
		}

		eval.elements[i] = elm
	}

	if len(e.ProofC) != 0 {
		eval.proofC, err = g.NewScalar().Decode(e.ProofC)
		if err != nil {
			return nil, fmt.Errorf("invalid c scalar proof: %w", err)
		}
	}

	if len(e.ProofS) != 0 {
		eval.proofS, err = g.NewScalar().Decode(e.ProofS)
		if err != nil {
			return nil, fmt.Errorf("invalid c scalar proof: %w", err)
		}
	}

	return eval, nil
}

// evaluation holds the evaluated elements and proofs in their internal representations.
type evaluation struct {
	elements []*group.Point
	proofC   *group.Scalar
	proofS   *group.Scalar
}

// serialize the components of the evaluation into byte arrays to be exposed in API.
func (e *evaluation) serialize(c Ciphersuite) *Evaluation {
	ev := &Evaluation{
		Elements: make([][]byte, len(e.elements)),
	}

	for i, el := range e.elements {
		ev.Elements[i] = serializePoint(el, pointLength(c))
	}

	if e.proofC != nil {
		ev.ProofC = serializeScalar(e.proofC, scalarLength(c))
	}

	if e.proofS != nil {
		ev.ProofS = serializeScalar(e.proofS, scalarLength(c))
	}

	return ev
}
