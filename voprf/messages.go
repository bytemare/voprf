// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package voprf implements RFC9497 and provides abstracted access to Oblivious Pseudorandom Functions (OPRF) and
// Threshold Oblivious Pseudorandom Functions (TOPRF) using Elliptic Curve Prime Order Groups (EC-OPRF).
// For VOPRF and POPRF use the github.com/bytemare/oprf/voprf package.
package voprf

import (
	"encoding/json"
	"errors"
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/voprf"
	"github.com/bytemare/voprf/internal"
)

var (
	errUnmarshalEvaluationShort = errors.New("decoding error: insufficient data length")
	errUnmarshalEvaluationEvals = errors.New("decoding error: wrong encoding length")
	errDecodeNoCiphersuite      = errors.New("decoding error: ciphersuite not set")
)

// Evaluation is the VOPRF and POPRF servers' output, containing the verifiable proof and evaluated elements.
// To decode a byte string back to an Evaluation, the SetCiphersuite must be used with the relevant ciphersuite.
type Evaluation struct {
	// Proof is the NIZK proof over the Evaluations elements.
	Proof [2]*group.Scalar `json:"p"`

	// Evaluations is the set of evaluated elements.
	Evaluations []*group.Element `json:"e"`
	group       group.Group
}

func (e *Evaluation) encodeProof() [2][]byte {
	return [2][]byte{
		e.Proof[0].Encode(),
		e.Proof[1].Encode(),
	}
}

func (e *Evaluation) encodeEvaluations() []byte {
	nEval := len(e.Evaluations)
	lenEval := len(e.Evaluations[0].Encode())

	output := make([]byte, 0, 2+nEval*lenEval)
	output = append(output, internal.I2osp2(nEval)...)

	for _, eval := range e.Evaluations {
		output = append(output, eval.Encode()...)
	}

	return output
}

func (e *Evaluation) encodeEvaluationsSplit() [][]byte {
	output := make([][]byte, len(e.Evaluations))
	for i, eval := range e.Evaluations {
		output[i] = eval.Encode()
	}

	return output
}

// Serialize returns the compact byte encoding of the Evaluation.
func (e *Evaluation) Serialize() []byte {
	proof := e.encodeProof()
	evaluations := e.encodeEvaluations()

	output := make([]byte, 0, 2*e.group.ScalarLength()+len(evaluations))
	output = append(output, proof[0]...)
	output = append(output, proof[1]...)
	output = append(output, evaluations...)

	return output
}

// SetCiphersuite needs to be set by a client on a new Evaluation before decoding it from its compact serialization.
func (e *Evaluation) SetCiphersuite(c voprf.Ciphersuite) {
	e.group = c.Group()
}

func decodeProof(g group.Group, data []byte) ([]*group.Scalar, error) {
	sLen := g.ScalarLength()

	pc := g.NewScalar()
	if err := pc.Decode(data[:sLen]); err != nil {
		return nil, fmt.Errorf("invalid c proof encoding: %w", err)
	}

	ps := g.NewScalar()
	if err := ps.Decode(data[sLen : 2*sLen]); err != nil {
		return nil, fmt.Errorf("invalid s proof encoding: %w", err)
	}

	return []*group.Scalar{pc, ps}, nil
}

func decodeEvaluations(g group.Group, output []*group.Element, data []byte) error {
	pLen := g.ElementLength()
	i := 0

	for offset := 0; offset < len(output); offset += pLen {
		decoded := g.NewElement()
		if err := decoded.Decode(data[offset : offset+pLen]); err != nil {
			return fmt.Errorf("invalid evaluation encoding - element %d: %w", i, err)
		}

		output[i] = decoded
		i++
	}

	return nil
}

func decodeEvaluationsSplit(g group.Group, output []*group.Element, data [][]byte) error {
	for i, eval := range data {
		decoded := g.NewElement()
		if err := decoded.Decode(eval); err != nil {
			return fmt.Errorf("invalid evaluation encoding - element %d: %w", i, err)
		}

		output[i] = decoded
	}

	return nil
}

// Deserialize decodes a compact serialization of an Evaluation into e.
func (e *Evaluation) Deserialize(data []byte) error {
	if e.group == 0 {
		return errDecodeNoCiphersuite
	}

	sLen := e.group.ScalarLength()
	pLen := e.group.ElementLength()

	expectedProofLen := 2 * sLen
	minimalEvaluationLength := 2 + pLen

	if len(data) < expectedProofLen+minimalEvaluationLength {
		return errUnmarshalEvaluationShort
	}

	evaluationOffset := expectedProofLen
	nbEvals := int(uint16(data[evaluationOffset+1]) | uint16(data[evaluationOffset])<<8)
	evaluations := data[evaluationOffset+2:]

	if len(evaluations) != nbEvals*pLen {
		return errUnmarshalEvaluationEvals
	}

	proof, err := decodeProof(e.group, data[:expectedProofLen])
	if err != nil {
		return err
	}

	evals := make([]*group.Element, nbEvals)
	if err = decodeEvaluations(e.group, evals, evaluations); err != nil {
		return err
	}

	e.Proof[0] = proof[0]
	e.Proof[1] = proof[1]
	e.Evaluations = evals

	return nil
}

// MarshalBinary encodes the Evaluation into its binary form.
func (e *Evaluation) MarshalBinary() ([]byte, error) {
	return e.Serialize(), nil
}

// UnmarshalBinary decodes the binary form of an Evaluation into e.
func (e *Evaluation) UnmarshalBinary(data []byte) error {
	return e.Deserialize(data)
}

// MarshalJSON encodes the Evaluation into JSON.
func (e *Evaluation) MarshalJSON() ([]byte, error) {
	enc := struct {
		Proof [2][]byte `json:"p"`
		Eval  [][]byte  `json:"e"`
	}{
		Proof: e.encodeProof(),
		Eval:  e.encodeEvaluationsSplit(),
	}

	out, err := json.Marshal(enc)
	if err != nil {
		return nil, fmt.Errorf("encoding evaluation: %w", err)
	}

	return out, nil
}

// UnmarshalJSON decodes a JSON encoded Evaluation into e.
func (e *Evaluation) UnmarshalJSON(data []byte) error {
	if e.group == 0 {
		return errDecodeNoCiphersuite
	}

	enc := struct {
		Proof [2][]byte `json:"p"`
		Eval  [][]byte  `json:"e"`
	}{
		Proof: [2][]byte{},
		Eval:  [][]byte{},
	}

	if err := json.Unmarshal(data, &enc); err != nil {
		return err
	}

	pc := e.group.NewScalar()
	if err := pc.Decode(enc.Proof[0]); err != nil {
		return fmt.Errorf("invalid c proof encoding: %w", err)
	}

	ps := e.group.NewScalar()
	if err := ps.Decode(enc.Proof[1]); err != nil {
		return fmt.Errorf("invalid s proof encoding: %w", err)
	}

	evals := make([]*group.Element, len(enc.Eval))
	if err := decodeEvaluationsSplit(e.group, evals, enc.Eval); err != nil {
		return err
	}

	e.Proof[0] = pc
	e.Proof[1] = ps
	e.Evaluations = evals

	return nil
}
