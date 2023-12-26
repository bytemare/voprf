// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"fmt"

	group "github.com/bytemare/crypto"
)

// Server holds the (V)OPRF prover data.
type Server struct {
	privateKey *group.Scalar
	publicKey  *group.Element
	*oprf
}

// KeyGen generates and sets a new private/public key pair.
func (s *Server) KeyGen() {
	s.privateKey = s.group.NewScalar().Random()
	s.publicKey = s.group.Base().Multiply(s.privateKey)
}

// Evaluate the input with the private key.
func (s *Server) Evaluate(blindedElement, info []byte) (*Evaluation, error) {
	return s.innerEvaluateBatch([][]byte{blindedElement}, nil, info)
}

// EvaluateWithRandom does the same as Evaluate and allows to provide a random input for proof generation.
func (s *Server) EvaluateWithRandom(blindedElement, random, info []byte) (*Evaluation, error) {
	return s.innerEvaluateBatch([][]byte{blindedElement}, random, info)
}

func (s *Server) getPrivateKeys(info []byte) (scalar, t *group.Scalar, err error) {
	if s.mode == POPRF {
		context := s.pTag(info)
		t = s.privateKey.Copy().Add(context)
		scalar = t.Copy().Invert()

		if scalar.IsZero() {
			return nil, nil, errZeroScalar
		}
	} else {
		scalar = s.privateKey
	}

	return scalar, t, nil
}

func setRandom(r *group.Scalar, random []byte) error {
	if len(random) == 0 {
		r.Random()
	} else {
		if err := r.Decode(random); err != nil {
			return fmt.Errorf("decoding input random scalar: %w", err)
		}
	}

	return nil
}

func (s *Server) innerEvaluateBatch(blindedElements [][]byte, random, info []byte) (*Evaluation, error) {
	ev := &evaluation{
		proofC:   nil,
		proofS:   nil,
		elements: nil,
	}
	ev.elements = make([]*group.Element, len(blindedElements))

	var blinded []*group.Element
	var scalar, t *group.Scalar

	scalar, t, err := s.getPrivateKeys(info)
	if err != nil {
		return nil, err
	}

	var r *group.Scalar

	if s.mode == VOPRF || s.mode == POPRF {
		blinded = make([]*group.Element, len(blindedElements))

		r = s.group.NewScalar()
		if err := setRandom(r, random); err != nil {
			return nil, err
		}
	}

	// decode and evaluate element(s)
	for i, bytes := range blindedElements {
		b := s.group.NewElement()
		if err := b.Decode(bytes); err != nil {
			return nil, fmt.Errorf("OPRF can't evaluate input : %w", err)
		}

		if s.mode == VOPRF || s.mode == POPRF {
			blinded[i] = b
		}

		ev.elements[i] = b.Copy().Multiply(scalar)
	}

	// generate proof
	if s.mode == VOPRF {
		ev.proofC, ev.proofS = s.oprf.generateProof(r, s.privateKey, s.publicKey, blinded, ev.elements)
	} else if s.mode == POPRF {
		tweakedKey := s.group.Base().Multiply(t)
		ev.proofC, ev.proofS = s.oprf.generateProof(r, t, tweakedKey, ev.elements, blinded)
	}

	return ev.serialize(), nil
}

// EvaluateBatch evaluates the input batch of blindedElements and returns a pointer to the Evaluation. If the server
// was set to be un VOPRF mode, the proof will be included in the Evaluation.
func (s *Server) EvaluateBatch(blindedElements [][]byte, info []byte) (*Evaluation, error) {
	return s.innerEvaluateBatch(blindedElements, nil, info)
}

// EvaluateBatchWithRandom does the same as EvaluateBatch and allows to provide a random input for proof generation.
func (s *Server) EvaluateBatchWithRandom(blindedElements [][]byte, random, info []byte) (*Evaluation, error) {
	return s.innerEvaluateBatch(blindedElements, random, info)
}

// PrivateKey returns the server's serialized private key.
func (s *Server) PrivateKey() []byte {
	return s.privateKey.Encode()
}

// PublicKey returns the server's serialized public key.
func (s *Server) PublicKey() []byte {
	return s.publicKey.Encode()
}

// Ciphersuite returns the cipher suite used in the server's instance.
func (s *Server) Ciphersuite() Ciphersuite {
	return s.oprf.ciphersuite
}
