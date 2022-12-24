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

	group "github.com/bytemare/crypto"
)

// Server holds the (V)OPRF prover data.
type Server struct {
	privateKey *group.Scalar
	publicKey  *group.Element
	*oprf
	nonceR []byte
}

// KeyGen generates and sets a new private/public key pair.
func (s *Server) KeyGen() {
	s.privateKey = s.group.NewScalar().Random()
	s.publicKey = s.group.Base().Multiply(s.privateKey)
}

// Evaluate the input with the private key.
func (s *Server) Evaluate(blindedElement, info []byte) (*Evaluation, error) {
	return s.EvaluateBatch([][]byte{blindedElement}, info)
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

func (s *Server) randomScalar() *group.Scalar {
	r := s.group.NewScalar()

	if s.nonceR == nil {
		r.Random()
	} else {
		if err := r.Decode(s.nonceR); err != nil {
			panic(err)
		}
	}

	return r
}

// EvaluateBatch evaluates the input batch of blindedElements and returns a pointer to the Evaluation. If the server
// was set to be un VOPRF mode, the proof will be included in the Evaluation.
func (s *Server) EvaluateBatch(blindedElements [][]byte, info []byte) (*Evaluation, error) {
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

	if s.mode == VOPRF || s.mode == POPRF {
		blinded = make([]*group.Element, len(blindedElements))
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
	random := s.randomScalar()

	if s.mode == VOPRF {
		ev.proofC, ev.proofS = s.oprf.generateProof(random, s.privateKey, s.publicKey, blinded, ev.elements)
	} else if s.mode == POPRF {
		tweakedKey := s.group.Base().Multiply(t)
		ev.proofC, ev.proofS = s.oprf.generateProof(random, t, tweakedKey, ev.elements, blinded)
	}

	return ev.serialize(), nil
}

// FullEvaluate reproduces the full PRF but without the blinding operations, using the client's input.
// This should output the same digest as the client's Finalize() function.
func (s *Server) FullEvaluate(input, info []byte) ([]byte, error) {
	p := s.HashToGroup(input)

	scalar, _, err := s.getPrivateKeys(info)
	if err != nil {
		return nil, err
	}

	t := p.Multiply(scalar)

	if s.oprf.mode == OPRF || s.oprf.mode == VOPRF {
		info = nil
	}

	return s.hashTranscript(input, info, t.Encode()), nil
}

// VerifyFinalize takes the client input (the un-blinded element) and the client's finalize() output,
// and returns whether it can match the client's output.
func (s *Server) VerifyFinalize(input, info, output []byte) bool {
	digest, err := s.FullEvaluate(input, info)
	if err != nil {
		return false
	}

	return ctEqual(digest, output)
}

// VerifyFinalizeBatch takes the batch of client input (the un-blinded elements) and the client's finalize() outputs,
// and returns whether it can match the client's outputs.
func (s *Server) VerifyFinalizeBatch(input, output [][]byte, info []byte) bool {
	res := true

	for i, in := range input {
		res = s.VerifyFinalize(in, info, output[i])
	}

	return res
}

// PrivateKey returns the server's serialized private key.
func (s *Server) PrivateKey() []byte {
	return s.privateKey.Encode()
}

// PublicKey returns the server's serialized public key.
func (s *Server) PublicKey() []byte {
	return s.publicKey.Encode()
}

// Ciphersuite returns the cipher suite used in s' instance.
func (s *Server) Ciphersuite() Ciphersuite {
	return s.oprf.id
}
