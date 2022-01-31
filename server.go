// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"errors"
	"fmt"

	"github.com/bytemare/crypto/group"
)

// Server holds the (V)OPRF prover data.
type Server struct {
	privateKey *group.Scalar
	publicKey  *group.Point
	*oprf
	nonceR []byte
}

var errZeroScalar = errors.New("inversion led to zero scalar")

func (s *Server) randomScalar() (r *group.Scalar) {
	if s.nonceR == nil {
		r = s.group.NewScalar().Random()
	} else {
		var err error
		r, err = s.group.NewScalar().Decode(s.nonceR)
		if err != nil {
			panic(err)
		}
	}

	return r
}

func (s *Server) generateProof(k *group.Scalar, pk *group.Point, cs, ds []*group.Point) (proofC, proofS *group.Scalar) {
	encPk := lengthPrefixEncode(serializePoint(pk, pointLength(s.id)))
	a0, a1 := s.computeComposites(k, encPk, cs, ds)
	r := s.randomScalar()

	a2 := s.group.Base().Mult(r)
	a3 := a0.Mult(r)

	proofC = s.challenge(encPk, a0, a1, a2, a3)
	proofS = r.Sub(proofC.Mult(k))

	return proofC, proofS
}

// KeyGen generates and sets a new private/public key pair.
func (s *Server) KeyGen() {
	s.privateKey = s.group.NewScalar().Random()
	s.publicKey = s.group.Base().Mult(s.privateKey)
}

// Evaluate the input with the private key.
func (s *Server) Evaluate(blindedElement, info []byte) (*Evaluation, error) {
	return s.EvaluateBatch([][]byte{blindedElement}, info)
}

// EvaluateBatch evaluates the input batch of blindedElements and returns a pointer to the Evaluation. If the server
// was set to be un VOPRF mode, the proof will be included in the Evaluation.
func (s *Server) EvaluateBatch(blindedElements [][]byte, info []byte) (*Evaluation, error) {
	ev := &evaluation{}
	ev.elements = make([]*group.Point, len(blindedElements))

	var blinded []*group.Point
	var scalar, t *group.Scalar

	if s.mode == POPRF {
		context := s.pTag(info)
		t = s.privateKey.Add(context)
		scalar = t.Invert()
		if scalar.IsZero() {
			return nil, errZeroScalar
		}
	} else {
		scalar = s.privateKey
	}

	if s.mode == VOPRF || s.mode == POPRF {
		blinded = make([]*group.Point, len(blindedElements))
	}

	// decode and evaluate element(s)
	for i, b := range blindedElements {
		b, err := s.group.NewElement().Decode(b)
		if err != nil {
			return nil, fmt.Errorf("OPRF can't evaluate input : %w", err)
		}

		if s.mode == VOPRF || s.mode == POPRF {
			blinded[i] = b
		}

		ev.elements[i] = b.Mult(scalar)
	}

	if s.mode == VOPRF {
		ev.proofC, ev.proofS = s.generateProof(s.privateKey, s.publicKey, blinded, ev.elements)
	} else if s.mode == POPRF {
		tweakedKey := s.group.Base().Mult(t)
		ev.proofC, ev.proofS = s.generateProof(t, tweakedKey, ev.elements, blinded)
	}

	return ev.serialize(s.id), nil
}

// FullEvaluate reproduces the full PRF but without the blinding operations, using the client's input.
// This should output the same digest as the client's Finalize() function.
func (s *Server) FullEvaluate(input, info []byte) ([]byte, error) {
	p := s.HashToGroup(input)

	var scalar *group.Scalar
	if s.mode == OPRF || s.mode == VOPRF {
		scalar = s.privateKey
	} else {
		// s.mode == POPRF
		context := s.pTag(info)
		k := s.privateKey.Add(context)
		scalar = k.Invert()
		if scalar.IsZero() {
			return nil, errZeroScalar
		}
	}

	t := p.Mult(scalar)

	if s.mode == POPRF {
		return s.hashTranscriptInfo(input, info, serializePoint(t, pointLength(s.id))), nil
	}

	// return s.hashTranscriptInfo(serializePoint(p, pointLength(s.id)), info, serializePoint(t, scalarLength(s.id)))
	// return s.hashTranscriptInfo(input, info, serializePoint(t, scalarLength(s.id)))
	return s.hashTranscript(input, serializePoint(t, pointLength(s.id))), nil
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
	return serializeScalar(s.privateKey, scalarLength(s.id))
}

// PublicKey returns the server's serialized public key.
func (s *Server) PublicKey() []byte {
	return serializePoint(s.publicKey, pointLength(s.id))
}

// Ciphersuite returns the cipher suite used in s' instance.
func (s *Server) Ciphersuite() Ciphersuite {
	return s.id
}
