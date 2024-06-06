// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"errors"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/voprf"
	"github.com/bytemare/voprf/internal"
)

// Server is used for VOPRF or POPRF server executions. For OPRF or TOPRF, used the oprf package (no need for a server
// instance).
type Server struct {
	// OPRF
	*internal.Verifiable

	// VOPRF
	privateKey *group.Scalar
	publicKey  *group.Element

	// POPRF
	scalar     *group.Scalar
	t          *group.Scalar
	tweakedKey *group.Element
}

// NewServer returns a server instance given a ciphersuite. poprfInfo must only be provided if
// the POPRF mode is requested. If poprfInfo is not provided or nil, the VOPRF mode is used.
func NewServer(cs voprf.Ciphersuite, poprfInfo ...byte) *Server {
	mode := internal.VOPRF
	if len(poprfInfo) != 0 {
		mode = internal.POPRF
	}

	s := &Server{
		Verifiable: internal.NewVerifiable(internal.LoadConfiguration(group.Group(cs), mode), poprfInfo),
		privateKey: nil,
		publicKey:  nil,
		scalar:     nil,
		t:          nil,
		tweakedKey: nil,
	}

	return s
}

var (
	errInvalidPrivateKey = errors.New("private key is nil or zero")
	errInvalidKeyPair    = errors.New("input public key doesn't belong to the private key")
)

func checkKeys(g group.Group, privateKey *group.Scalar, publicKey *group.Element) error {
	if publicKey == nil || publicKey.IsIdentity() {
		return errInvalidPublicKey
	}

	if privateKey == nil || privateKey.IsZero() {
		return errInvalidPrivateKey
	}

	if g.Base().Multiply(privateKey).Equal(publicKey) != 1 {
		return errInvalidKeyPair
	}

	return nil
}

func (s *Server) setKeyPair(privateKey *group.Scalar, publicKey *group.Element) {
	s.privateKey = privateKey
	s.publicKey = publicKey

	if s.Core.Mode == internal.POPRF {
		s.scalar, s.t = s.Verifiable.TweakPrivateKey(privateKey)
		s.tweakedKey = s.Core.Group.Base().Multiply(s.t)
	} else {
		s.scalar = s.privateKey
	}
}

// SetKeyPair sets the server's private and public key pair. This returns an error if either key is nil, the public key
// is the identity element, or if it doesn't match as a public key to the provided private key.
func (s *Server) SetKeyPair(privateKey *group.Scalar, publicKey *group.Element) error {
	if err := checkKeys(s.Core.Group, privateKey, publicKey); err != nil {
		return err
	}

	s.setKeyPair(privateKey, publicKey)

	return nil
}

// DeriveKeyPair derives and set the server's private and public key pair given a secret seed and instance specific
// info.
func (s *Server) DeriveKeyPair(seed, info []byte) {
	sk, pk := s.Core.DeriveKeyPair(seed, info)
	s.setKeyPair(sk, pk)
}

// GenerateKeys generates and sets a new, random private and public key pair.
func (s *Server) GenerateKeys() {
	sk := s.Core.Group.NewScalar().Random()
	pk := s.Core.Group.Base().Multiply(sk)
	s.setKeyPair(sk, pk)
}

// KeyPair returns the server's private and public key pair.
func (s *Server) KeyPair() (*group.Scalar, *group.Element) {
	return s.privateKey, s.publicKey
}

func (s *Server) evaluate(
	blinded []*group.Element,
	random []*group.Scalar,
) *Evaluation {
	// Set the random element for the proof
	r := s.Group.NewScalar()
	if len(random) != 0 && random[0] != nil {
		r = random[0]
	} else {
		r.Random()
	}

	// Evaluate
	evaluated := voprf.EvaluateBatch(s.scalar, blinded)

	var proofC, proofS *group.Scalar

	if s.Core.Mode == internal.VOPRF {
		proofC, proofS = s.Verifiable.GenerateProof(r, s.privateKey, s.publicKey, blinded, evaluated)
	} else { // POPRF
		proofC, proofS = s.Verifiable.GenerateProof(r, s.t, s.tweakedKey, evaluated, blinded)
	}

	return &Evaluation{
		group: s.Group,
		Proof: [2]*group.Scalar{
			proofC, proofS,
		},
		Evaluations: evaluated,
	}
}

// Evaluate takes the Client provided blinded element and evaluates it, returning the evaluated element and the
// NIZK proof. The random argument is optional, and enables to force the use of that scalar for the random input to the
// NIZK proof.
func (s *Server) Evaluate(
	blinded *group.Element,
	random ...*group.Scalar,
) *Evaluation {
	sBlinded := []*group.Element{blinded}
	return s.evaluate(sBlinded, random)
}

// EvaluateBatch takes the Client provided blinded elements and evaluates them, returning the evaluated elements and the
// unique NIZK proof for the whole set. The random argument is optional, and enables to force the use of that scalar for
// the random input to the NIZK proof.
func (s *Server) EvaluateBatch(
	blinded []*group.Element,
	random ...*group.Scalar,
) *Evaluation {
	return s.evaluate(blinded, random)
}
