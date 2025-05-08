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

	"github.com/bytemare/ecc"

	"github.com/bytemare/voprf"
	"github.com/bytemare/voprf/internal"
)

var (
	errInvalidPublicKey = errors.New("server public key is either nil or the identity element")
	errDifferentSize    = errors.New("number of evaluations differs from number of previously blinded elements")
	errInputNilEval     = errors.New("provided evaluation is nil")
	errInputNoEval      = errors.New("provided evaluation does not contain evaluations")
	errInputProofCNil   = errors.New("proof c is nil")
	errInputProofCZero  = errors.New("proof c is zero")
	errInputProofSNil   = errors.New("proof s is nil")
	errInputProofSZero  = errors.New("proof s is zero")
	errInvalidProof     = errors.New("invalid proof")
)

// Client is used for VOPRF or POPRF client executions. For OPRF or TOPRF, used oprf.Client.
type Client struct {
	oprf            *voprf.Client
	verifiable      *internal.Verifiable
	serverPublicKey *ecc.Element
	tweakedKey      *ecc.Element
	blindedInput    []*ecc.Element
}

// NewClient returns a client given the ciphersuite and the server's public key. poprfInfo must only be provided if
// the POPRF mode is requested. If poprfInfo is not provided or nil, the VOPRF mode is used.
func NewClient(cs voprf.Ciphersuite, serverPublicKey *ecc.Element, poprfInfo ...byte) (*Client, error) {
	if serverPublicKey == nil || serverPublicKey.IsIdentity() {
		return nil, errInvalidPublicKey
	}

	mode := internal.VOPRF

	// If info is given, then a POPRF is requested by the caller.
	if len(poprfInfo) != 0 {
		mode = internal.POPRF
	}

	c := internal.NewClient(mode, ecc.Group(cs))

	client := &Client{
		oprf: &voprf.Client{
			Client: c,
		},
		verifiable:      internal.NewVerifiable(c.Core, poprfInfo),
		serverPublicKey: serverPublicKey,
		tweakedKey:      nil,
		blindedInput:    []*ecc.Element{},
	}

	if mode == internal.POPRF {
		client.tweakedKey = client.verifiable.TweakPublicKey(serverPublicKey)
	}

	return client, nil
}

// SetBlind sets one or multiple blinds in the client's blind register. This is optional, and useful if you want to
// force usage of specific blinding scalar. If no blinding scalars are set, new, random blinds will be used.
func (c *Client) SetBlind(blind ...*ecc.Scalar) {
	c.oprf.SetBlind(blind...)
}

// Blind blinds the input using the first blinding scalar in the Client's register. If no blinding scalars were
// previously set, new, random blinds will be used.
func (c *Client) Blind(input []byte) *ecc.Element {
	c.blindedInput = make([]*ecc.Element, 1)
	c.blindedInput[0] = c.oprf.Blind(input)

	return c.blindedInput[0]
}

// BlindBatch blinds the given set, using either previously set blinds in the same order (if they have been set) or
// newly generated random blinds. Note that if not enough blinds were set, new, random blinds will be used as necessary.
func (c *Client) BlindBatch(inputs [][]byte) []*ecc.Element {
	c.blindedInput = c.oprf.BlindBatch(inputs)
	return c.blindedInput
}

// Finalize verifies the Server provided proofs, and, if they are valid, unblinds the evaluated element and returns
// the protocol output.
func (c *Client) Finalize(evaluation *Evaluation) ([]byte, error) {
	if err := c.checkEvaluation(evaluation); err != nil {
		return nil, err
	}

	if !c.verifyProof(evaluation) {
		return nil, errInvalidProof
	}

	return c.oprf.Client.Finalize(0, evaluation.Evaluations[0], c.verifiable.POPRFInfo...), nil
}

// FinalizeBatch verifies the Server provided proofs, and, if they are valid, unblinds the evaluated elements and
// returns the protocol output.
func (c *Client) FinalizeBatch(evaluation *Evaluation) ([][]byte, error) {
	if err := c.checkEvaluation(evaluation); err != nil {
		return nil, err
	}

	if !c.verifyProof(evaluation) {
		return nil, errInvalidProof
	}

	return c.oprf.Client.FinalizeBatch(evaluation.Evaluations, c.verifiable.POPRFInfo...), nil
}

func (c *Client) verifyProof(evaluation *Evaluation) bool {
	var (
		pk     *ecc.Element
		cs, ds []*ecc.Element
	)

	if c.oprf.Mode == internal.VOPRF {
		cs, ds = c.blindedInput, evaluation.Evaluations
		pk = c.serverPublicKey
	} else { // POPRF
		cs, ds = evaluation.Evaluations, c.blindedInput
		pk = c.tweakedKey
	}

	return c.verifiable.VerifyProof(evaluation.Proof[0], evaluation.Proof[1], pk, cs, ds)
}

func (c *Client) checkEvaluation(evaluation *Evaluation) error {
	switch {
	case evaluation == nil:
		return errInputNilEval
	case evaluation.Proof[0] == nil:
		return errInputProofCNil
	case evaluation.Proof[0].IsZero():
		return errInputProofCZero
	case evaluation.Proof[1] == nil:
		return errInputProofSNil
	case evaluation.Proof[1].IsZero():
		return errInputProofSZero
	case len(evaluation.Evaluations) == 0:
		return errInputNoEval
	case len(evaluation.Evaluations) != len(c.blindedInput):
		// combined with the previous check this check, this also implies that len(c.blindedInput) >= 1
		return errDifferentSize
	default:
		return nil
	}
}
