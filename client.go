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

	group "github.com/bytemare/crypto"
)

var (
	errArrayLength        = errors.New("blinding init failed, non-nil array of incompatible length")
	errNilProofC          = errors.New("c proof is nil or empty")
	errNilProofS          = errors.New("s proof is nil or empty")
	errInvalidNumElements = errors.New("invalid number of element ")
	errInvalidInput       = errors.New(
		"invalid input - OPRF input deterministically maps to the group identity element",
	)
)

// Client represents the Client/Verifier party in a (V)OPRF protocol session,
// and exposes relevant functions for its execution.
type Client struct {
	tweakedKey      *group.Element
	serverPublicKey *group.Element
	*oprf

	input          [][]byte
	blind          []*group.Scalar
	blindedElement []*group.Element
}

func (c *Client) initBlinding(length int) error {
	if len(c.input) == 0 {
		c.input = make([][]byte, length)
	} else if len(c.input) != length {
		return errArrayLength
	}

	if len(c.blind) == 0 {
		c.blind = make([]*group.Scalar, length)
	} else if len(c.blind) != length {
		return errArrayLength
	}

	if len(c.blindedElement) == 0 {
		c.blindedElement = make([]*group.Element, length)
	} else if len(c.blindedElement) != length {
		return errArrayLength
	}

	return nil
}

func (c *Client) verifyProof(ev *evaluation) error {
	if ev.proofC == nil {
		return errNilProofC
	}

	if ev.proofS == nil {
		return errNilProofS
	}

	var pk *group.Element
	var cs, ds []*group.Element

	if c.mode == VOPRF {
		cs, ds = c.blindedElement, ev.elements
		pk = c.serverPublicKey
	} else { // POPRF
		cs, ds = ev.elements, c.blindedElement
		pk = c.tweakedKey
	}

	encGk := lengthPrefixEncode(serializePoint(pk, pointLength(c.id)))
	a0, a1 := c.computeComposites(nil, encGk, cs, ds)

	ab := c.group.Base().Multiply(ev.proofS)
	ap := pk.Multiply(ev.proofC)
	a2 := ab.Add(ap)

	bm := a0.Multiply(ev.proofS)
	bz := a1.Multiply(ev.proofC)
	a3 := bm.Add(bz)
	expectedC := c.challenge(encGk, a0, a1, a2, a3)

	if !ctEqual(expectedC.Encode(), ev.proofC.Encode()) {
		return errProofFailed
	}

	return nil
}

func (c *Client) innerBlind(input, info []byte, index int) {
	if c.blind[index] == nil {
		c.blind[index] = c.group.NewScalar().Random()
	}

	c.input[index] = input

	if c.mode == POPRF {
		m := c.pTag(info)

		t := c.group.Base().Multiply(m).Add(c.serverPublicKey)
		if t.IsIdentity() {
			panic(errInvalidInput)
		}

		c.tweakedKey = t
	}

	p := c.HashToGroup(input)
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	c.blindedElement[index] = p.Multiply(c.blind[index])
}

func (c *Client) unblind(evaluated *group.Element, blind *group.Scalar) *group.Element {
	modInv := blind.Copy().Invert()
	return evaluated.Multiply(modInv)
}

// Blind masks the input with a preset or new random blinding element.
func (c *Client) Blind(input, info []byte) []byte {
	if err := c.initBlinding(1); err != nil {
		panic(err)
	}

	c.innerBlind(input, info, 0)

	return serializePoint(c.blindedElement[0], pointLength(c.id))
}

// BlindBatch allows blinding of batched input. If internal blinds are not set, new ones are created. In either case,
// the blinds are returned, and can safely be ignored if not needed externally. Subsequent calls on unblinding functions
// will automatically use the internal blinds, unless specified otherwise through unblindBatchWithBlinds().
func (c *Client) BlindBatch(input [][]byte, info []byte) (blinds, blindedElements [][]byte, err error) {
	if err := c.initBlinding(len(input)); err != nil {
		return nil, nil, err
	}

	blinds = make([][]byte, len(input))
	blindedElements = make([][]byte, len(input))

	for i, in := range input {
		c.innerBlind(in, info, i)
		// Only keep the blinds in a multiplicative mode
		if c.blind[i] != nil {
			blinds[i] = serializeScalar(c.blind[i], scalarLength(c.id))
		}

		blindedElements[i] = serializePoint(c.blindedElement[i], pointLength(c.id))
	}

	return blinds, blindedElements, nil
}

// BlindBatchWithBlinds enables blinding batches while specifying which blinds to use.
func (c *Client) BlindBatchWithBlinds(blinds, input [][]byte, info []byte) ([][]byte, error) {
	if len(blinds) != len(input) {
		return nil, errParamInputEqualLen
	}

	if err := c.initBlinding(len(blinds)); err != nil {
		return nil, err
	}

	blindedElements := make([][]byte, len(input))

	for i, blind := range blinds {
		s := c.group.NewScalar()
		if err := s.Decode(blind); err != nil {
			return nil, fmt.Errorf("input blind %d decoding errored with %w", i, err)
		}

		c.input[i] = input[i]
		c.blind[i] = s
		c.innerBlind(input[i], info, i)
		blindedElements[i] = serializePoint(c.blindedElement[i], pointLength(c.id))
	}

	return blindedElements, nil
}

func (o *oprf) hashTranscript(input, info, unblinded []byte) []byte {
	encInput := lengthPrefixEncode(input)

	encElement := lengthPrefixEncode(unblinded)
	encDST := []byte(dstFinalize)

	var hash []byte

	if info == nil { // OPRF and VOPRF
		hash = o.hash.Hash(encInput, encElement, encDST)
	} else { // POPRF, with info
		encInfo := lengthPrefixEncode(info)
		hash = o.hash.Hash(encInput, encInfo, encElement, encDST)
	}

	return hash
}

// Finalize finalizes the protocol execution by verifying the proof if necessary,
// unblinding the evaluated element, and hashing the transcript.
func (c *Client) Finalize(e *Evaluation, info []byte) ([]byte, error) {
	output, err := c.FinalizeBatch(e, info)
	if err != nil {
		return nil, err
	}

	return output[0], nil
}

// FinalizeBatch finalizes the protocol execution by verifying the proof if necessary,
// unblinding the evaluated elements, and hashing the transcript.
func (c *Client) FinalizeBatch(e *Evaluation, info []byte) ([][]byte, error) {
	if len(e.Elements) != len(c.input) {
		return nil, errParamFinalizeLen
	}

	ev, err := e.deserialize(c.group)
	if err != nil {
		return nil, err
	}

	if len(ev.elements) != len(c.blindedElement) {
		return nil, errInvalidNumElements
	}

	if c.mode == OPRF || c.mode == VOPRF {
		info = nil
	}

	if c.mode == VOPRF || c.mode == POPRF {
		if err := c.verifyProof(ev); err != nil {
			return nil, err
		}
	}

	out := make([][]byte, len(c.input))

	for i, ee := range ev.elements {
		u := c.unblind(ee, c.blind[i])
		out[i] = c.hashTranscript(c.input[i], info, serializePoint(u, pointLength(c.id)))
	}

	return out, nil
}
