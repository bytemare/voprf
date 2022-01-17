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

var (
	errArrayLength        = errors.New("blinding init failed, non-nil array of incompatible length")
	errNilProofC          = errors.New("c proof is nil or empty")
	errNilProofS          = errors.New("s proof is nil or empty")
	errInvalidNumElements = errors.New("invalid number of element ")
)

// Client represents the Client/Verifier party in a (V)OPRF protocol session,
// and exposes relevant functions for its execution.
type Client struct {
	serverPublicKey *group.Point
	*oprf

	input          [][]byte
	blind          []*group.Scalar
	blindedElement []*group.Point
}

// State represents a client's state, allowing internal values to be exported and imported to resume a (V)OPRF session.
type State struct {
	Ciphersuite     Ciphersuite `json:"s"`
	Mode            Mode        `json:"m"`
	ServerPublicKey []byte      `json:"p,omitempty"`
	Input           [][]byte    `json:"i"`
	Blind           [][]byte    `json:"r"`
	Blinded         [][]byte    `json:"d"`
}

// Export extracts the client's internal values that can be imported in another client for session resumption.
func (c *Client) Export() *State {
	s := &State{
		Ciphersuite: c.id,
		Mode:        c.mode,
	}

	if c.serverPublicKey != nil {
		s.ServerPublicKey = serializePoint(c.serverPublicKey, pointLength(c.id))
	}

	if len(c.input) != len(c.blind) {
		panic("different number of input and blind values")
	}

	s.Input = make([][]byte, len(c.input))
	s.Blind = make([][]byte, len(c.blind))
	s.Blinded = make([][]byte, len(c.blindedElement))

	for i := 0; i < len(c.input); i++ {
		s.Input[i] = make([]byte, len(c.input[i]))
		copy(s.Input[i], c.input[i])
		s.Blind[i] = serializeScalar(c.blind[i], pointLength(c.id))
		s.Blinded[i] = serializePoint(c.blindedElement[i], pointLength(c.id))
	}

	return s
}

func (c *Client) Import(state *State) error {
	var err error

	if len(state.Input) != len(state.Blinded) {
		return errStateDiffInput
	}

	if len(state.Blinded) != 0 && len(state.Blinded) != len(state.Blind) {
		return errStateDiffBlind
	}

	if state.Mode == VOPRF && state.ServerPublicKey == nil {
		return errStateNoPubKey
	}

	c.oprf = suites[state.Ciphersuite].new(state.Mode)

	if state.ServerPublicKey != nil {
		c.serverPublicKey, err = c.group.NewElement().Decode(state.ServerPublicKey)
		if err != nil {
			return err
		}
	}

	c.blind = make([]*group.Scalar, len(state.Blind))
	for i := 0; i < len(state.Blind); i++ {
		c.blind[i], err = c.group.NewScalar().Decode(state.Blind[i])
		if err != nil {
			return err
		}
	}

	c.input = make([][]byte, len(state.Input))
	c.blindedElement = make([]*group.Point, len(state.Blinded))

	for i := 0; i < len(state.Blinded); i++ {
		c.input[i] = make([]byte, len(state.Input[i]))
		copy(c.input[i], state.Input[i])

		c.blindedElement[i], err = c.group.NewElement().Decode(state.Blinded[i])
		if err != nil {
			return fmt.Errorf("invalid blinded element: %w", err)
		}
	}

	return nil
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
		c.blindedElement = make([]*group.Point, length)
	} else if len(c.blindedElement) != length {
		return errArrayLength
	}

	return nil
}

func (c *Client) verifyProof(ev *evaluation, info []byte) error {
	if ev.proofC == nil {
		return errNilProofC
	}

	if ev.proofS == nil {
		return errNilProofS
	}

	var pk *group.Point
	var cs, ds []*group.Point

	if c.mode == VOPRF {
		cs, ds = c.blindedElement, ev.elements
		pk = c.serverPublicKey
	} else { // POPRF
		cs, ds = ev.elements, c.blindedElement
		tag := c.pTag(info)
		pk = c.id.Group().Base().Mult(tag).Add(c.serverPublicKey)
	}

	encGk := lengthPrefixEncode(serializePoint(pk, pointLength(c.id)))
	a0, a1 := c.computeComposites(nil, encGk, cs, ds)

	ab := c.group.Base().Mult(ev.proofS)
	ap := pk.Mult(ev.proofC)
	a2 := ab.Add(ap)

	bm := a0.Mult(ev.proofS)
	bz := a1.Mult(ev.proofC)
	a3 := bm.Add(bz)
	expectedC := c.challenge(encGk, a0, a1, a2, a3)

	if !ctEqual(expectedC.Bytes(), ev.proofC.Bytes()) {
		return errProofFailed
	}

	return nil
}

func (c *Client) innerBlind(input []byte, index int) {
	if c.blind[index] == nil {
		c.blind[index] = c.group.NewScalar().Random()
	}

	c.input[index] = input
	c.blindedElement[index] = c.HashToGroup(input).Mult(c.blind[index])
}

func (c *Client) unblind(evaluated *group.Point, blind *group.Scalar) *group.Point {
	return evaluated.InvertMult(blind)
}

// Blind blinds, or masks, the input with a preset or new random blinding element.
func (c *Client) Blind(input []byte) []byte {
	if err := c.initBlinding(1); err != nil {
		panic(err)
	}

	c.innerBlind(input, 0)

	return serializePoint(c.blindedElement[0], pointLength(c.id))
}

// BlindBatch allows blinding of batched input. If internal blinds are not set, new ones are created. In either case,
// the blinds are returned, and can safely be ignored if not needed externally. Subsequent calls on unblinding functions
// will automatically use the internal blinds, unless specified otherwise through unblindBatchWithBlinds().
func (c *Client) BlindBatch(input [][]byte) (blinds, blindedElements [][]byte, err error) {
	if err := c.initBlinding(len(input)); err != nil {
		return nil, nil, err
	}

	blinds = make([][]byte, len(input))
	blindedElements = make([][]byte, len(input))

	for i, in := range input {
		c.innerBlind(in, i)
		// Only keep the blinds in a multiplicative mode
		if c.blind[i] != nil {
			blinds[i] = serializeScalar(c.blind[i], scalarLength(c.id))
		}

		blindedElements[i] = serializePoint(c.blindedElement[i], pointLength(c.id))
	}

	return blinds, blindedElements, nil
}

// BlindBatchWithBlinds enables blinding batches while specifying which blinds to use.
func (c *Client) BlindBatchWithBlinds(blinds, input [][]byte) ([][]byte, error) {
	if len(blinds) != len(input) {
		return nil, errParamInputEqualLen
	}

	if err := c.initBlinding(len(blinds)); err != nil {
		return nil, err
	}

	blindedElements := make([][]byte, len(input))

	for i, blind := range blinds {
		s, err := c.group.NewScalar().Decode(blind)
		if err != nil {
			return nil, fmt.Errorf("input blind %d decoding errored with %w", i, err)
		}

		c.input[i] = input[i]
		c.blind[i] = s
		c.innerBlind(input[i], i)
		blindedElements[i] = serializePoint(c.blindedElement[i], pointLength(c.id))
	}

	return blindedElements, nil
}

func (o *oprf) hashTranscript(input, unblinded []byte) []byte {
	encInput := lengthPrefixEncode(input)
	encElement := lengthPrefixEncode(unblinded)
	encDST := []byte(dstFinalize)

	return o.hash.Hash(encInput, encElement, encDST)
}

func (o *oprf) hashTranscriptInfo(input, info, unblinded []byte) []byte {
	encInput := lengthPrefixEncode(input)
	encInfo := lengthPrefixEncode(info)
	encElement := lengthPrefixEncode(unblinded)
	encDST := []byte(dstFinalize)

	return o.hash.Hash(encInput, encInfo, encElement, encDST)
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

	if c.mode == VOPRF || c.mode == POPRF {
		if err := c.verifyProof(ev, info); err != nil {
			return nil, err
		}
	}

	out := make([][]byte, len(c.input))

	for i, ee := range ev.elements {
		u := c.unblind(ee, c.blind[i])
		// pi := c.HashToGroup(c.input[i])
		// out[i] = c.hashTranscriptInfo(serializePoint(pi, pointLength(c.id)), info, serializePoint(u, pointLength(c.id)))
		if c.mode == OPRF || c.mode == VOPRF {
			out[i] = c.hashTranscript(c.input[i], serializePoint(u, pointLength(c.id)))
		} else {
			out[i] = c.hashTranscriptInfo(c.input[i], info, serializePoint(u, pointLength(c.id)))
		}
	}

	return out, nil
}
