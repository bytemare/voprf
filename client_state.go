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

// State represents a client's state, allowing internal values to be exported and imported to resume a (V)OPRF session.
type State struct {
	Identifier      Identifier `json:"s"`
	ServerPublicKey []byte     `json:"p,omitempty"`
	Input           [][]byte   `json:"i"`
	Blind           [][]byte   `json:"r"`
	Blinded         [][]byte   `json:"d"`
	Mode            Mode       `json:"m"`
}

// Export extracts the client's internal values that can be imported in another client for session resumption.
func (c *Client) Export() *State {
	s := &State{
		ServerPublicKey: nil,
		Input:           nil,
		Blind:           nil,
		Blinded:         nil,
		Identifier:      c.id,
		Mode:            c.mode,
	}

	if c.serverPublicKey != nil {
		s.ServerPublicKey = c.serverPublicKey.Encode()
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
		s.Blind[i] = c.blind[i].Encode()
		s.Blinded[i] = c.blindedElement[i].Encode()
	}

	return s
}

func (c *Client) importPrecheck(state *State) error {
	if len(state.Input) != len(state.Blinded) {
		return errStateDiffInput
	}

	if len(state.Blinded) != 0 && len(state.Blinded) != len(state.Blind) {
		return errStateDiffBlind
	}

	if state.Mode == VOPRF && state.ServerPublicKey == nil {
		return errStateNoPubKey
	}

	return nil
}

func (c *Client) importPublicKey(state *State) error {
	if state.ServerPublicKey != nil {
		pk := c.group.NewElement()
		if err := pk.Decode(state.ServerPublicKey); err != nil {
			return fmt.Errorf("server public key - %w", err)
		}

		c.serverPublicKey = pk
	}

	return nil
}

func (c *Client) importBlinds(state *State) error {
	c.blind = make([]*group.Scalar, len(state.Blind))
	for i := 0; i < len(state.Blind); i++ {
		blind := c.group.NewScalar()
		if err := blind.Decode(state.Blind[i]); err != nil {
			return fmt.Errorf("blind %d - %w", i, err)
		}

		c.blind[i] = blind
	}

	return nil
}

func (c *Client) importBlinded(state *State) error {
	c.input = make([][]byte, len(state.Input))
	c.blindedElement = make([]*group.Element, len(state.Blinded))

	for i := 0; i < len(state.Blinded); i++ {
		c.input[i] = make([]byte, len(state.Input[i]))
		copy(c.input[i], state.Input[i])

		blinded := c.group.NewElement()
		if err := blinded.Decode(state.Blinded[i]); err != nil {
			return fmt.Errorf("invalid blinded element: %w", err)
		}

		c.blindedElement[i] = blinded
	}

	return nil
}

// Import populates the client's internal values with those found in the state, from which a session can be resumed.
func (c *Client) Import(state *State) error {
	if err := c.importPrecheck(state); err != nil {
		return err
	}

	c.oprf = suites[state.Identifier].new(state.Mode)

	if err := c.importPublicKey(state); err != nil {
		return err
	}

	if err := c.importBlinds(state); err != nil {
		return err
	}

	if err := c.importBlinded(state); err != nil {
		return err
	}

	return nil
}
