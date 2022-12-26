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

// State represents a client's state, allowing internal values to be exported and imported to resume a session.
type State struct {
	Identifier      Identifier `json:"s"`
	TweakedKey      []byte     `json:"t,omitempty"`
	ServerPublicKey []byte     `json:"p,omitempty"`
	Input           [][]byte   `json:"i"`
	Blind           [][]byte   `json:"r"`
	Blinded         [][]byte   `json:"d"`
	Mode            Mode       `json:"m"`
}

// Export extracts the client's internal values that can be imported in another client for session resumption.
func (c *Client) Export() *State {
	s := &State{
		Identifier:      c.id,
		TweakedKey:      nil,
		ServerPublicKey: nil,
		Input:           nil,
		Blind:           nil,
		Blinded:         nil,
		Mode:            c.mode,
	}

	if c.serverPublicKey != nil {
		s.ServerPublicKey = c.serverPublicKey.Encode()
	}

	if c.tweakedKey != nil {
		s.TweakedKey = c.tweakedKey.Encode()
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

// RecoverClient returns a Client recovered form the state, from which a session can be resumed.
func (s *State) RecoverClient() (*Client, error) {
	if s.Mode != OPRF && s.Mode != VOPRF && s.Mode != POPRF {
		return nil, errParamInvalidMode
	}

	if !s.Identifier.Available() {
		return nil, errParamInvalidID
	}

	c := s.Identifier.client(s.Mode)

	if err := importPrecheck(s); err != nil {
		return nil, err
	}

	c.oprf = s.Identifier.new(s.Mode)

	if err := c.importTweakedKey(s); err != nil {
		return nil, err
	}

	if err := c.importPublicKey(s); err != nil {
		return nil, err
	}

	if err := c.importBlinds(s); err != nil {
		return nil, err
	}

	if err := c.importBlinded(s); err != nil {
		return nil, err
	}

	return c, nil
}

func importPrecheck(state *State) error {
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

func (c *Client) importTweakedKey(state *State) error {
	if state.TweakedKey != nil {
		t := c.group.NewElement()
		if err := t.Decode(state.TweakedKey); err != nil {
			return fmt.Errorf("tweaked key - %w", err)
		}

		c.tweakedKey = t
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
