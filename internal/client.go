// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"slices"

	"github.com/bytemare/ecc"
)

// A Client holds the core functionalities for all OPRF, TOPRF, VOPRF, and POPRF.
type Client struct {
	// Core abstracts configuration dependent operations.
	*Core

	// Inputs registry: the inputs are necessary in blinding and finalizing.
	Inputs [][]byte

	// Blinds registry: the blinds are necessary in blinding and finalizing.
	Blinds []*ecc.Scalar
}

// NewClient loads the configuration for a new client. The info argument should only be set by the caller in the POPRF
// mode.
func NewClient(mode Mode, g ecc.Group) *Client {
	return &Client{
		Core:   LoadConfiguration(g, mode),
		Inputs: make([][]byte, 1),
		Blinds: make([]*ecc.Scalar, 1),
	}
}

// Size returns the length of the input and blind registers in its current state.
func (c *Client) Size() int {
	return len(c.Inputs)
}

// UpdateStateCapacity increases the internal input and blind registers to n, if necessary. If n is smaller than the
// current capacity, the buffers are unchanged.
func (c *Client) UpdateStateCapacity(n int) {
	if n <= cap(c.Inputs) {
		return
	}

	d := n - cap(c.Inputs)

	c.Inputs = slices.Grow(c.Inputs, d)
	c.Inputs = append(c.Inputs, make([][]byte, d)...)
	c.Blinds = slices.Grow(c.Blinds, d)
	c.Blinds = append(c.Blinds, make([]*ecc.Scalar, d)...)
}

// SetBlind sets a single blinding scalar at position index in the internal register.
func (c *Client) SetBlind(index int, blind *ecc.Scalar) *Client {
	c.Blinds[index] = c.Group.NewScalar().Set(blind)
	return c
}

// Blind uses the blinding scalar at position index in the internal register to blind the input, and return the blinded
// input.
func (c *Client) Blind(index int, input []byte) *ecc.Element {
	// register input and blind
	c.Inputs[index] = make([]byte, len(input))
	copy(c.Inputs[index], input)

	if c.Blinds[index] == nil {
		c.Blinds[index] = c.Core.Group.NewScalar().Random()
	}

	// blind input
	p := c.HashToGroup(input)
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	return p.Multiply(c.Blinds[index])
}

// Unblind uses the blinding scalar at position index in the internal register to unblind the evaluated element, and
// return the unblinded evaluation.
func (c *Client) Unblind(index int, evaluated *ecc.Element) *ecc.Element {
	inv := c.Blinds[index].Copy().Invert()
	return evaluated.Copy().Multiply(inv)
}

// Finalize finalizes the client's xOPRF execution. It takes a server evaluated element and the position in the internal
// blind register of the blind used in the blinding phase and returns the xOPRF output. The optional info argument must
// only be provided when using the POPRF mode.
func (c *Client) Finalize(index int, evaluated *ecc.Element, info ...byte) []byte {
	unblinded := c.Unblind(index, evaluated)
	return c.HashTranscript(c.Inputs[index], unblinded.Encode(), info)
}

// FinalizeBatch unblinds the evaluated elements and returns the corresponding protocol outputs. The optional info
// argument must only be provided when using the POPRF mode.
func (c *Client) FinalizeBatch(evaluated []*ecc.Element, info ...byte) ([][]byte, error) {
	out := make([][]byte, len(evaluated))

	for i, e := range evaluated {
		out[i] = c.Finalize(i, e, info...)
	}

	return out, nil
}
