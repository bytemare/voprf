// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package voprf implements RFC9497 and provides abstracted access to Oblivious Pseudorandom Functions (OPRF) and
// Threshold Oblivious Pseudorandom Functions (TOPRF) using Elliptic Curve Prime Order Groups (EC-OPRF).
// For VOPRF and POPRF use the github.com/bytemare/oprf/voprf package.
package voprf

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/bytemare/voprf/internal"
)

// Ciphersuite of the xOPRF compatible cipher suite to be used.
type Ciphersuite byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group and SHA-512.
	Ristretto255Sha512 = Ciphersuite(ecc.Ristretto255Sha512)

	// decaf448Shake256 identifies the Decaf448 group and Shake-256. Not supported.
	// decaf448Shake256 = 2.

	// P256Sha256 identifies the NIST P-256 group and SHA-256.
	P256Sha256 = Ciphersuite(ecc.P256Sha256)

	// P384Sha384 identifies the NIST P-384 group and SHA-384.
	P384Sha384 = Ciphersuite(ecc.P384Sha384)

	// P521Sha512 identifies the NIST P-512 group and SHA-512.
	P521Sha512 = Ciphersuite(ecc.P521Sha512)

	// Secp256k1 identifies the SECp256k1 group and SHA-256.
	Secp256k1 = Ciphersuite(ecc.Secp256k1Sha256)
)

var (
	errBatchNoElements    = errors.New("no evaluated elements provided to Finalize()")
	errBatchDifferentSize = errors.New("number of evaluations is different thant number of previously blinded inputs")
)

// FromGroup returns a Ciphersuite given a Group.
func FromGroup(g ecc.Group) Ciphersuite {
	return Ciphersuite(g)
}

// Group returns the elliptic curve prime-order group of the ciphersuite.
func (c Ciphersuite) Group() ecc.Group {
	return ecc.Group(c)
}

// Name returns the [RFC9497](https://datatracker.ietf.org/doc/rfc9497) compliant identifier of the ciphersuite.
func (c Ciphersuite) Name() string {
	return internal.CiphersuiteIdentifier[ecc.Group(c)]
}

// DeriveKeyPair returns a private-public key pair for the OPRF mode, given a secret seed and instance specific info.
// VOPRF and POPRF keys must be created with server.DeriveKeyPair() in the voprf package.
// TOPRF key pairs should be created using a distributed key generation protocol.
func DeriveKeyPair(c Ciphersuite, seed, info []byte) (*ecc.Scalar, *ecc.Element) {
	// We don't use this as a method to a Ciphersuite, as it might be confusing when in VOPRF or POPRF mode, which
	// use the Ciphersuite identifier from this package.
	return internal.LoadConfiguration(c.Group(), internal.OPRF).DeriveKeyPair(seed, info)
}

// Client returns an OPRF client.
func (c Ciphersuite) Client() *Client {
	return &Client{
		Client: internal.NewClient(internal.OPRF, ecc.Group(c)),
	}
}

// Client is used for OPRF and TOPRF client executions.
type Client struct {
	*internal.Client
}

// SetBlind sets one or multiple blinds in the client's blind register. This is optional, and useful if you want to
// force usage of specific blinding scalar. If no blinding scalars are set, new, random blinds will be used.
func (c *Client) SetBlind(blind ...*ecc.Scalar) {
	c.Client.UpdateStateCapacity(len(blind))

	for i, b := range blind {
		c.Client.SetBlind(i, b)
	}
}

// Blind blinds the input using the first blinding scalar in the Client's register. If no blinding scalars were
// previously set, new, random blinds will be used.
func (c *Client) Blind(input []byte) *ecc.Element {
	return c.Client.Blind(0, input)
}

// BlindBatch blinds the given set, using either previously set blinds in the same order (if they have been set) or
// newly generated random blinds. Note that if not enough blinds were set, new, random blinds will be used as necessary.
func (c *Client) BlindBatch(inputs [][]byte) []*ecc.Element {
	c.UpdateStateCapacity(len(inputs))
	blindedInput := make([]*ecc.Element, len(inputs))

	for i, in := range inputs {
		blindedInput[i] = c.Client.Blind(i, in)
	}

	return blindedInput
}

// Finalize unblinds the evaluated element and returns the protocol output.
func (c *Client) Finalize(evaluated *ecc.Element) []byte {
	return c.Client.Finalize(0, evaluated)
}

// FinalizeBatch unblinds the evaluated elements and returns the corresponding protocol outputs.
func (c *Client) FinalizeBatch(evaluated []*ecc.Element) ([][]byte, error) {
	if len(evaluated) == 0 {
		return nil, errBatchNoElements
	}

	if len(evaluated) != c.Size() {
		return nil, errBatchDifferentSize
	}

	return c.Client.FinalizeBatch(evaluated)
}

// Evaluate is the server's function to evaluate a Client provided blinded element with the server's secret key.
func Evaluate(key *ecc.Scalar, blinded *ecc.Element) *ecc.Element {
	return blinded.Copy().Multiply(key)
}

// EvaluateBatch is the server's function to evaluate a set of Client provided blinded elements with the
// server's secret key.
func EvaluateBatch(key *ecc.Scalar, blinded []*ecc.Element) []*ecc.Element {
	evaluated := make([]*ecc.Element, len(blinded))
	for i, b := range blinded {
		evaluated[i] = Evaluate(key, b)
	}

	return evaluated
}
