// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

	oprf "github.com/bytemare/voprf"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// helper functions

type configuration struct {
	curve       elliptic.Curve
	name        string
	ciphersuite oprf.Ciphersuite
	hash        hash.Hash
	group       group.Group
}

var configurationTable = []configuration{
	{
		name:        "Ristretto255",
		ciphersuite: oprf.Ristretto255Sha512,
		group:       group.Ristretto255Sha512,
		hash:        hash.SHA512,
		curve:       nil,
	},
	{
		name:        "P256Sha256",
		ciphersuite: oprf.P256Sha256,
		group:       group.P256Sha256,
		hash:        hash.SHA256,
		curve:       elliptic.P256(),
	},
	{
		name:        "P384Sha512",
		ciphersuite: oprf.P384Sha384,
		group:       group.P384Sha384,
		hash:        hash.SHA384,
		curve:       elliptic.P384(),
	},
	{
		name:        "P521Sha512",
		ciphersuite: oprf.P521Sha512,
		group:       group.P521Sha512,
		hash:        hash.SHA512,
		curve:       elliptic.P521(),
	},
	{
		name:        "Secp256k1Sha256",
		ciphersuite: oprf.Secp256k1,
		group:       group.Secp256k1,
		hash:        hash.SHA256,
		curve:       nil,
	},
}

func testAll(t *testing.T, f func(*configuration)) {
	for _, test := range configurationTable {
		t.Run(test.name, func(t *testing.T) {
			f(&test)
		})
	}
}

func getBadRistrettoScalar() []byte {
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadRistrettoElement() []byte {
	a := "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadSecP256k1Scalar() []byte {
	a := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func badScalar(t *testing.T, g group.Group, curve elliptic.Curve) []byte {
	order := curve.Params().P
	exceeded := new(big.Int).Add(order, big.NewInt(2)).Bytes()

	err := g.NewScalar().Decode(exceeded)
	if err == nil {
		t.Errorf("Exceeding order did not yield an error for group %s", g)
	}

	return exceeded
}

func randomBytes(length int) []byte {
	r := make([]byte, length)
	if _, err := rand.Read(r); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return r
}

func getBadNistElement(t *testing.T, g group.Group) []byte {
	size := g.ElementLength()
	element := randomBytes(size)
	// detag compression
	element[0] = 4

	// test if invalid compression is detected
	err := g.NewElement().Decode(element)
	if err == nil {
		t.Errorf("detagged compressed point did not yield an error for group %s", g)
	}

	return element
}

func getBadElement(t *testing.T, c *configuration) []byte {
	switch c.ciphersuite {
	case oprf.Ristretto255Sha512:
		return getBadRistrettoElement()
	default:
		return getBadNistElement(t, c.ciphersuite.Group())
	}
}

func getBadScalar(t *testing.T, c *configuration) []byte {
	switch c.ciphersuite {
	case oprf.Ristretto255Sha512:
		return getBadRistrettoScalar()
	case oprf.Secp256k1:
		return getBadSecP256k1Scalar()
	default:
		return badScalar(t, c.ciphersuite.Group(), c.curve)
	}
}

const (
	hash2groupDSTPrefix = "HashToGroup-"
)
