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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

	"github.com/bytemare/voprf"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// helper functions

type configuration struct {
	curve       elliptic.Curve
	ciphersuite voprf.Ciphersuite
	name        string
	hash        hash.Hash
	group       group.Group
}

var configurationTable = []configuration{
	{
		name:        "Ristretto255",
		ciphersuite: voprf.Ristretto255Sha512,
		group:       group.Ristretto255Sha512,
		hash:        hash.SHA512,
		curve:       nil,
	},
	{
		name:        "P256Sha256",
		ciphersuite: voprf.P256Sha256,
		group:       group.P256Sha256,
		hash:        hash.SHA256,
		curve:       elliptic.P256(),
	},
	{
		name:        "P384Sha512",
		ciphersuite: voprf.P384Sha384,
		group:       group.P384Sha384,
		hash:        hash.SHA384,
		curve:       elliptic.P384(),
	},
	{
		name:        "P521Sha512",
		ciphersuite: voprf.P521Sha512,
		group:       group.P521Sha512,
		hash:        hash.SHA512,
		curve:       elliptic.P521(),
	},
	{
		name:        "Secp256k1Sha256",
		ciphersuite: voprf.Secp256k1,
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
	case voprf.Ristretto255Sha512:
		return getBadRistrettoElement()
	default:
		return getBadNistElement(t, c.ciphersuite.Group())
	}
}

func getBadScalar(t *testing.T, c *configuration) []byte {
	switch c.ciphersuite {
	case voprf.Ristretto255Sha512:
		return getBadRistrettoScalar()
	default:
		return badScalar(t, c.ciphersuite.Group(), c.curve)
	}
}

const (
	deriveKeyPairDST    = "DeriveKeyPair"
	hash2groupDSTPrefix = "HashToGroup-"
)

func concatenate(input ...[]byte) []byte {
	if len(input) == 1 {
		if len(input[0]) == 0 {
			return nil
		}

		return input[0]
	}

	length := 0
	for _, in := range input {
		length += len(in)
	}

	buf := make([]byte, 0, length)

	for _, in := range input {
		buf = append(buf, in...)
	}

	return buf
}

func dst(prefix string, contextString []byte) []byte {
	p := []byte(prefix)
	t := make([]byte, 0, len(p)+len(contextString))
	t = append(t, p...)
	t = append(t, contextString...)

	return t
}

func i2osp2(value int) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(value))

	return out
}

func lengthPrefixEncode(input []byte) []byte {
	return append(i2osp2(len(input)), input...)
}

func contextString(mode voprf.Mode, g voprf.Ciphersuite) []byte {
	ctx := make([]byte, 0, len(voprf.Version)+3+len(g.String()))
	ctx = append(ctx, voprf.Version...)
	ctx = append(ctx, "-"...)
	ctx = append(ctx, byte(mode))
	ctx = append(ctx, "-"...)
	ctx = append(ctx, g.String()...)

	return ctx
}

func deriveKeyPair(seed, info []byte, mode voprf.Mode, g voprf.Ciphersuite) (*group.Scalar, *group.Element) {
	dst := concatenate([]byte(deriveKeyPairDST), contextString(mode, g))
	deriveInput := concatenate(seed, lengthPrefixEncode(info))

	var counter uint8
	var s *group.Scalar

	for s == nil || s.IsZero() {
		if counter > 255 {
			panic("impossible to generate non-zero scalar")
		}

		s = g.Group().HashToScalar(concatenate(deriveInput, []byte{counter}), dst)
		counter++
	}

	return s, g.Group().Base().Multiply(s)
}
