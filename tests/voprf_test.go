// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"encoding/hex"
	"testing"

	"github.com/bytemare/voprf"
)

func makeClientAndServer(t *testing.T, mode voprf.Mode, ciphersuite voprf.Ciphersuite) (*voprf.Client, *voprf.Server) {
	server, err := ciphersuite.Server(mode, nil)
	if err != nil {
		t.Fatal(err)
	}

	spk := server.PublicKey()

	client, err := ciphersuite.Client(mode, spk)
	if err != nil {
		t.Fatal(err)
	}

	return client, server
}

func runOPRF(t *testing.T, c *configuration, mode voprf.Mode, input, info []byte) *voprf.Evaluation {
	client, server := makeClientAndServer(t, mode, c.ciphersuite)

	blinded := client.Blind(input, info)

	evaluation, err := server.Evaluate(blinded, info)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = client.Finalize(evaluation, info); err != nil {
		t.Fatal(err)
	}

	return evaluation
}

func TestOPRF(t *testing.T) {
	mode := voprf.OPRF
	input := []byte("input")

	testAll(t, func(c *configuration) {
		_ = runOPRF(t, c, mode, input, nil)
	})
}

func TestVOPRF(t *testing.T) {
	mode := voprf.VOPRF
	input := []byte("input")

	testAll(t, func(c *configuration) {
		_ = runOPRF(t, c, mode, input, nil)
	})
}

func TestPOPRF(t *testing.T) {
	mode := voprf.POPRF
	info := []byte("info")
	input := []byte("input")

	testAll(t, func(c *configuration) {
		_ = runOPRF(t, c, mode, input, info)
	})
}

func TestBatching(t *testing.T) {
	mode := voprf.POPRF
	info := []byte("info")
	inputs := [][]byte{
		[]byte("input1"),
		[]byte("input2"),
		[]byte("input3"),
	}

	testAll(t, func(c *configuration) {
		client, server := makeClientAndServer(t, mode, c.ciphersuite)

		_, blinded, err := client.BlindBatch(inputs, info)
		if err != nil {
			t.Fatal(err)
		}

		evaluation, err := server.EvaluateBatch(blinded, info)
		if err != nil {
			t.Fatal(err)
		}

		if _, err = client.FinalizeBatch(evaluation, info); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAvailability(t *testing.T) {
	testAll(t, func(c *configuration) {
		if !c.ciphersuite.Available() {
			t.Fatal("expected availability")
		}
	})
}

func TestCiphersuiteGroup(t *testing.T) {
	testAll(t, func(c *configuration) {
		if c.ciphersuite.Group() != c.group {
			t.Fatal("expected equality")
		}

		ciphersuite, err := voprf.FromGroup(c.group)
		if err != nil {
			t.Fatal(err)
		}

		if ciphersuite != c.ciphersuite {
			t.Fatal("expected equality")
		}
	})
}

func TestCiphersuiteHashes(t *testing.T) {
	testAll(t, func(c *configuration) {
		if c.hash != c.ciphersuite.Hash() {
			t.Fatal("expected equality")
		}
	})
}

func TestServerKeys(t *testing.T) {
	mode := voprf.OPRF

	testAll(t, func(c *configuration) {
		server, err := c.ciphersuite.Server(mode, nil)
		if err != nil {
			t.Fatal(err)
		}

		private := c.ciphersuite.Group().NewScalar()
		if err = private.Decode(server.PrivateKey()); err != nil {
			t.Fatal(err)
		}

		public := c.ciphersuite.Group().NewElement()
		if err = public.Decode(server.PublicKey()); err != nil {
			t.Fatal(err)
		}

		pk := c.ciphersuite.Group().Base().Multiply(private)
		if pk.Equal(public) != 1 {
			t.Fatal("expected equality")
		}
	})
}

func TestDeriveKeyPair(t *testing.T) {
	info := []byte("some instance")
	ciphersuite := voprf.Ristretto255Sha512

	random, _ := hex.DecodeString("c332260baab120459e7ad1d47ce5a43f980abe9c19ecc0550bbd0dde58a548bf")
	encodedReferenceSecretKeyR255, _ := hex.DecodeString(
		"78e4560c5779791f87f6493fff0ac0476d64ebdecb9ae26a0565f673b10be906",
	)
	encodedReferencePublicKeyR255, _ := hex.DecodeString(
		"7c45e2a6748414358f597874d4afa951cbc39cb3300c5cfde9ac86348062560f",
	)

	refSk := ciphersuite.Group().NewScalar()
	_ = refSk.Decode(encodedReferenceSecretKeyR255)

	refPk := ciphersuite.Group().NewElement()
	_ = refPk.Decode(encodedReferencePublicKeyR255)

	keyPair := ciphersuite.DeriveKeyPair(voprf.OPRF, random, info)

	if keyPair.SecretKey.Equal(refSk) != 1 || keyPair.PublicKey.Equal(refPk) != 1 {
		t.Fatal("expected equality")
	}
}
