// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bytemare/voprf/voprf"

	oprf "github.com/bytemare/voprf"
)

var errExpectedEquality = errors.New("expected equality")

func makeVPClientAndServer(t *testing.T, ciphersuite oprf.Ciphersuite, info []byte) (*voprf.Client, *voprf.Server) {
	sk := ciphersuite.Group().NewScalar().Random()
	pk := ciphersuite.Group().Base().Multiply(sk)

	server := voprf.NewServer(ciphersuite, info...)
	if err := server.SetKeyPair(sk, pk); err != nil {
		t.Fatal(err)
	}

	client, err := voprf.NewClient(ciphersuite, pk, info...)
	if err != nil {
		t.Fatal(err)
	}

	return client, server
}

func TestOPRF(t *testing.T) {
	input := []byte("input")

	testAll(t, func(c *configuration) {
		serverKey := c.group.NewScalar().Random()
		client := c.ciphersuite.Client()
		blinded := client.Blind(input)
		evaluated := oprf.Evaluate(serverKey, blinded)
		_ = client.Finalize(evaluated)
	})
}

func doVPOPRF(t *testing.T, input, info []byte, c *configuration) {
	serverKey := c.group.NewScalar().Random()
	serverPubkey := c.group.Base().Multiply(serverKey)

	server := voprf.NewServer(c.ciphersuite, info...)
	if err := server.SetKeyPair(serverKey, serverPubkey); err != nil {
		t.Fatal(err)
	}

	client, err := voprf.NewClient(c.ciphersuite, serverPubkey, info...)
	if err != nil {
		t.Fatal(err)
	}

	blinded := client.Blind(input)
	evaluation := server.Evaluate(blinded)
	_, err = client.Finalize(evaluation)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVOPRF(t *testing.T) {
	input := []byte("input")

	testAll(t, func(c *configuration) {
		doVPOPRF(t, input, nil, c)
	})
}

func TestPOPRF(t *testing.T) {
	info := []byte("info")
	input := []byte("input")

	testAll(t, func(c *configuration) {
		doVPOPRF(t, input, info, c)
	})
}

func TestOPRFBatching(t *testing.T) {
	inputs := [][]byte{
		[]byte("input1"),
		[]byte("input2"),
		[]byte("input3"),
	}

	testAll(t, func(c *configuration) {
		client := c.ciphersuite.Client()
		blinded := client.BlindBatch(inputs)
		evaluation := oprf.EvaluateBatch(c.group.NewScalar().Random(), blinded)

		if _, err := client.FinalizeBatch(evaluation); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVPOPRFBatching(t *testing.T) {
	info := []byte("info")
	inputs := [][]byte{
		[]byte("input1"),
		[]byte("input2"),
		[]byte("input3"),
	}

	testAll(t, func(c *configuration) {
		client, server := makeVPClientAndServer(t, c.ciphersuite, info)
		blinded := client.BlindBatch(inputs)
		evaluation := server.EvaluateBatch(blinded)

		if _, err := client.FinalizeBatch(evaluation); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCiphersuiteGroup(t *testing.T) {
	testAll(t, func(c *configuration) {
		if c.ciphersuite.Group() != c.group {
			t.Fatal(errExpectedEquality)
		}

		ciphersuite := oprf.FromGroup(c.group)

		if ciphersuite != c.ciphersuite {
			t.Fatal(errExpectedEquality)
		}
	})
}

func TestDeriveKeyPair(t *testing.T) {
	info := []byte("some instance")
	ciphersuite := oprf.Ristretto255Sha512

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

	sk, pk := oprf.DeriveKeyPair(ciphersuite, random, info)

	if !sk.Equal(refSk) || !pk.Equal(refPk) {
		t.Fatal(errExpectedEquality)
	}
}

func Test_DecodeElement(t *testing.T) {
	testAll(t, func(c *configuration) {
		element := c.group.NewElement().Base().Multiply(c.group.NewScalar().Random()).Encode()
		if _, err := c.ciphersuite.DecodeElement(element); err != nil {
			t.Errorf("unexpected error, got %v", err)
		}
	})
}

func Test_DecodeScalar(t *testing.T) {
	testAll(t, func(c *configuration) {
		scalar := c.group.NewScalar().Random().Encode()
		if _, err := c.ciphersuite.DecodeScalar(scalar); err != nil {
			t.Errorf("unexpected error, got %v", err)
		}
	})
}

func Test_Evaluation_Serde(t *testing.T) {
	testAll(t, func(c *configuration) {
		b := c.group.NewElement().Base() // just use any non-zero element

		server := voprf.NewServer(c.ciphersuite)
		server.GenerateKeys()

		eval := server.Evaluate(b)

		// Serialize
		serialized := eval.Serialize()

		binary, err := eval.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Compare(serialized, binary) != 0 {
			t.Fatal("expected equality")
		}

		json, err := eval.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// Deserialize
		{
			evaluation := new(voprf.Evaluation)
			evaluation.SetCiphersuite(c.ciphersuite)

			if err = evaluation.UnmarshalJSON(json); err != nil {
				t.Fatal(err)
			}

			compareEvaluations(t, eval, evaluation, true)
		}

		{
			evaluation := new(voprf.Evaluation)
			evaluation.SetCiphersuite(c.ciphersuite)

			if err = evaluation.UnmarshalBinary(binary); err != nil {
				t.Fatal(err)
			}

			compareEvaluations(t, eval, evaluation, true)
		}

		{
			evaluation := new(voprf.Evaluation)
			evaluation.SetCiphersuite(c.ciphersuite)

			if err = evaluation.Deserialize(serialized); err != nil {
				t.Fatal(err)
			}

			compareEvaluations(t, eval, evaluation, true)
		}
	})
}

func compareEvaluations(t *testing.T, a, b *voprf.Evaluation, expected bool) {
	isEqual := a.Proof[0].Equal(b.Proof[0])
	isEqual = isEqual && a.Proof[1].Equal(b.Proof[1])
	isEqual = isEqual && len(a.Evaluations) == len(b.Evaluations)

	if isEqual != expected {
		t.Fatalf("unexpected comparison result: want %v got %v", expected, isEqual)
	}

	for i, eval := range a.Evaluations {
		isEqual = isEqual && eval.Equal(b.Evaluations[i])
	}

	if isEqual != expected {
		t.Fatalf("unexpected comparison result: want %v got %v", expected, isEqual)
	}
}
