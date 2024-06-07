// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"

	oprf "github.com/bytemare/voprf"
	"github.com/bytemare/voprf/internal"
	"github.com/bytemare/voprf/voprf"
)

/*
Test
- NewClient: serverPublicKey == nil || serverPublicKey.IsIdentity()
- client.checkEvaluation
- client.verifyproof: len(c.blindedInput) == 0
- client.verifyproof
- server.checkkeys
-

*/

func Test_DecodeBadElement(t *testing.T) {
	testAll(t, func(c *configuration) {
		bad := getBadElement(t, c)

		if _, err := c.ciphersuite.DecodeElement(bad); err == nil ||
			!strings.Contains(err.Error(), "element Decode: ") {
			t.Errorf("expected error, got %v", err)
		}
	})
}

func Test_DecodeBadScalar(t *testing.T) {
	testAll(t, func(c *configuration) {
		bad := getBadScalar(t, c)

		if _, err := c.ciphersuite.DecodeScalar(bad); err == nil || !strings.Contains(err.Error(), "scalar Decode: ") {
			t.Errorf("expected error, got %v", err)
		}
	})
}

func Test_VOPRF_Client_BadPubkey(t *testing.T) {
	expected := errors.New("server public key is either nil or the identity element")
	testAll(t, func(c *configuration) {
		// Test with nil pubkey
		if _, err := voprf.NewClient(c.ciphersuite, nil); err == nil || expected.Error() != err.Error() {
			t.Error("expected error")
		}

		// Test with identity
		if _, err := voprf.NewClient(c.ciphersuite, c.group.NewElement()); err == nil ||
			expected.Error() != err.Error() {
			t.Error("expected error")
		}
	})
}

func copyEval(e *voprf.Evaluation) *voprf.Evaluation {
	cpy := &voprf.Evaluation{
		Proof: [2]*group.Scalar{
			e.Proof[0].Copy(),
			e.Proof[1].Copy(),
		},
		Evaluations: make([]*group.Element, len(e.Evaluations)),
	}

	for i, eval := range e.Evaluations {
		cpy.Evaluations[i] = eval.Copy()
	}

	return cpy
}

type Finalizer func()

func testFinalize(t *testing.T, client *voprf.Client, expected error, badEval *voprf.Evaluation) {
	if _, err := client.Finalize(badEval); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error: want %q, got %q", expected, err)
	}

	if _, err := client.FinalizeBatch(badEval); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error: want %q, got %q", expected, err)
	}
}

func Test_VOPRF_Client_BadEvaluation(t *testing.T) {
	errInputNilEval := errors.New("provided evaluation is nil")
	errDifferentSize := errors.New("number of evaluations differs from number of previously blinded elements")
	errInputNoEval := errors.New("provided evaluation does not contain evaluations")
	errInputProofCNil := errors.New("proof c is nil")
	errInputProofCZero := errors.New("proof c is zero")
	errInputProofSNil := errors.New("proof s is nil")
	errInputProofSZero := errors.New("proof s is zero")

	testAll(t, func(c *configuration) {
		server := voprf.NewServer(c.ciphersuite)
		server.GenerateKeys()
		_, pk := server.KeyPair()

		client, err := voprf.NewClient(c.ciphersuite, pk)
		if err != nil {
			t.Error(err)
		}

		blinded := client.Blind([]byte("input"))
		evaluation := server.Evaluate(blinded)

		testFinalize(t, client, errInputNilEval, nil)

		badEval := copyEval(evaluation)
		badEval.Evaluations = nil
		testFinalize(t, client, errInputNoEval, badEval)

		badEval.Evaluations = []*group.Element{}
		testFinalize(t, client, errInputNoEval, badEval)

		badEval = copyEval(evaluation)
		badEval.Proof[0] = nil
		testFinalize(t, client, errInputProofCNil, badEval)

		badEval = copyEval(evaluation)
		badEval.Proof[0] = c.group.NewScalar()
		testFinalize(t, client, errInputProofCZero, badEval)

		badEval = copyEval(evaluation)
		badEval.Proof[1] = nil
		testFinalize(t, client, errInputProofSNil, badEval)

		badEval = copyEval(evaluation)
		badEval.Proof[1] = c.group.NewScalar()
		testFinalize(t, client, errInputProofSZero, badEval)

		badEval = copyEval(evaluation)
		badEval.Evaluations = append(badEval.Evaluations, c.group.NewElement())
		testFinalize(t, client, errDifferentSize, badEval)
	})
}

func Test_VOPRF_Client_InvalidProof(t *testing.T) {
	errProofFailed := errors.New("invalid proof")

	testAll(t, func(c *configuration) {
		server := voprf.NewServer(c.ciphersuite)
		server.GenerateKeys()
		_, pk := server.KeyPair()

		client, err := voprf.NewClient(c.ciphersuite, pk)
		if err != nil {
			t.Error(err)
		}

		blinded := client.Blind([]byte("input"))
		evaluation := server.Evaluate(blinded)
		cpy := copyEval(evaluation)

		// Tamper with c
		evaluation.Proof[0] = c.group.NewScalar().Random()
		testFinalize(t, client, errProofFailed, evaluation)

		// Tamper with s
		cpy.Proof[1] = c.group.NewScalar().Random()
		testFinalize(t, client, errProofFailed, cpy)
	})
}

func Test_VOPRF_Server_CheckKeys(t *testing.T) {
	errInvalidPublicKey := errors.New("server public key is either nil or the identity element")
	errInvalidPrivateKey := errors.New("private key is nil or zero")
	errInvalidKeyPair := errors.New("input public key doesn't belong to the private key")

	testAll(t, func(c *configuration) {
		server := voprf.NewServer(c.ciphersuite)

		sk := c.group.NewScalar().Random()
		pk := c.group.NewElement().Base().Multiply(sk)

		// Test private key
		if err := server.SetKeyPair(nil, pk); err == nil || err.Error() != errInvalidPrivateKey.Error() {
			t.Error("expected error")
		}

		zero := c.group.NewScalar()
		if err := server.SetKeyPair(zero, pk); err == nil || err.Error() != errInvalidPrivateKey.Error() {
			t.Error("expected error")
		}

		// Test public key
		if err := server.SetKeyPair(sk, nil); err == nil || err.Error() != errInvalidPublicKey.Error() {
			t.Error("expected error")
		}

		identity := c.group.NewElement()
		if err := server.SetKeyPair(sk, identity); err == nil || err.Error() != errInvalidPublicKey.Error() {
			t.Error("expected error")
		}

		wrongKey := c.group.NewElement().Base().Multiply(c.group.NewScalar().Random())
		if err := server.SetKeyPair(sk, wrongKey); err == nil || err.Error() != errInvalidKeyPair.Error() {
			t.Errorf("expected error: want %q, got %q", errInvalidKeyPair, err)
		}
	})
}

func Test_OPRF_Client_Finalize_BadBatch(t *testing.T) {
	errBatchNoElements := errors.New("no evaluated elements provided to Finalize()")
	errBatchDifferentSize := errors.New("number of evaluations is different thant number of previously blinded inputs")
	inputs := [][]byte{
		[]byte("input1"),
		[]byte("input2"),
		[]byte("input3"),
	}

	testAll(t, func(c *configuration) {
		client := c.ciphersuite.Client()
		blinded := client.BlindBatch(inputs)
		evaluation := oprf.EvaluateBatch(c.group.NewScalar().Random(), blinded)

		if _, err := client.FinalizeBatch(nil); err == nil || err.Error() != errBatchNoElements.Error() {
			t.Error("expected error")
		}

		if _, err := client.FinalizeBatch(evaluation[:2]); err == nil || err.Error() != errBatchDifferentSize.Error() {
			t.Error("expected error")
		}
	})
}

func getBadCiphersuite() oprf.Ciphersuite {
	return oprf.Ciphersuite(group.Edwards25519Sha512)
}

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report interface{}
	func() {
		defer func() {
			if report = recover(); report != nil {
				has = true
			}
		}()

		f()
	}()

	if has {
		err = fmt.Errorf("%v", report)
	}

	return
}

func expectPanic(expectedError error, f func()) (bool, string) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, "no panic"
	}

	if expectedError == nil {
		return true, ""
	}

	if err == nil {
		return false, "panic but no message"
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Sprintf("expected %q, got %q", expectedError, err)
	}

	return true, ""
}

func Test_BadCiphersuite(t *testing.T) {
	expectedError := errors.New("invalid OPRF dependency - Group: edwards25519_XMD:SHA-512_ELL2_RO_")
	if hasPanic, err := expectPanic(expectedError, func() {
		_ = internal.LoadConfiguration(group.Edwards25519Sha512, 0)
	}); !hasPanic {
		t.Fatalf("expected panic with wrong group: %v", err)
	}
}
