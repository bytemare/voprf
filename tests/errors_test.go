// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/voprf/internal"
	"github.com/bytemare/voprf/voprf"

	secretsharing "github.com/bytemare/secret-sharing"
	oprf "github.com/bytemare/voprf"
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
		Proof: [2]*ecc.Scalar{
			e.Proof[0].Copy(),
			e.Proof[1].Copy(),
		},
		Evaluations: make([]*ecc.Element, len(e.Evaluations)),
	}

	for i, eval := range e.Evaluations {
		cpy.Evaluations[i] = eval.Copy()
	}

	return cpy
}

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

		badEval.Evaluations = []*ecc.Element{}
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
		return false, fmt.Sprintf("expected panic with %q, got %q", expectedError, err)
	}

	return true, ""
}

func Test_BadCiphersuite(t *testing.T) {
	expectedError := errors.New("invalid OPRF dependency - Group: edwards25519_XMD:SHA-512_ELL2_RO_")
	if hasPanic, err := expectPanic(expectedError, func() {
		_ = internal.LoadConfiguration(ecc.Edwards25519Sha512, 0)
	}); !hasPanic {
		t.Fatalf("expected panic with wrong group: %v", err)
	}
}

func pTag(g ecc.Group, info []byte) *ecc.Scalar {
	framedInfo := make([]byte, 0, len("Info")+2+len(info))
	framedInfo = append(framedInfo, "Info"...)
	framedInfo = append(framedInfo, append(internal.I2osp2(len(info)), info...)...)
	ctx := internal.ContextString(internal.POPRF, internal.CiphersuiteIdentifier[g])
	dst := internal.Dst("HashToScalar-", ctx)
	return g.HashToScalar(framedInfo, dst)
}

func Test_BreakPOPRF(t *testing.T) {
	errInvalidPOPRFPrivateKey := errors.New(
		"invalid input - POPRF private key tweaking yields the zero scalar",
	)
	errInvalidPOPRFPubKey := errors.New(
		"invalid input - POPRF public key tweaking yields the group identity element",
	)
	info := []byte("info")

	testAll(t, func(c *configuration) {
		tag := pTag(c.group, info)
		sk1 := c.group.NewScalar().Subtract(tag) // negate the tag, so to yield an 0 when tweaking in POPRF
		pk := c.group.Base().Multiply(sk1)

		if hasPanic, err := expectPanic(errInvalidPOPRFPrivateKey, func() {
			_ = voprf.NewServer(c.ciphersuite, info...).SetKeyPair(sk1, pk)
		}); !hasPanic {
			t.Fatalf("expected panic for tweaking to zero scalar: %v", err)
		}

		if hasPanic, err := expectPanic(errInvalidPOPRFPubKey, func() {
			_, _ = voprf.NewClient(c.ciphersuite, pk, info...)
		}); !hasPanic {
			t.Fatalf("expected panic: %v", err)
		}
	})
}

func Test_NewVerifiable_POPRFNotSet(t *testing.T) {
	errWrongMode := errors.New("internal error: POPRF info provided but POPRF mode not set")

	testAll(t, func(c *configuration) {
		if hasPanic, err := expectPanic(errWrongMode, func() {
			client := internal.NewClient(internal.VOPRF, ecc.Group(c.ciphersuite))
			_ = internal.NewVerifiable(client.Core, []byte("info"))
		}); !hasPanic {
			t.Fatalf("expected panic with wrong group: %v", err)
		}
	})
}

func Test_Serde_Evaluation_CiphersuiteNotSet(t *testing.T) {
	errDecodeNoCiphersuite := errors.New("decoding error: ciphersuite not set")
	eval := new(voprf.Evaluation)

	if err := eval.Deserialize(nil); err == nil || err.Error() != errDecodeNoCiphersuite.Error() {
		t.Errorf("expected error starts with %q, got %q", errDecodeNoCiphersuite, err)
	}
}

func Test_Serde_Evaluation_TooShort(t *testing.T) {
	errUnmarshalEvaluationShort := errors.New("decoding error: insufficient data length")

	testAll(t, func(c *configuration) {
		eval := new(voprf.Evaluation)
		eval.SetCiphersuite(c.ciphersuite)

		if err := eval.Deserialize(nil); err == nil || err.Error() != errUnmarshalEvaluationShort.Error() {
			t.Errorf("expected error starts with %q, got %q", errUnmarshalEvaluationShort, err)
		}

		if err := eval.Deserialize([]byte("short string")); err == nil ||
			err.Error() != errUnmarshalEvaluationShort.Error() {
			t.Errorf("expected error starts with %q, got %q", errUnmarshalEvaluationShort, err)
		}
	})
}

func Test_Serde_Evaluation_TooFewEvals(t *testing.T) {
	errUnmarshalEvaluationEvals := errors.New("decoding error: wrong encoding length")

	testAll(t, func(c *configuration) {
		goodC := c.group.NewScalar().Random().Encode()
		goodS := c.group.NewScalar().Random().Encode()
		goodE := c.group.Base().Encode()
		badLengthPrefix := []byte{0, 2}
		eval := new(voprf.Evaluation)
		eval.SetCiphersuite(c.ciphersuite)
		e := slices.Concat(goodC, goodS, badLengthPrefix, goodE)

		if err := eval.Deserialize(e); err == nil || err.Error() != errUnmarshalEvaluationEvals.Error() {
			t.Errorf("expected error starts with %q, got %q", errUnmarshalEvaluationEvals, err)
		}
	})
}

func Test_Serde_Evaluation_InvalidProofAndEncoding(t *testing.T) {
	errC := "invalid c proof encoding:"
	errS := "invalid s proof encoding:"
	errE := "invalid evaluation encoding - element 0:"

	testAll(t, func(c *configuration) {
		goodC := c.group.NewScalar().Random().Encode()
		badC := getBadScalar(t, c)
		goodS := c.group.NewScalar().Random().Encode()
		bads := getBadScalar(t, c)
		goodE := c.group.Base().Encode()
		badE := getBadElement(t, c)
		lengthPrefix := []byte{0, 1}
		eval := new(voprf.Evaluation)
		eval.SetCiphersuite(c.ciphersuite)

		// Test bad c proof
		e := slices.Concat(badC, goodS, lengthPrefix, goodE)
		if err := eval.Deserialize(e); err == nil || !strings.HasPrefix(err.Error(), errC) {
			t.Errorf("expected error starts with %q, got %q", errC, err)
		}

		// Test bad s proof
		e = slices.Concat(goodC, bads, lengthPrefix, goodE)
		if err := eval.Deserialize(e); err == nil || !strings.HasPrefix(err.Error(), errS) {
			t.Errorf("expected error starts with %q, got %q", errS, err)
		}

		// Test bad evaluation
		e = slices.Concat(goodC, goodS, lengthPrefix, badE)
		if err := eval.Deserialize(e); err == nil || !strings.HasPrefix(err.Error(), errE) {
			t.Errorf("expected error starts with %q, got %q", errC, err)
		}
	})
}

func Test_Serde_Evaluation_UnmarshalJSON(t *testing.T) {
	errC := "invalid c proof encoding:"
	errS := "invalid s proof encoding:"
	errE := "invalid evaluation encoding - element 0:"
	jsonFMT := "{\"p\":[\"%s\",\"%s\"],\"e\":[\"%s\"]}"
	testAll(t, func(c *configuration) {
		goodC := base64.StdEncoding.EncodeToString(c.group.NewScalar().Random().Encode())
		badC := base64.StdEncoding.EncodeToString(getBadScalar(t, c))
		goodS := base64.StdEncoding.EncodeToString(c.group.NewScalar().Random().Encode())
		bads := base64.StdEncoding.EncodeToString(getBadScalar(t, c))
		goodE := base64.StdEncoding.EncodeToString(c.group.Base().Encode())
		badE := base64.StdEncoding.EncodeToString(getBadElement(t, c))
		eval := new(voprf.Evaluation)
		eval.SetCiphersuite(c.ciphersuite)

		// bad JSON
		e := []byte(fmt.Sprintf(jsonFMT, badC, goodS, goodE))
		e[0] = 0
		if err := eval.UnmarshalJSON(e); err == nil {
			t.Errorf("expected error")
		}

		// bad c proof
		e = []byte(fmt.Sprintf(jsonFMT, badC, goodS, goodE))
		if err := eval.UnmarshalJSON(e); err == nil || !strings.HasPrefix(err.Error(), errC) {
			t.Errorf("expected error starts with %q, got %q", "yo", err)
		}

		// bad s proof
		e = []byte(fmt.Sprintf(jsonFMT, goodC, bads, goodE))
		if err := eval.UnmarshalJSON(e); err == nil || !strings.HasPrefix(err.Error(), errS) {
			t.Errorf("expected error starts with %q, got %q", "yo", err)
		}

		// bad eval
		e = []byte(fmt.Sprintf(jsonFMT, goodC, goodS, badE))
		if err := eval.UnmarshalJSON(e); err == nil || !strings.HasPrefix(err.Error(), errE) {
			t.Errorf("expected error starts with %q, got %q", "yo", err)
		}
	})
}

func Test_TOPRF_Panic(t *testing.T) {
	// A nil ID or zero ID is provided in the evaluation identifiers
	errPolyXIsZero := errors.New("identifier for interpolation is nil or zero")

	// the list of peers has a zero identifier
	errPolyHasZeroCoeff := errors.New("one of the polynomial's coefficients is zero")

	// the list of peers doesn't include a provided id
	errPolyCoeffInexistant := errors.New("the identifier does not exist in the polynomial")

	// the list of peers has duplicates
	errPolyHasDuplicates := errors.New("the polynomial has duplicate coefficients")

	testAll(t, func(c *configuration) {
		sk := c.group.NewScalar().Random()
		blinded := c.group.Base()

		shares, err := secretsharing.Shard(c.ciphersuite.Group(), sk, 3, 5)
		if err != nil {
			panic(err)
		}

		evaluations := make([]*oprf.ThresholdEvaluation, 3)
		for i, share := range shares[:3] {
			evaluations[i] = &oprf.ThresholdEvaluation{
				Identifier: share.Identifier(),
				Evaluated:  oprf.Evaluate(share.SecretKey(), blinded),
			}
		}

		peers := []uint16{
			evaluations[0].Identifier,
			evaluations[1].Identifier,
			evaluations[2].Identifier,
		}

		// 1.
		{
			share := &keys.KeyShare{
				Secret: shares[1].SecretKey().Copy(),
				PublicKeyShare: keys.PublicKeyShare{
					ID: 0,
				},
			}

			if hasPanic, err := expectPanic(errPolyXIsZero, func() {
				_ = oprf.ThresholdEvaluate(c.group, peers, share, blinded)
			}); !hasPanic {
				t.Fatal(err)
			}
		}

		// 4.
		{
			ev := copyTEvals(evaluations)
			ev[1].Identifier = 0
			if hasPanic, err := expectPanic(errPolyHasZeroCoeff, func() {
				_ = oprf.ThresholdProxyCombine(c.group, ev)
			}); !hasPanic {
				t.Fatal(err)
			}
		}

		// 5.
		{
			share := &keys.KeyShare{
				Secret: shares[4].SecretKey().Copy(),
				PublicKeyShare: keys.PublicKeyShare{
					ID: shares[len(shares)-1].Identifier() + 1,
				},
			}

			if hasPanic, err := expectPanic(errPolyCoeffInexistant, func() {
				_ = oprf.ThresholdEvaluate(c.group, peers, share, blinded)
			}); !hasPanic {
				t.Fatal(err)
			}
		}

		// 6.
		{
			peers[2] = peers[0]
			share := &keys.KeyShare{
				Secret: shares[0].SecretKey().Copy(),
				PublicKeyShare: keys.PublicKeyShare{
					ID: shares[0].Identifier(),
				},
			}

			if hasPanic, err := expectPanic(errPolyHasDuplicates, func() {
				_ = oprf.ThresholdEvaluate(c.group, peers, share, blinded)
			}); !hasPanic {
				t.Fatal(err)
			}
		}

		// 7.
		{
			ev := copyTEvals(evaluations)
			ev[1].Identifier = ev[0].Identifier
			if hasPanic, err := expectPanic(errPolyHasDuplicates, func() {
				_ = oprf.ThresholdProxyCombine(c.group, ev)
			}); !hasPanic {
				t.Fatal(err)
			}
		}
	})
}

func copyTEvals(te []*oprf.ThresholdEvaluation) []*oprf.ThresholdEvaluation {
	cpy := make([]*oprf.ThresholdEvaluation, 0, len(te))
	for _, e := range te {
		cpy = append(cpy, &oprf.ThresholdEvaluation{
			Identifier: e.Identifier,
			Evaluated:  e.Evaluated.Copy(),
		})
	}

	return cpy
}
