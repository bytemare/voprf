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
	"testing"

	"github.com/bytemare/voprf/voprf"
)

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
	isEqual := a.Proof[0].Equal(b.Proof[0]) == 1
	isEqual = isEqual && a.Proof[1].Equal(b.Proof[1]) == 1
	isEqual = isEqual && len(a.Evaluations) == len(b.Evaluations)

	if isEqual != expected {
		t.Fatalf("unexpected comparison result: want %v got %v", expected, isEqual)
	}

	for i, eval := range a.Evaluations {
		isEqual = isEqual && eval.Equal(b.Evaluations[i]) == 1
	}

	if isEqual != expected {
		t.Fatalf("unexpected comparison result: want %v got %v", expected, isEqual)
	}
}
