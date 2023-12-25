// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/bytemare/voprf"
)

func TestEvaluationSerde(t *testing.T) {
	suite := voprf.Ristretto255Sha512
	input := []byte("input")
	mode := voprf.OPRF

	server, err := suite.Server(mode, nil)
	if err != nil {
		t.Fatal(err)
	}

	spk := server.PublicKey()

	client, err := suite.Client(mode, spk)
	if err != nil {
		t.Fatal(err)
	}

	blinded := client.Blind(input, nil)
	evaluation, err := server.Evaluate(blinded, nil)
	if err != nil {
		panic(err)
	}

	ser := evaluation.Serialize()
	deser := &voprf.Evaluation{}

	if err := deser.Deserialize(ser); err != nil {
		t.Fatal(err)
	}

	if !areArraysOfArraysEqual(evaluation.Elements, deser.Elements) {
		t.Fatal("evaluation serde failed")
	}

	if bytes.Compare(evaluation.ProofC, evaluation.ProofC) != 0 {
		t.Fatal("evaluation serde failed")
	}

	if bytes.Compare(evaluation.ProofS, evaluation.ProofS) != 0 {
		t.Fatal("evaluation serde failed")
	}
}

func TestClient_State(t *testing.T) {
	suite := voprf.Ristretto255Sha512
	input := []byte("input")
	kp := suite.KeyGen()              // only used in VOPRF and POPRF
	info := []byte("additional data") // only used in POPRF

	for _, mode := range []voprf.Mode{voprf.OPRF, voprf.VOPRF, voprf.POPRF} {
		t.Run(fmt.Sprintf("State test for mode %v", mode), func(t *testing.T) {
			client, err := suite.Client(mode, kp.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			client.Blind(input, info)

			export := client.Export()

			serialized, err := json.Marshal(export)
			if err != nil {
				t.Fatal(err)
			}

			state := &voprf.State{}
			if err := json.Unmarshal(serialized, state); err != nil {
				t.Fatal(err)
			}

			resumed, err := state.RecoverClient()
			if err != nil {
				t.Fatal(err)
			}

			export2 := resumed.Export()

			if !areStatesEqual(export, export2) {
				t.Fatal("states are not equal")
			}
		})
	}
}

func areArraysOfArraysEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, c := range a {
		if bytes.Compare(c, b[i]) != 0 {
			return false
		}
	}

	return true
}

func areStatesEqual(x1, x2 *voprf.State) bool {
	if x1.Mode != x2.Mode {
		return false
	}

	if x1.Identifier != x2.Identifier {
		return false
	}

	if bytes.Compare(x1.TweakedKey, x1.TweakedKey) != 0 {
		return false
	}

	if bytes.Compare(x1.ServerPublicKey, x1.ServerPublicKey) != 0 {
		return false
	}

	if !areArraysOfArraysEqual(x1.Input, x2.Input) {
		return false
	}

	if !areArraysOfArraysEqual(x1.Blind, x2.Blind) {
		return false
	}

	if !areArraysOfArraysEqual(x1.Blinded, x2.Blinded) {
		return false
	}

	return true
}
