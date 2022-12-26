// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bytemare/voprf"
)

func TestClient_State(t *testing.T) {
	suite := voprf.RistrettoSha512
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

			if !cmp.Equal(export, export2) {
				t.Fatal("states are not equal")
			}
		})
	}
}
