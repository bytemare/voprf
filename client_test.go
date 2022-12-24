// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"bytes"
	"testing"
)

func testExport(t *testing.T, client *Client, export *State) {
	if export.Ciphersuite != client.id {
		t.Fatal("group does not match")
	}

	if export.Mode != client.mode {
		t.Fatal("mode is not correct")
	}

	if !bytes.Equal(export.ServerPublicKey, client.serverPublicKey.Encode()) {
		t.Fatal("blind is not correct")
	}

	for i, b := range client.input {
		if !bytes.Equal(export.Input[i], b) {
			t.Fatalf("input %d is not correct", i)
		}
	}

	for i, b := range client.blind {
		if !bytes.Equal(export.Blind[i], b.Encode()) {
			t.Fatalf("blind %d is not correct", i)
		}
	}
}

func dummyClientExport(t *testing.T) (*Client, *State) {
	suite := RistrettoSha512
	input := []byte("input")
	client, _ := suite.Client(OPRF, nil)
	client.Blind(input, nil)
	export := client.Export()

	testExport(t, client, export)

	return client, export
}

// func TestClient_Export(t *testing.T) {
// 	dummyClientExport(t)
// }
//
// func TestClient_Import(t *testing.T) {
// 	client, export := dummyClientExport(t)
//
// 	clientCopy, _ := RistrettoSha512.Client(OPRF, nil)
// 	if err := clientCopy.Import(export); err != nil {
// 		panic(err)
// 	}
//
// 	if !reflect.DeepEqual(client, clientCopy) {
// 		t.Fatal("Export encoding/decoding failed.")
// 	}
//
// 	testExport(t, clientCopy, export)
// }
