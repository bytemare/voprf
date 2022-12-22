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
	if export.Identifier != client.id {
		t.Fatal("group does not match")
	}

	if export.Mode != client.mode {
		t.Fatal("mode is not correct")
	}

	if !bytes.Equal(export.ServerPublicKey, serializePoint(client.serverPublicKey, pointLength(client.id))) {
		t.Fatal("blind is not correct")
	}

	for i, b := range client.input {
		if !bytes.Equal(export.Input[i], b) {
			t.Fatalf("input %d is not correct", i)
		}
	}

	for i, b := range client.blind {
		if !bytes.Equal(export.Blind[i], serializeScalar(b, scalarLength(client.id))) {
			t.Fatalf("blind %d is not correct", i)
		}
	}
}

//func TestClient_Export(t *testing.T) {
//	suite := RistrettoSha512
//	input := []byte("input")
//	server, _ := suite.OPRFServer(nil)
//	serverPubKey := server.PublicKey()
//	client, _ := suite.OPRFClient(serverPubKey)
//	client.Blind(input)
//
//	x := client.Export()
//
//	testExport(t, client, x)
//}

//func TestClient_Import(t *testing.T) {
//	suite := RistrettoSha512
//	enc := encoding.JSON
//	input := []byte("input")
//	server, _ := suite.OPRFServer(nil)
//	serverPubKey := server.PublicKey()
//	client, _ := suite.OPRFClient(serverPubKey)
//	client.Blind(input)
//	export := client.Export()
//
//	testExport(t, client, export)
//
//	encoded, err := enc.Encode(export)
//	if err != nil {
//		panic(err)
//	}
//
//	decoded, err := enc.Decode(encoded, &State{})
//	if err != nil {
//		panic(err)
//	}
//	export2 := decoded.(*State)
//
//	if !reflect.DeepEqual(export, export2) {
//		t.Fatal("Export encoding/decoding failed.")
//	}
//
//	clientCopy, _ := P256Sha256.OPRFClient(nil)
//	if err := clientCopy.Import(export2); err != nil {
//		panic(err)
//	}
//
//	testExport(t, clientCopy, export)
//}
