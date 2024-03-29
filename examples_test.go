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
	"fmt"

	"github.com/bytemare/voprf"
)

func exchangeWithServer(blinded []byte, verifiable bool) []byte {
	var server *voprf.Server
	var err error
	privateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")

	if verifiable {
		server, err = voprf.Ristretto255Sha512.Server(voprf.VOPRF, privateKey)
		if err != nil {
			panic(err)
		}
	} else {
		server, err = voprf.Ristretto255Sha512.Server(voprf.OPRF, privateKey)
		if err != nil {
			panic(err)
		}
	}

	evaluation, err := server.Evaluate(blinded, nil)
	if err != nil {
		panic(err)
	}

	ev := evaluation.Serialize()

	return ev
}

// This shows you how to set up and run the base OPRF client.
func Example_client() {
	input := []byte("input")

	// Set up a new client. Not indicating a server public key indicates we don't use the verifiable mode.
	client, err := voprf.Ristretto255Sha512.Client(voprf.OPRF, nil)
	if err != nil {
		panic(err)
	}

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input, nil)
	fmt.Printf("Send these %d bytes to the server.\n", len(blinded))

	// Exchange with the server is not covered in this example. Let's say the server sends the following serialized
	// evaluation.
	evaluation, _ := hex.DecodeString("00010020b4d261d982c6edd2fea53e8a39c1df6393f23cb9d1b4768891ec2f43b8d8e831")

	// The client needs to decode the evaluation to finalize the process.
	eval := new(voprf.Evaluation)
	if err = eval.Deserialize(evaluation); err != nil {
		panic(err)
	}

	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
	output, err := client.Finalize(eval, nil)
	if output == nil || err != nil {
		panic(err)
	}
	// Output:Send these 32 bytes to the server.
}

// This shows you how to set up and run the Verifiable OPRF client.
func Example_verifiableClient() {
	ciphersuite := voprf.Ristretto255Sha512
	input := []byte("input")
	serverPubKey, _ := hex.DecodeString("066c39841db2ca3c2e83e251e71b619013674149692ca2ab41d1b33a1a4fff38")

	// Instantiate a new client with the preprocessed values.
	client, err := ciphersuite.Client(voprf.VOPRF, serverPubKey)
	if err != nil {
		panic(err)
	}

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input, nil)

	// Exchange with the server is not covered here. The following call is to mock an exchange with a server.
	evaluation := exchangeWithServer(blinded, true)

	// The client needs to decode the evaluation to finalize the process.
	eval := new(voprf.Evaluation)
	if err := eval.Deserialize(evaluation); err != nil {
		panic(err)
	}

	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
	// If proof verification fails, an error is returned.
	output, err := client.Finalize(eval, nil)
	if output == nil || err != nil {
		panic(err)
	}
	// Output:
}

// This shows you how to set up and run the base OPRF server.
func Example_server() {
	// We suppose the client sends this blinded element.
	blinded, _ := hex.DecodeString("7eaf3d7cbe43d54637274342ce53578b2aba836f297f4f07997a6e1dced1c058")

	// Set up a new server. A private key is automatically created if none is given.
	server, err := voprf.Ristretto255Sha512.Server(voprf.OPRF, nil)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input.
	evaluation, err := server.Evaluate(blinded, nil)
	if err != nil {
		panic(err)
	}

	// The server encodes the evaluation, and sends it to the client.
	_ = evaluation.Serialize()
	// Output:
}

// This shows you how to set up and run the Verifiable OPRF server.
func Example_verifiableServer() {
	privateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")

	// We suppose the client sends this blinded element.
	blinded, _ := hex.DecodeString("7eaf3d7cbe43d54637274342ce53578b2aba836f297f4f07997a6e1dced1c058")

	// Set up a new server.
	server, err := voprf.Ristretto255Sha512.Server(voprf.VOPRF, privateKey)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input. Proofs are embedded in the evaluation.
	evaluation, err := server.Evaluate(blinded, nil)
	if err != nil {
		panic(err)
	}

	// The server encodes the evaluation, and sends it to the client.
	_ = evaluation.Serialize()
	// Output:
}
