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

	group "github.com/bytemare/crypto"

	oprf "github.com/bytemare/voprf"
	"github.com/bytemare/voprf/voprf"
)

func exchangeWithOPRFServer(blinded *group.Element) []byte {
	// Let's say this is the private key the server uses.
	encodedPrivateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")
	privateKey, err := oprf.Ristretto255Sha512.DecodeScalar(encodedPrivateKey)
	if err != nil {
		panic(err)
	}

	return oprf.Evaluate(privateKey, blinded).Encode()
}

func exchangeWithVOPRFServer(ciphersuite oprf.Ciphersuite, blinded *group.Element) []byte {
	// Let's say this is the private key the server uses.
	encodedPrivateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")
	privateKey, err := oprf.Ristretto255Sha512.DecodeScalar(encodedPrivateKey)
	if err != nil {
		panic(err)
	}

	publicKey := ciphersuite.Group().Base().Multiply(privateKey)

	server := voprf.NewServer(oprf.Ristretto255Sha512)
	if err = server.SetKeyPair(privateKey, publicKey); err != nil {
		if err != nil {
			panic(err)
		}
	}

	return server.Evaluate(blinded).Serialize()
}

// This shows you how to set up and run the base OPRF client.
func Example_oprf_client() {
	// Your configuration.
	ciphersuite := oprf.Ristretto255Sha512
	input := []byte("input")

	// Set up a new client.
	client := ciphersuite.Client()

	// The following is optional and only useful in very rare edge-cases (e.g. tests), where you want to use a specific
	// blind. Note that blinds are supposed to be secret and ephemeral.
	// In normal circumstances, you don't need to set your blinds.
	encodedBlind, _ := hex.DecodeString("39b5cfe207bfa50cf4ae02becc06332ae44f746514139896faef99b64cd7d20c")

	blind, err := ciphersuite.DecodeScalar(encodedBlind)
	if err != nil {
		panic(err)
	}

	client.SetBlind(blind)

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)
	fmt.Printf(
		"Send these %d encoded bytes to the server: %s\n",
		len(blinded.Encode()),
		hex.EncodeToString(blinded.Encode()),
	)

	// For the purpose of this example, the following simulates and exchange with the server: the client sends the
	// blinded element, and the server sends back the evaluated element.
	encodedEvaluation := exchangeWithOPRFServer(blinded)

	// If a byte array was received, client needs to decode the encoded evaluation to finalize the process.
	evaluated, err := ciphersuite.DecodeElement(encodedEvaluation)
	if err != nil {
		panic(err)
	}

	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
	output := client.Finalize(evaluated)
	if output == nil || err != nil {
		panic(err)
	}

	fmt.Printf("OPRF client output: %s\n", hex.EncodeToString(output))
	// Output:Send these 32 encoded bytes to the server: aee258da2b3f9c5616f19fb84f40f04278539253a02789490c0a5b380dc8eb39
	// OPRF client output: 08b80bebe6c6aa40143f46c0892f930b98efa122f89a16e62471a05c905e9ffa9be7f8e5633bb95edd28e96b113d1d0fee66b4e6a83942685a36876a6e37550b
}

// This shows you how to set up and run the base OPRF server evaluation.
func Example_oprf_server() {
	// Your configuration.
	ciphersuite := oprf.Ristretto255Sha512
	encodedPrivateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")

	// Let's decode the server keys.
	privateKey, err := oprf.Ristretto255Sha512.DecodeScalar(encodedPrivateKey)
	if err != nil {
		panic(err)
	}

	// We suppose the client sends this blinded element.
	encodedBlindedElement, _ := hex.DecodeString("7eaf3d7cbe43d54637274342ce53578b2aba836f297f4f07997a6e1dced1c058")

	// We need to decode the client provided element.
	blinded, err := ciphersuite.DecodeElement(encodedBlindedElement)
	if err != nil {
		panic(err)
	}

	// No need to set up a server, as the operation is very simple.
	evaluation := oprf.Evaluate(privateKey, blinded)

	// The server encodes the evaluation, and sends it to the client.
	encodedEvaluation := evaluation.Encode()
	fmt.Printf("Encoded evaluation: %s", hex.EncodeToString(encodedEvaluation))
	// Output:Encoded evaluation: 8c2466a064a1eab64b226aa5a19df2115383693fe4ef260976e18949d28e9050
}

// This shows you how to set up and run the Verifiable OPRF client.
func Example_voprf_client() {
	// Your configuration.
	ciphersuite := oprf.Ristretto255Sha512
	input := []byte("input")
	serverPublicKeyHex := "066c39841db2ca3c2e83e251e71b619013674149692ca2ab41d1b33a1a4fff38"

	// To initiate the client we the server's public key.
	encodedServerPubKey, _ := hex.DecodeString(serverPublicKeyHex)
	serverPublicKey, _ := ciphersuite.DecodeElement(encodedServerPubKey)

	// Instantiate a new client with the preprocessed values.
	client, err := voprf.NewClient(ciphersuite, serverPublicKey)
	if err != nil {
		panic(err)
	}

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)

	// Exchange with the server is not covered here. The following call is to mock an exchange with a server.
	evaluation := exchangeWithVOPRFServer(ciphersuite, blinded)

	// The client needs to decode the evaluation to finalize the process.
	eval := new(voprf.Evaluation)
	eval.SetCiphersuite(ciphersuite)
	if err = eval.Deserialize(evaluation); err != nil {
		panic(err)
	}

	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
	// If proof verification fails, an error is returned.
	output, err := client.Finalize(eval)
	if output == nil || err != nil {
		panic(err)
	}
	// Output:
}

// This shows you how to set up and run the Verifiable OPRF server.
func Example_voprf_server() {
	// Your configuration.
	ciphersuite := oprf.Ristretto255Sha512
	encodedPrivateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")
	encodedPublicKey, _ := hex.DecodeString("066c39841db2ca3c2e83e251e71b619013674149692ca2ab41d1b33a1a4fff38")

	// Let's decode the server keys.
	privateKey, err := oprf.Ristretto255Sha512.DecodeScalar(encodedPrivateKey)
	if err != nil {
		panic(err)
	}

	publicKey, err := oprf.Ristretto255Sha512.DecodeElement(encodedPublicKey)
	if err != nil {
		panic(err)
	}

	// Set up a new server. If no info is provided, the VOPRF is used. If you want to use the POPRF mode,
	// you must provide the POPRF info here as the additional argument.
	server := voprf.NewServer(ciphersuite)

	if err = server.SetKeyPair(privateKey, publicKey); err != nil {
		if err != nil {
			panic(err)
		}
	}

	// Let's suppose the client sends this blinded element.
	encodedBlindedElement, _ := hex.DecodeString("7eaf3d7cbe43d54637274342ce53578b2aba836f297f4f07997a6e1dced1c058")

	// We need to decode the client provided element.
	blinded, err := ciphersuite.DecodeElement(encodedBlindedElement)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input.
	evaluation := server.Evaluate(blinded)

	// The server encodes the evaluation, and sends it to the client.
	_ = evaluation.Serialize()
	// Output:
}
