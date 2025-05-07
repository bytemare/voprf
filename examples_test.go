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
	"slices"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/voprf/voprf"

	secretsharing "github.com/bytemare/secret-sharing"
	oprf "github.com/bytemare/voprf"
)

func exchangeWithOPRFServer(blinded *ecc.Element) []byte {
	// Let's say this is the private key the server uses.
	encodedPrivateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")
	privateKey, err := oprf.Ristretto255Sha512.DecodeScalar(encodedPrivateKey)
	if err != nil {
		panic(err)
	}

	return oprf.Evaluate(privateKey, blinded).Encode()
}

func exchangeWithVOPRFServer(ciphersuite oprf.Ciphersuite, blinded *ecc.Element) []byte {
	// Let's say this is the private key the server uses.
	encodedPrivateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")
	privateKey, err := oprf.Ristretto255Sha512.DecodeScalar(encodedPrivateKey)
	if err != nil {
		panic(err)
	}

	publicKey := ciphersuite.Group().Base().Multiply(privateKey)

	server := voprf.NewServer(oprf.Ristretto255Sha512)
	if err = server.SetKeyPair(privateKey, publicKey); err != nil {
		panic(err)
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
	if output == nil {
		panic("output is nil")
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
		panic(err)
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

var (
	toprfKeyShares       []*keys.KeyShare
	toprfGlobalSecretKey *ecc.Scalar
	toprfThreshold       = uint16(3)
	toprfMaxParticipants = uint16(5)
)

// Example_key_generation shows how to create keys in a threshold setup with distributed key generation described in
// the original FROST paper.
func Example_key_generation_decentralised() {
	fmt.Println("Visit github.com/bytemare/dkg for an example and documentation.")
	// Output: Visit github.com/bytemare/dkg for an example and documentation.
}

func Example_key_generation_centralised() {
	ciphersuite := oprf.Ristretto255Sha512

	// This is the global secret to be shared
	toprfGlobalSecretKey = ciphersuite.Group().NewScalar().Random()

	// Shard the secret into shares
	var err error

	toprfKeyShares, err = secretsharing.Shard(
		ciphersuite.Group(),
		toprfGlobalSecretKey,
		toprfThreshold,
		toprfMaxParticipants,
	)
	if err != nil {
		panic(err)
	}
}

// This shows how to run an OPRF in a threshold setting, where t among n servers can evaluate a client's blinded input.
// Not that, for the example, we use a central trusted dealer to shard and distribute the key shares, but it's highly
// recommended to use a distributed key generation.
// There are two options for the threshold evaluation
//  1. ThresholdEvaluate + ThresholdCombine: more efficient, replaces the server's oprf Evaluate() function, but
//     participants must know the identities of the other participants.
//  2. oprf Evaluate() + ThresholdProxyCombine: easier, less efficient, participants don't need to know the other
//     participants, and servers use the unmodified oprf Evaluate().
func Example_toprf() {
	ciphersuite := oprf.Ristretto255Sha512
	clientInput := []byte("client secret")

	// Server setup. We need a set of n key shares. Use:
	//	- Example_toprf_dkg_setup for an example of distributed key generation setup (recommended)
	// 	- Example_key_generation_centralised for an example of trusted dealer's centralized key generation
	// In both cases the combination of all shares is stored in toprfGlobalSecretKey.
	Example_key_generation_centralised()

	// The client starts as with the base OPRF mode.
	client := ciphersuite.Client()
	blinded := client.Blind(clientInput)

	// The client then sends the blinded input to the servers. Among these servers, at least the threshold amount of
	// uncompromised servers must evaluate that blinded input and respond. Let's use the following selection of servers.
	participantServers := []*keys.KeyShare{
		toprfKeyShares[2],
		toprfKeyShares[0],
		toprfKeyShares[3],
	}

	// All participants need to know the identifiers of the other participants
	participantServersIdentifiers := []uint16{
		participantServers[0].Identifier(),
		participantServers[1].Identifier(),
		participantServers[2].Identifier(),
	}

	evaluations := make([]*oprf.ThresholdEvaluation, len(participantServers))

	// The following shows the first option.
	for i, serverShare := range participantServers {
		evaluations[i] = oprf.ThresholdEvaluate(
			ciphersuite.Group(),
			participantServersIdentifiers,
			serverShare,
			blinded,
		)
	}

	// The set of responses must now be combined. This can be done server-side or on the client.
	combined := oprf.ThresholdCombine(evaluations)

	// The client then proceeds as usual, and finalizes the protocol.
	option1Output := client.Finalize(combined)

	// Now let's see how to use the second option.
	for i, serverShare := range participantServers {
		evaluations[i] = &oprf.ThresholdEvaluation{
			Identifier: serverShare.Identifier(),
			Evaluated:  oprf.Evaluate(serverShare.SecretKey(), blinded),
		}
	}

	// Recombine the distributed evaluations. This can be done server-side or on the client.
	combined = oprf.ThresholdProxyCombine(ciphersuite.Group(), evaluations)

	// The client then proceeds as usual, and finalizes the protocol.
	option2Output := client.Finalize(combined)

	// The following is to demonstrate we get the same results than with a base evaluation.
	referenceEvaluation := oprf.Evaluate(toprfGlobalSecretKey, blinded)
	referenceOutput := client.Finalize(referenceEvaluation)

	if slices.Compare(referenceOutput, option1Output) != 0 ||
		slices.Compare(referenceOutput, option2Output) != 0 {
		fmt.Printf("Base OPRF and TOPRF outputs differ:\n\twant: %s\n\tgot : %s\n\tgot : %s\n",
			hex.EncodeToString(referenceOutput),
			hex.EncodeToString(option1Output),
			hex.EncodeToString(option2Output))
	} else {
		fmt.Println("OPRF and TOPRF executions yield the same output!")
	}

	// Output:OPRF and TOPRF executions yield the same output!
}
