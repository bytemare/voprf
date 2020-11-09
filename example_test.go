// Package voprf provides abstracted access to Oblivious Pseudorandom Functions (OPRF)
// and Verifiable Oblivious Pseudorandom Functions (VOPRF) using Elliptic Curves (EC(V)OPRF).
//
// This work in progress implements https://tools.ietf.org/html/draft-irtf-cfrg-voprf
//
// Integrations can use either additive or multiplicative operations.
package voprf

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
)

func ExampleBaseMultiplicative() {
	input := []byte("input")
	enc := encoding.JSON

	// Set up a new server. A private key is automatically created if using nil as parameter.
	server, err := RistrettoSha512.Server(nil)
	if err != nil {
		panic(err)
	}

	// Set up a new client
	client := RistrettoSha512.Client()

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)

	// The server evaluates the blinded input, and returns an Evaluation.
	// This evaluation also contains proofs if Verifiable mode is requested.
	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	// The server encodes the Evaluation, and sends it to the client
	eval, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	// The client wraps up the protocol execution, by decoding the received evaluation,
	// reverting the blinding and hashing the protocol transcript.
	output, err := client.Finish(eval, enc)
	if err != nil {
		panic(err)
	}

	// This is not part of the protocol, but allows output verification
	if server.VerifyFinalize(input, output, client.info) {
		fmt.Printf("Success! The OPRF works as intended.")
	} else {
		fmt.Printf("Something went wrong.")
	}
	// Output: Success! The OPRF works as intended.
}

func ExampleBaseAdditive() {
	input := []byte("input")
	enc := encoding.JSON

	server, err := RistrettoSha512.Server(nil)
	if err != nil {
		panic(err)
	}

	// Get the encoded public key, to be send to clients through another channel
	serverPubKey := server.PublicKey()

	// The client preprocesses some values given the server's public key,
	// and should store it and retrieve it when needed.
	preprocessed, err := RistrettoSha512.Preprocess(serverPubKey)
	if err != nil {
		panic(err)
	}

	// Encode the preprocessed values for storage, and store it.
	encoded, err := preprocessed.Encode(enc)
	if err != nil {
		panic(err)
	}

	// Upon retrieval, decode/restore it.
	decoded, err := RistrettoSha512.DecodePreprocessedBlind(encoded, enc)
	if err != nil {
		panic(err)
	}

	// Instantiate a new client with the preprocessed values
	client := RistrettoSha512.ClientAdditive(decoded)

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)

	// The server evaluates the blinded input, and returns an Evaluation.
	// This evaluation also contains proofs if Verifiable mode is requested.
	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	// The server encodes the Evaluation, and sends it to the client
	eval, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	// The client wraps up the protocol execution, by decoding the received evaluation,
	// reverting the blinding and hashing the protocol transcript.
	output, err := client.Finish(eval, enc)
	if err != nil {
		panic(err)
	}

	// This is not part of the protocol, but allows output verification
	if server.VerifyFinalize(input, output, client.info) {
		fmt.Printf("Success! The OPRF works as intended.")
	} else {
		fmt.Printf("Something went wrong.")
	}
	// Output: Success! The OPRF works as intended.
}

func ExampleVerifiableMultiplicative() {
	input := []byte("input")
	enc := encoding.JSON

	server, err := RistrettoSha512.VerifiableServer(nil)
	if err != nil {
		panic(err)
	}

	// Get the encoded public key, to be send to clients through another channel
	pubKey := server.PublicKey()

	// Instantiate a new client that will verify the server's responses with the server's public key
	client, err := RistrettoSha512.VerifiableClient(pubKey)
	if err != nil {
		panic(err)
	}

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)

	// The server evaluates the blinded input, and returns an Evaluation.
	// This evaluation also contains proofs if Verifiable mode is requested.
	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	// The server encodes the Evaluation, and sends it to the client
	eval, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	// The client wraps up the protocol execution, by decoding the received evaluation,
	// reverting the blinding and hashing the protocol transcript.
	output, err := client.Finish(eval, enc)
	if err != nil {
		panic(err)
	}

	// This is not part of the protocol, but allows output verification
	if server.VerifyFinalize(input, output, client.info) {
		fmt.Printf("Success! The OPRF works as intended.")
	} else {
		fmt.Printf("Something went wrong.")
	}
	// Output: Success! The OPRF works as intended.
}

func ExampleVerifiableAdditive() {
	input := []byte("input")
	enc := encoding.JSON

	server, err := RistrettoSha512.VerifiableServer(nil)
	if err != nil {
		panic(err)
	}

	// Get the encoded public key, to be send to clients through another channel
	serverPubKey := server.PublicKey()

	// The client preprocesses some values given the server's public key,
	// and should store it and retrieve it when needed.
	preprocessed, err := RistrettoSha512.Preprocess(serverPubKey)
	if err != nil {
		panic(err)
	}

	// Encode the preprocessed values for storage, and store it.
	encoded, err := preprocessed.Encode(enc)
	if err != nil {
		panic(err)
	}

	// Upon retrieval, decode/restore it.
	decoded, err := RistrettoSha512.DecodePreprocessedBlind(encoded, enc)
	if err != nil {
		panic(err)
	}

	// Instantiate a new client with the preprocessed values
	client, err := RistrettoSha512.VerifiableClientAdditive(serverPubKey, decoded)
	if err != nil {
		panic(err)
	}

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)

	// The server evaluates the blinded input, and returns an Evaluation.
	// This evaluation also contains proofs if Verifiable mode is requested.
	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	// The server encodes the Evaluation, and sends it to the client
	eval, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	// The client wraps up the protocol execution, by decoding the received evaluation,
	// reverting the blinding and hashing the protocol transcript.
	output, err := client.Finish(eval, enc)
	if err != nil {
		panic(err)
	}

	// This is not part of the protocol, but allows output verification
	if server.VerifyFinalize(input, output, client.info) {
		fmt.Printf("Success! The OPRF works as intended.")
	} else {
		fmt.Printf("Something went wrong.")
	}
	// Output: Success! The OPRF works as intended.
}
