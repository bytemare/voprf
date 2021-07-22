package voprf

import (
	"encoding/hex"
	"github.com/bytemare/cryptotools/encoding"
)

func exchangeWithServer(blinded []byte, verifiable bool, enc encoding.Encoding) []byte {
	var server *Server
	var err error

	if verifiable {
		privateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")

		server, err = RistrettoSha512.VerifiableServer(privateKey)
		if err != nil {
			panic(err)
		}
	} else {
		server, err = RistrettoSha512.Server(nil)
		if err != nil {
			panic(err)
		}
	}

	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	ev, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	return ev
}

func ExampleBaseMultiplicativeClient() {
	input := []byte("input")
	enc := encoding.JSON

	// Set up a new client. Not indicating a server public key indicates we don't use the verifiable mode.
	client := RistrettoSha512.Client()

	// The client blinds the initial input, and sends this to the server.
	blinded := client.Blind(input)

	// Exchange with the server is not covered here. The following call is to mock an exchange with a server.
	ev := exchangeWithServer(blinded, false, enc)

	// The client needs to decode the evaluation to finalize the process.
	eval, err := DecodeEvaluation(ev, enc)
	if err != nil {
		panic(err)
	}

	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
	output, err := client.Finalize(eval)
	if output == nil || err != nil {
		panic(err)
	}
	// Output:
}

//func ExampleBaseAdditiveClient() {
//	input := []byte("input")
//	serverPubKey, _ := hex.DecodeString("066c39841db2ca3c2e83e251e71b619013674149692ca2ab41d1b33a1a4fff38")
//	enc := encoding.JSON
//
//	// The client preprocesses some values given the server's public key,
//	// and should store it to retrieve it when needed.
//	preprocessed, err := RistrettoSha512.Preprocess(serverPubKey)
//	if err != nil {
//		panic(err)
//	}
//
//	// encode the preprocessed values for storage, and store it.
//	encoded, err := preprocessed.Encode(enc)
//	if err != nil {
//		panic(err)
//	}
//
//	// Upon retrieval, decode/restore it.
//	decodedPPB, err := DecodePreprocessedBlind(encoded, enc)
//	if err != nil {
//		panic(err)
//	}
//
//	// Instantiate a new client with the preprocessed values.
//	// (Note that a nil public key here will switch in the base mode)
//	client, err := RistrettoSha512.ClientAdditive(nil, decodedPPB)
//	if err != nil {
//		panic(err)
//	}
//
//	// The client blinds the initial input, and sends this to the server.
//	blinded := client.Blind(input)
//
//	log.Printf("Blinding : %v\n", client.blinding)
//
//	// Exchange with the server is not covered here. The following call is to mock an exchange with a server.
//	ev := exchangeWithServer(blinded, false, enc)
//
//	log.Printf("Changed Blinding : %v\n", client.blinding)
//
//	// The client needs to decode the evaluation to finalize the process.
//	eval, err := DecodeEvaluation(ev, enc)
//	if err != nil {
//		panic(err)
//	}
//
//	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
//	output, err := client.Finalize(eval)
//	if output == nil || err != nil {
//		panic(err)
//	}
//	// Output:
//}
//
//func ExampleVerifiableClient() {
//	input := []byte("input")
//	serverPubKey, _ := hex.DecodeString("066c39841db2ca3c2e83e251e71b619013674149692ca2ab41d1b33a1a4fff38")
//	enc := encoding.JSON
//
//	// The client preprocesses some values given the server's public key,
//	// and should store it to retrieve it when needed.
//	preprocessed, err := RistrettoSha512.Preprocess(serverPubKey)
//	if err != nil {
//		panic(err)
//	}
//
//	// encode the preprocessed values for storage, and store it.
//	encoded, err := preprocessed.Encode(enc)
//	if err != nil {
//		panic(err)
//	}
//
//	// Upon retrieval, decode/restore it.
//	decodedPPB, err := DecodePreprocessedBlind(encoded, enc)
//	if err != nil {
//		panic(err)
//	}
//
//	// Instantiate a new client with the preprocessed values.
//	// (Note that a nil public key here will switch in the base mode)
//	log.Printf("pubkey %v", serverPubKey)
//	client, err := RistrettoSha512.ClientAdditive(serverPubKey, decodedPPB)
//	if err != nil {
//		panic(err)
//	}
//
//	// The client blinds the initial input, and sends this to the server.
//	blinded := client.Blind(input)
//
//	log.Printf("Blinding : %v\n", client.blinding)
//
//	// Exchange with the server is not covered here. The following call is to mock an exchange with a server.
//	ev := exchangeWithServer(blinded, false, enc)
//
//	log.Printf("Changed Blinding : %v\n", client.blinding)
//
//	// The client needs to decode the evaluation to finalize the process.
//	eval, err := DecodeEvaluation(ev, enc)
//	if err != nil {
//		panic(err)
//	}
//
//	// The client finalizes the protocol execution by reverting the blinding and hashing the protocol transcript.
//	// If proof verification fails, an error is returned.
//	output, err := client.Finalize(eval)
//	if output == nil || err != nil {
//		panic(err)
//	}
//	// Output:
//}

func ExampleBaseServer() {
	enc := encoding.JSON

	// We suppose the client sends this blinded element.
	blinded, _ := hex.DecodeString("7eaf3d7cbe43d54637274342ce53578b2aba836f297f4f07997a6e1dced1c058")

	// Set up a new server. A private key is automatically created if none is given.
	server, err := RistrettoSha512.Server(nil)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input.
	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	// The server encodes the evaluation, and sends it to the client.
	ev, err := evaluation.Encode(enc)
	if ev == nil || err != nil {
		panic(err)
	}
	// Output:
}

func ExampleVerifiableServer() {
	privateKey, _ := hex.DecodeString("8132542d5ed08594e7522b5eac6bee38bab5868996c25a3fd2a7739be1856b04")
	enc := encoding.JSON

	// We suppose the client sends this blinded element.
	blinded, _ := hex.DecodeString("7eaf3d7cbe43d54637274342ce53578b2aba836f297f4f07997a6e1dced1c058")

	// Set up a new server.
	server, err := RistrettoSha512.VerifiableServer(privateKey)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input. Proofs are embedded in the evaluation.
	evaluation, err := server.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	// The server encodes the evaluation, and sends it to the client.
	ev, err := evaluation.Encode(enc)
	if ev == nil || err != nil {
		panic(err)
	}
	// Output:
}
