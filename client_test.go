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

	if !bytes.Equal(export.ServerPublicKey, client.serverPublicKey.Bytes()) {
		t.Fatal("blind is not correct")
	}

	for i, b := range client.input {
		if !bytes.Equal(export.Input[i], b) {
			t.Fatalf("input %d is not correct", i)
		}
	}

	for i, b := range client.blind {
		if !bytes.Equal(export.Blind[i], b.Bytes()) {
			t.Fatalf("blind %d is not correct", i)
		}
	}
}

//func TestClient_Export(t *testing.T) {
//	suite := RistrettoSha512
//	input := []byte("input")
//	server, _ := suite.Server(nil)
//	serverPubKey := server.PublicKey()
//	client, _ := suite.Client(serverPubKey)
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
//	server, _ := suite.Server(nil)
//	serverPubKey := server.PublicKey()
//	client, _ := suite.Client(serverPubKey)
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
//	clientCopy, _ := P256Sha256.Client(nil)
//	if err := clientCopy.Import(export2); err != nil {
//		panic(err)
//	}
//
//	testExport(t, clientCopy, export)
//}
