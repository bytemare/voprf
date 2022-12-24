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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
)

type test struct {
	Batch             int
	Blind             [][]byte
	BlindedElement    [][]byte
	Info              []byte
	EvaluationElement [][]byte
	ProofC            []byte
	NonceR            []byte
	ProofS            []byte
	Input             [][]byte
	Output            [][]byte
}

type testVectors []vector

type testVector struct {
	Batch             int    `json:"Batch"`
	Blind             string `json:"Blind"`
	BlindedElement    string `json:"BlindedElement"`
	EvaluationElement string `json:"EvaluationElement"`
	Info              string `json:"Info"`
	EvaluationProof   struct {
		Proof  string `json:"proof,omitempty"`
		Random string `json:"r,omitempty"`
	} `json:"Proof,omitempty"`
	Input  string `json:"Input"`
	Output string `json:"Output"`
}

func decodeBatch(nb int, in string) ([][]byte, error) {
	v := strings.Split(in, ",")
	if len(v) != nb {
		return nil, fmt.Errorf("incoherent number of values in batch %d/%d", len(v), nb)
	}

	out := make([][]byte, nb)

	for i, s := range v {
		dec, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("hex decoding errored with %q", err)
		}
		out[i] = dec
	}

	return out, nil
}

func (t *test) Verify(suite Ciphersuite) error {
	g := suite.Group()

	for i, b := range t.Blind {
		if err := g.NewScalar().Decode(b); err != nil {
			return fmt.Errorf("blind %d decoding: %w", i, err)
		}
	}

	for i, b := range t.BlindedElement {
		if err := g.NewElement().Decode(b); err != nil {
			return fmt.Errorf("blinded element %d decoding: %w", i, err)
		}
	}

	for i, b := range t.EvaluationElement {
		if err := g.NewElement().Decode(b); err != nil {
			return fmt.Errorf("evaluation element %d decoding: %w", i, err)
		}
	}

	return nil
}

func (tv *testVector) Decode() (*test, error) {
	blind, err := decodeBatch(tv.Batch, tv.Blind)
	// blind, err := hex.DecodeString(tv.Blind)
	if err != nil {
		return nil, fmt.Errorf(" Blind decoding errored with %q", err)
	}

	blinded, err := decodeBatch(tv.Batch, tv.BlindedElement)
	// blinded, err := hex.DecodeString(tv.BlindedElement)
	if err != nil {
		return nil, fmt.Errorf(" BlindedElement decoding errored with %q", err)
	}

	evaluationElement, err := decodeBatch(tv.Batch, tv.EvaluationElement)
	if err != nil {
		return nil, fmt.Errorf(" EvaluationElement decoding errored with %q", err)
	}

	info, err := hex.DecodeString(tv.Info)
	if err != nil {
		return nil, fmt.Errorf(" info decoding errored with %q", err)
	}

	var proofC, nonceR, proofS []byte
	if len(tv.EvaluationProof.Proof) != 0 {
		pLen := len(tv.EvaluationProof.Proof)
		c := tv.EvaluationProof.Proof[:pLen/2]
		s := tv.EvaluationProof.Proof[pLen/2:]

		proofC, err = hex.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf(" ProofC decoding errored with %q", err)
		}

		proofS, err = hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf(" ProofS decoding errored with %q", err)
		}

		nonceR, err = hex.DecodeString(tv.EvaluationProof.Random)
		if err != nil {
			return nil, fmt.Errorf(" NonceR decoding errored with %q", err)
		}
	}

	input, err := decodeBatch(tv.Batch, tv.Input)
	// input, err := hex.DecodeString(tv.Input)
	if err != nil {
		return nil, fmt.Errorf(" Input decoding errored with %q", err)
	}

	output, err := decodeBatch(tv.Batch, tv.Output)
	// output, err := hex.DecodeString(tv.Output)
	if err != nil {
		return nil, fmt.Errorf(" Output decoding errored with %q", err)
	}

	return &test{
		Batch:             tv.Batch,
		Blind:             blind,
		BlindedElement:    blinded,
		EvaluationElement: evaluationElement,
		Info:              info,
		ProofC:            proofC,
		NonceR:            nonceR,
		ProofS:            proofS,
		Input:             input,
		Output:            output,
	}, nil
}

type vector struct {
	DST     string       `json:"groupDST"`
	Hash    string       `json:"hash"`
	Mode    Mode         `json:"mode"`
	KeyInfo string       `json:"keyInfo"`
	SksSeed string       `json:"seed"`
	PkSm    string       `json:"pkSm,omitempty"`
	SkSm    string       `json:"skSm"`
	SuiteID string       `json:"identifier"`
	Vectors []testVector `json:"vectors,omitempty"`
}

func hashToHash(h string) hash.Identifier {
	switch h {
	case "SHA256":
		return hash.SHA256
	case "SHA384":
		return hash.SHA384
	case "SHA512":
		return hash.SHA512
	case "SHA3-256":
		return hash.SHA3_256
	case "SHA3-512":
		return hash.SHA3_512
	case "SHAKE128":
		return hash.SHAKE128
	case "SHAKE256":
		return hash.SHAKE256
	case "BLAKE2XB":
		return hash.BLAKE2XB
	case "BLAKE2XS":
		return hash.BLAKE2XS
	default:
		return nil
	}
}

func (v vector) checkParams(t *testing.T) {
	// Check mode
	if v.Mode != OPRF && v.Mode != VOPRF && v.Mode != POPRF {
		t.Fatalf("invalid mode %v", v.Mode)
	}

	// Check hash
	hID := hashToHash(v.Hash)
	if hID == nil {
		t.Fatalf("invalid hash function %v", v.Hash)
	}

	if !hID.Available() {
		t.Fatalf("hash function not available %v", v.Hash)
	}

	// Check cipher suite
	//if v.SuiteID == 0 || v.SuiteID >= maxID {
	//	t.Fatalf("invalid cipher suite %v / %v", v.SuiteID, v.SuiteName)
	//}
}

func testBlind(t *testing.T, client *Client, input, blind, expected, info []byte) {
	s := client.group.NewScalar()
	if err := s.Decode(blind); err != nil {
		t.Fatal(fmt.Errorf("blind decoding to scalar in suite %v errored with %q", client.oprf.id, err))
	}

	client.blind = []*group.Scalar{s}

	blinded := client.Blind(input, info)

	if !bytes.Equal(expected, blinded) {
		t.Fatal("unexpected blinded output")
	}
}

func testBlindBatchWithBlinds(t *testing.T, client *Client, inputs, blinds, outputs [][]byte, info []byte) {
	blinded, err := client.BlindBatchWithBlinds(blinds, inputs, info)
	if err != nil {
		t.Fatal(err)
	}

	for i, o := range outputs {
		if !bytes.Equal(o, blinded[i]) {
			t.Fatal("unexpected blinded output")
		}
	}
}

func testOPRF(t *testing.T, mode Mode, client *Client, server *Server, test *test) {
	var err error

	// OPRFClient Blinding
	if test.Batch == 1 {
		testBlind(t, client, test.Input[0], test.Blind[0], test.BlindedElement[0], test.Info)
	} else {
		testBlindBatchWithBlinds(t, client, test.Input, test.Blind, test.BlindedElement, test.Info)
	}

	// OPRFServer evaluating
	var ev *Evaluation
	server.nonceR = test.NonceR
	if test.Batch == 1 {
		ev, err = server.Evaluate(test.BlindedElement[0], test.Info)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(test.EvaluationElement[0], ev.Elements[0]) {
			t.Fatal("unexpected evaluation element")
		}
	} else {
		ev, err = server.EvaluateBatch(test.BlindedElement, test.Info)
		if err != nil {
			t.Fatal(err)
		}

		for i, e := range test.EvaluationElement {
			if !bytes.Equal(e, ev.Elements[i]) {
				t.Fatal("unexpected evaluation elements")
			}
		}
	}

	// Verify proofs
	if mode == VOPRF || mode == POPRF {
		if !bytes.Equal(test.ProofC, ev.ProofC) {
			t.Errorf("unexpected c proof\n\twant %v\n\tgot  %v", hex.EncodeToString(test.ProofC), hex.EncodeToString(ev.ProofC))
		}

		if !bytes.Equal(test.ProofS, ev.ProofS) {
			t.Errorf("unexpected s proof\n\twant %v\n\tgot  %v", hex.EncodeToString(test.ProofS), hex.EncodeToString(ev.ProofS))
		}
	}

	// OPRFClient finalize
	if test.Batch == 1 {
		output, err := client.Finalize(ev, test.Info)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(test.Output[0], output) {
			t.Fatal("finalize() output is not valid.")
		}

		if !server.VerifyFinalize(test.Input[0], test.Info, output) {
			t.Fatal("VerifyFinalize() returned false.")
		}
	} else {
		output, err := client.FinalizeBatch(ev, test.Info)
		if err != nil {
			t.Fatal(err)
		}

		for i, o := range test.Output {
			if !bytes.Equal(o, output[i]) {
				t.Fatal("finalizeBatch() output is not valid.")
			}
		}

		if !server.VerifyFinalizeBatch(test.Input, output, test.Info) {
			t.Fatal("VerifyFinalize() returned false.")
		}
	}
}

func (v vector) test(t *testing.T) {
	// Check mode, hash function, and cipher suite
	v.checkParams(t)

	// Get mode, hash function, and cipher suite
	mode := v.Mode
	suite := suitesID[v.SuiteID]

	privKey, err := hex.DecodeString(v.SkSm)
	if err != nil {
		t.Fatalf("private key decoding errored with %q\nfor sksm %v\n", err, v.SkSm)
	}

	var serverPublicKey []byte
	if mode == VOPRF || mode == POPRF {
		pksm, err := hex.DecodeString(v.PkSm)
		if err != nil {
			t.Fatalf("error decoding public key %v", err)
		}
		serverPublicKey = pksm
	}

	expectedDST, err := hex.DecodeString(v.DST)
	if err != nil {
		t.Fatalf("hex decoding errored with %q", err)
	}

	// Test Multiplicative Mode
	for i, tv := range v.Vectors {
		t.Run(fmt.Sprintf("Vector %d", i), func(t *testing.T) {
			test, err := tv.Decode()
			if err != nil {
				t.Fatal(fmt.Sprintf("batches : %v Failed %v\n", tv.Batch, err))
			}

			if err := test.Verify(suite); err != nil {
				t.Fatal(err)
			}

			// Test DeriveKeyPair
			seed, err := hex.DecodeString(v.SksSeed)
			if err != nil {
				t.Fatal(err)
			}

			keyInfo, err := hex.DecodeString(v.KeyInfo)
			if err != nil {
				t.Fatal(err)
			}

			o := suites[suite].new(mode)

			sks, _ := o.DeriveKeyPair(seed, keyInfo)
			// log.Printf("sks %v", hex.EncodeToString(serializeScalar(sks, scalarLength(o.id))))
			if !bytes.Equal(sks.Encode(), privKey) {
				t.Fatalf("DeriveKeyPair yields unexpected output\n\twant: %v\n\tgot : %v", privKey, sks.Encode())
			}

			// Set up a new server.
			server, err := suite.Server(mode, privKey)
			if err != nil {
				t.Fatalf("failed on setting up server %q\nvector value (%d) %v\ndecoded (%d) %v\n", err, len(v.SkSm), v.SkSm, len(privKey), privKey)
			}

			if string(expectedDST) != string(dst(hash2groupDSTPrefix, o.contextString)) {
				t.Fatal("GroupDST output is not valid.")
			}

			client, err := suite.Client(mode, serverPublicKey)
			if err != nil {
				t.Fatal(err)
			}

			if string(expectedDST) != string(dst(hash2groupDSTPrefix, o.contextString)) {
				t.Fatal("GroupDST output is not valid.")
			}

			// test protocol execution
			testOPRF(t, mode, client, server, test)
		})
	}
}

func TestVOPRF(t *testing.T) {
	if err := filepath.Walk("test/allVectors.json",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var v testVectors
			errJSON := json.Unmarshal(contents, &v)
			if errJSON != nil {
				return errJSON
			}

			for _, tv := range v {
				if tv.SuiteID == "decaf448-SHAKE256" {
					continue
				}

				//if tv.SuiteName == "OPRF(P-384, SHA-384)" {
				//	continue
				//}

				t.Run(string(tv.Mode)+" - "+tv.SuiteID, tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}
