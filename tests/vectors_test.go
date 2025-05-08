// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"

	"github.com/bytemare/voprf/internal"
	"github.com/bytemare/voprf/voprf"

	oprf "github.com/bytemare/voprf"
)

type test struct {
	ServerPrivateKey  *ecc.Scalar
	ProofC            *ecc.Scalar
	NonceR            *ecc.Scalar
	ProofS            *ecc.Scalar
	Blind             []*ecc.Scalar
	BlindedElement    []*ecc.Element
	Info              []byte
	EvaluationElement []*ecc.Element
	Input             [][]byte
	Output            [][]byte
	Batch             int
	oprf.Ciphersuite
}

type testVector struct {
	EvaluationProof struct {
		Proof  string `json:"proof,omitempty"`
		Random string `json:"r,omitempty"`
	} `json:"Proof,omitempty"`
	Blind             string `json:"Blind"`
	BlindedElement    string `json:"BlindedElement"`
	EvaluationElement string `json:"EvaluationElement"`
	Info              string `json:"Info"`
	Input             string `json:"Input"`
	Output            string `json:"Output"`
	Batch             int    `json:"Batch"`
	Ciphersuite       oprf.Ciphersuite
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

func decodeBatchScalar(g ecc.Group, nb int, in string) ([]*ecc.Scalar, error) {
	b, err := decodeBatch(nb, in)
	if err != nil {
		return nil, err
	}

	res := make([]*ecc.Scalar, nb)
	for i, bi := range b {
		res[i] = g.NewScalar()
		if err := res[i].Decode(bi); err != nil {
			return nil, err
		}
	}

	return res, nil
}

func decodeBatchElement(g ecc.Group, nb int, in string) ([]*ecc.Element, error) {
	b, err := decodeBatch(nb, in)
	if err != nil {
		return nil, err
	}

	res := make([]*ecc.Element, nb)
	for i, bi := range b {
		res[i] = g.NewElement()
		if err := res[i].Decode(bi); err != nil {
			return nil, err
		}
	}

	return res, nil
}

//func (t *test) Verify(suite oprf.Ciphersuite) error {
//	g := suite.Group()
//
//	for i, b := range t.Blind {
//		if err := g.NewScalar().Decode(b); err != nil {
//			return fmt.Errorf("blind %d decoding: %w", i, err)
//		}
//	}
//
//	for i, b := range t.BlindedElement {
//		if err := g.NewElement().Decode(b); err != nil {
//			return fmt.Errorf("blinded element %d decoding: %w", i, err)
//		}
//	}
//
//	for i, b := range t.EvaluationElement {
//		if err := g.NewElement().Decode(b); err != nil {
//			return fmt.Errorf("evaluation element %d decoding: %w", i, err)
//		}
//	}
//
//	return nil
//}

func decodeScalar(g ecc.Group, s string) (*ecc.Scalar, error) {
	ds, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf(" ProofC decoding errored with %q", err)
	}

	out := g.NewScalar()
	if err := out.Decode(ds); err != nil {
		return nil, err
	}

	return out, nil
}

func (tv *testVector) Decode() (*test, error) {
	g := tv.Ciphersuite.Group()
	blind, err := decodeBatchScalar(g, tv.Batch, tv.Blind)
	// blind, err := hex.DecodeString(tv.Blind)
	if err != nil {
		return nil, fmt.Errorf(" Blind decoding errored with %q", err)
	}

	blinded, err := decodeBatchElement(g, tv.Batch, tv.BlindedElement)
	// blinded, err := hex.DecodeString(tv.BlindedElement)
	if err != nil {
		return nil, fmt.Errorf(" BlindedElement decoding errored with %q", err)
	}

	evaluationElement, err := decodeBatchElement(g, tv.Batch, tv.EvaluationElement)
	if err != nil {
		return nil, fmt.Errorf(" EvaluationElement decoding errored with %q", err)
	}

	info, err := hex.DecodeString(tv.Info)
	if err != nil {
		return nil, fmt.Errorf(" info decoding errored with %q", err)
	}

	var proofC, nonceR, proofS *ecc.Scalar
	if len(tv.EvaluationProof.Proof) != 0 {
		pLen := len(tv.EvaluationProof.Proof)
		c := tv.EvaluationProof.Proof[:pLen/2]
		s := tv.EvaluationProof.Proof[pLen/2:]

		proofC, err = decodeScalar(tv.Ciphersuite.Group(), c)
		if err != nil {
			return nil, fmt.Errorf(" ProofC decoding errored with %q", err)
		}

		proofS, err = decodeScalar(tv.Ciphersuite.Group(), s)
		if err != nil {
			return nil, fmt.Errorf(" ProofS decoding errored with %q", err)
		}

		nonceR, err = decodeScalar(tv.Ciphersuite.Group(), tv.EvaluationProof.Random)
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
		Ciphersuite:       tv.Ciphersuite,
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

type vectors []vector

type vector struct {
	DST         string        `json:"groupDST"`
	Hash        string        `json:"hash"`
	KeyInfo     string        `json:"keyInfo"`
	SksSeed     string        `json:"seed"`
	PkSm        string        `json:"pkSm,omitempty"`
	SkSm        string        `json:"skSm"`
	SuiteID     string        `json:"identifier"`
	TestVectors []testVector  `json:"vectors,omitempty"`
	Mode        internal.Mode `json:"mode"`
}

func hashToHash(h string) hash.Hash {
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
		return 0
	}
}

func (v vector) checkParams(t *testing.T) {
	// Check mode
	if v.Mode != internal.OPRF && v.Mode != internal.VOPRF && v.Mode != internal.POPRF {
		t.Fatalf("invalid mode %v", v.Mode)
	}

	// Check hash
	hID := hashToHash(v.Hash)
	if hID == 0 {
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

type Client interface {
	Blind(input []byte) *ecc.Element
	BlindBatch(inputs [][]byte) []*ecc.Element
	SetBlind(blind ...*ecc.Scalar)
}

func testBlind(t *testing.T, client Client, blind *ecc.Scalar, input []byte, expected *ecc.Element) {
	client.SetBlind(blind)
	blinded := client.Blind(input)

	if !blinded.Equal(expected) {
		t.Fatal("unexpected blinded output")
	}
}

func testBlindBatch(t *testing.T, client Client, blinds []*ecc.Scalar, inputs [][]byte, expected []*ecc.Element) {
	client.SetBlind(blinds...)

	blinded := client.BlindBatch(inputs)
	if len(blinded) != len(expected) {
		t.Fatal("different number of blinded elements than expected")
	}

	for i, b := range expected {
		if !b.Equal(expected[i]) {
			t.Fatalf("unexpected blinded output %d", i)
		}
	}
}

func testOPRFEvaluation(t *testing.T, test *test) {
	if len(test.BlindedElement) > 1 {
		ev := oprf.Evaluate(test.ServerPrivateKey, test.BlindedElement[0])

		if !test.EvaluationElement[0].Equal(ev) {
			t.Fatal("unexpected evaluation element")
		}
	} else {
		ev := oprf.EvaluateBatch(test.ServerPrivateKey, test.BlindedElement)

		if len(ev) != len(test.BlindedElement) {
			t.Fatal("unequal length")
		}

		for i, e := range ev {
			if !test.EvaluationElement[i].Equal(e) {
				t.Fatal("unexpected evaluation element")
			}
		}
	}
}

func testOPRFFinalize(t *testing.T, client *oprf.Client, test *test) {
	if test.Batch == 1 {
		output := client.Finalize(test.EvaluationElement[0])

		if !bytes.Equal(test.Output[0], output) {
			t.Fatal("finalize() output is not valid.")
		}
	} else {
		output, err := client.FinalizeBatch(test.EvaluationElement)
		if err != nil {
			t.Fatal(err)
		}

		for i, o := range test.Output {
			if !bytes.Equal(o, output[i]) {
				t.Fatal("finalizeBatch() output is not valid.")
			}
		}
	}
}

func testVPOPRFEvaluation(t *testing.T, server *voprf.Server, test *test) {
	var evaluation *voprf.Evaluation
	if test.Batch == 1 {
		evaluation = server.Evaluate(test.BlindedElement[0], test.NonceR)

		if !evaluation.Evaluations[0].Equal(test.EvaluationElement[0]) {
			t.Fatalf(
				"unexpected evaluation element:\n\twant: %v\n\tgot : %v\n",
				hex.EncodeToString(test.EvaluationElement[0].Encode()),
				hex.EncodeToString(evaluation.Evaluations[0].Encode()),
			)
		}
	} else {
		evaluation = server.EvaluateBatch(test.BlindedElement, test.NonceR)

		for i, e := range test.EvaluationElement {
			if !e.Equal(evaluation.Evaluations[i]) {
				t.Fatal("unexpected evaluation elements")
			}
		}
	}

	if !evaluation.Proof[0].Equal(test.ProofC) {
		t.Fatal("unexpected proof c")
	}

	if !evaluation.Proof[1].Equal(test.ProofS) {
		t.Fatal("unexpected proof s")
	}
}

func testVPOPRFFinalize(t *testing.T, client *voprf.Client, test *test) {
	evaluation := &voprf.Evaluation{
		Proof:       [2]*ecc.Scalar{test.ProofC, test.ProofS},
		Evaluations: test.EvaluationElement,
	}

	if test.Batch == 1 {
		output, err := client.Finalize(evaluation)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(test.Output[0], output) {
			t.Fatalf(
				"finalize() output is not valid.\n\twant: %s\n\tgot : %s\n",
				hex.EncodeToString(test.Output[0]),
				hex.EncodeToString(output),
			)
		}
	} else {
		output, err := client.FinalizeBatch(evaluation)
		if err != nil {
			t.Fatal(err)
		}

		for i, o := range test.Output {
			if !bytes.Equal(o, output[i]) {
				t.Fatal("finalizeBatch() output is not valid.")
			}
		}
	}
}

func testOPRF(
	t *testing.T,
	test *test,
) {
	client := test.Ciphersuite.Client()

	// OPRFClient Blinding
	if test.Batch == 1 {
		testBlind(t, client, test.Blind[0], test.Input[0], test.BlindedElement[0])
	} else {
		testBlindBatch(t, client, test.Blind, test.Input, test.BlindedElement)
	}

	// OPRFServer evaluating
	testOPRFEvaluation(t, test)

	// OPRFClient finalize
	testOPRFFinalize(t, client, test)
}

func testVPOPRF(
	t *testing.T,
	test *test,
) {
	sk, pk := test.ServerPrivateKey, test.Ciphersuite.Group().Base().Multiply(test.ServerPrivateKey)
	server := voprf.NewServer(test.Ciphersuite, test.Info...)
	if err := server.SetKeyPair(sk, pk); err != nil {
		t.Fatal(err)
	}

	client, err := voprf.NewClient(test.Ciphersuite, pk, test.Info...)
	if err != nil {
		t.Fatal(err)
	}

	// OPRFClient Blinding
	if test.Batch == 1 {
		testBlind(t, client, test.Blind[0], test.Input[0], test.BlindedElement[0])
	} else {
		testBlindBatch(t, client, test.Blind, test.Input, test.BlindedElement)
	}

	// OPRFServer evaluating
	testVPOPRFEvaluation(t, server, test)

	// OPRFClient finalize
	testVPOPRFFinalize(t, client, test)
}

func (v vector) testVector(
	t *testing.T,
	test *test,
) {
	expectedDST, err := hex.DecodeString(v.DST)
	if err != nil {
		t.Fatalf("hex decoding errored with %q", err)
	}

	if string(
		expectedDST,
	) != string(
		internal.Dst(hash2groupDSTPrefix, internal.ContextString(v.Mode, test.Ciphersuite.Name())),
	) {
		t.Fatalf(
			"GroupDST output is not valid.\n\twant: %s\n\tgot : %s\n",
			expectedDST,
			internal.Dst(hash2groupDSTPrefix, internal.ContextString(v.Mode, test.Ciphersuite.Name())),
		)
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

	privKey, err := hex.DecodeString(v.SkSm)
	if err != nil {
		t.Fatalf("private key decoding errored with %q\nfor sksm %v\n", err, v.SkSm)
	}

	var sks *ecc.Scalar

	if v.Mode == internal.OPRF {
		sks, _ = oprf.DeriveKeyPair(test.Ciphersuite, seed, keyInfo)
	} else {
		server := voprf.NewServer(test.Ciphersuite, test.Info...)
		server.DeriveKeyPair(seed, keyInfo)
		sks, _ = server.KeyPair()
	}

	if !bytes.Equal(sks.Encode(), privKey) {
		t.Fatalf("DeriveKeyPair yields unexpected output\n\twant: %v\n\tgot : %v", privKey, sks.Encode())
	}

	test.ServerPrivateKey = sks

	// test protocol execution
	if v.Mode == internal.OPRF {
		testOPRF(t, test)
	} else {
		testVPOPRF(t, test)
	}
}

func suiteToCiphersuite(t *testing.T, s string) oprf.Ciphersuite {
	switch s {
	case "ristretto255-SHA512":
		return oprf.Ristretto255Sha512
	case "decaf448-SHAKE256":
		t.Fatal("decaf not supported")
	case "P256-SHA256":
		return oprf.P256Sha256
	case "P384-SHA384":
		return oprf.P384Sha384
	case "P521-SHA512":
		return oprf.P521Sha512
	}

	t.Fatalf("unknown suite: %s", s)
	return 0
}

func (v vector) test(t *testing.T) {
	// Check mode, hash function, and cipher suite
	v.checkParams(t)

	for i, tv := range v.TestVectors {
		t.Run(fmt.Sprintf("Vector %d", i), func(t *testing.T) {
			tv.Ciphersuite = suiteToCiphersuite(t, v.SuiteID)

			test, err := tv.Decode()
			if err != nil {
				t.Fatal(fmt.Sprintf("batches : %v Failed %v\n", tv.Batch, err))
			}

			v.testVector(t, test)
		})
	}
}

func loadVOPRFVectors(filepath string) (vectors, error) {
	contents, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var v vectors
	errJSON := json.Unmarshal(contents, &v)
	if errJSON != nil {
		return nil, errJSON
	}

	return v, nil
}

func TestVOPRFVectors(t *testing.T) {
	vectorFile := "allVectors.json"

	v, err := loadVOPRFVectors(vectorFile)
	if err != nil || v == nil {
		t.Fatal(err)
	}

	for _, tv := range v {
		if tv.SuiteID == "decaf448-SHAKE256" {
			continue
		}

		t.Run(string(tv.Mode)+" - "+tv.SuiteID, tv.test)
	}
}
