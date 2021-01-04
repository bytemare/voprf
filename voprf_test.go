package voprf

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/cryptotools/group"
	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
)

type test struct {
	Batch             int
	Blind             [][]byte
	BlindedElement    [][]byte
	EvaluationElement [][]byte
	ProofC            []byte
	ProofS            []byte
	Info              []byte
	Input             [][]byte
	Output            [][]byte
	UnblindedElement  [][]byte
}

type testVectors []vector

type testVector struct {
	Batch             int    `json:"Batch"`
	Blind             string `json:"Blind"`
	BlindedElement    string `json:"BlindedElement"`
	EvaluationElement string `json:"EvaluationElement"`
	EvaluationProof   struct {
		C string `json:"c,omitempty"`
		S string `json:"s,omitempty"`
	} `json:"EvaluationProof,omitempty"`
	Info             string `json:"Info"`
	Input            string `json:"Input"`
	Output           string `json:"Output"`
	UnblindedElement string `json:"UnblindedElement"`
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
	// evaluationElement, err := hex.DecodeString(tv.EvaluationElement)
	if err != nil {
		return nil, fmt.Errorf(" EvaluationElement decoding errored with %q", err)
	}

	proofC, err := hex.DecodeString(tv.EvaluationProof.C)
	if err != nil {
		return nil, fmt.Errorf(" ProofC decoding errored with %q", err)
	}

	proofS, err := hex.DecodeString(tv.EvaluationProof.S)
	if err != nil {
		return nil, fmt.Errorf(" ProofS decoding errored with %q", err)
	}

	info, err := hex.DecodeString(tv.Info)
	if err != nil {
		return nil, fmt.Errorf(" Info decoding errored with %q", err)
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

	unblinded, err := decodeBatch(tv.Batch, tv.UnblindedElement)
	// unblinded, err := hex.DecodeString(tv.UnblindedElement)
	if err != nil {
		return nil, fmt.Errorf(" UnblindedElement decoding errored with %q", err)
	}

	return &test{
		Batch:             tv.Batch,
		Blind:             blind,
		BlindedElement:    blinded,
		EvaluationElement: evaluationElement,
		ProofC:            proofC,
		ProofS:            proofS,
		Info:              info,
		Input:             input,
		Output:            output,
		UnblindedElement:  unblinded,
	}, nil
}

type vector struct {
	DST       string       `json:"groupDST"`
	Hash      string       `json:"hash"`
	Mode      Mode         `json:"mode"`
	PkSm      string       `json:"pkSm,omitempty"`
	SkSm      string       `json:"skSm"`
	SuiteID   Ciphersuite  `json:"suiteID"`
	SuiteName string       `json:"suiteName"`
	Vectors   []testVector `json:"vectors,omitempty"`
}

func hashToHash(h string) hash.Identifier {
	switch h {
	case "SHA256":
		return hash.SHA256
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
	if v.Mode != Base && v.Mode != Verifiable {
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
	if v.SuiteID == 0 || v.SuiteID >= maxID {
		t.Fatalf("invalid cipher suite %v / %v", v.SuiteID, v.SuiteName)
	}
}

func getPreprocessedBlind(c Ciphersuite, serverPublicKey []byte) (*PreprocessedBlind, error) {
	preprocessed, err := c.Preprocess(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("preprocess: %w", err)
	}

	encoded, err := preprocessed.Encode(encoding.JSON)
	if err != nil {
		return nil, fmt.Errorf("preprocess encode: %w", err)
	}

	decoded, err := DecodePreprocessedBlind(encoded, encoding.JSON)
	if err != nil {
		return nil, fmt.Errorf("preprocess decode: %w", err)
	}

	return decoded, nil
}

func getClient(c Ciphersuite, mode Mode, blinding Blinding, serverPublicKey []byte) (*Client, error) {
	var verifiablePubKey []byte

	if mode == Verifiable {
		verifiablePubKey = serverPublicKey
	}

	switch blinding {
	case Multiplicative:
		return c.Client(verifiablePubKey)
	case Additive:
		p, err := getPreprocessedBlind(c, serverPublicKey)
		if err != nil {
			return nil, err
		}

		return c.ClientAdditive(verifiablePubKey, p)
	default:
		return nil, errors.New("invalid blinding")
	}
}

func getServer(c Ciphersuite, mode Mode, privateKey []byte) (*Server, error) {
	switch mode {
	case Base:
		return c.Server(privateKey)
	case Verifiable:
		return c.VerifiableServer(privateKey)
	default:
		return nil, errors.New("invalid mode")
	}
}

func testBlind(t *testing.T, client *Client, input, blind, output []byte) {
	s, err := client.group.NewScalar().Decode(blind)
	if err != nil {
		t.Fatal(fmt.Errorf("blind decoding to scalar in suite %v errored with %q", client.oprf.id, err))
	}

	client.blind = []group.Scalar{s}

	blinded := client.Blind(input)

	if !assert.Equal(t, output, blinded) {
		t.Fatal("unexpected blinded output")
	}
}

func testBlindBatch(t *testing.T, client *Client, inputs, blinds, outputs [][]byte) {
	if err := client.initBlinding(len(inputs)); err != nil {
		t.Fatal(err)
	}

	for i, b := range blinds {
		s, err := client.group.NewScalar().Decode(b)
		if err != nil {
			t.Fatal(fmt.Errorf("blind decoding to scalar in suite %v errored with %q", client.oprf.id, err))
		}

		client.blind[i] = s
	}

	_, blinded, err := client.BlindBatch(inputs)
	if err != nil {
		t.Fatal(err)
	}

	if !assert.Equal(t, outputs, blinded) {
		t.Fatal("unexpected blinded output")
	}
}

func testBlindBatchWithBlinds(t *testing.T, client *Client, inputs, blinds, outputs [][]byte) {
	blinded, err := client.BlindBatchWithBlinds(blinds, inputs)
	if err != nil {
		t.Fatal(err)
	}

	if !assert.Equal(t, outputs, blinded) {
		t.Fatal("unexpected blinded output")
	}
}

func testOPRF(t *testing.T, mode Mode, client *Client, server *Server, test *test) {
	var err error

	// Client Blinding
	if test.Batch == 1 {
		testBlind(t, client, test.Input[0], test.Blind[0], test.BlindedElement[0])
	} else {
		testBlindBatch(t, client, test.Input, test.Blind, test.BlindedElement)
		testBlindBatchWithBlinds(t, client, test.Input, test.Blind, test.BlindedElement)
	}

	// Server evaluating
	var ev *Evaluation
	if test.Batch == 1 {
		ev, err = server.Evaluate(test.BlindedElement[0])
		if err != nil {
			t.Fatal(err)
		}

		if !assert.Equal(t, test.EvaluationElement[0], ev.Elements[0]) {
			t.Fatal("unexpected evaluation element")
		}
	} else {
		ev, err = server.EvaluateBatch(test.BlindedElement)
		if err != nil {
			t.Fatal(err)
		}

		if !assert.Equal(t, test.EvaluationElement, ev.Elements) {
			t.Fatal("unexpected evaluation elements")
		}
	}

	// Set proofs
	if mode == Verifiable {
		//if !assert.Equal(t, test.ProofC, ev.ProofC) {
		//	t.Error("unexpected c proof")
		//}

		//if !assert.Equal(t, test.ProofS, ev.ProofS) {
		//	t.Error("unexpected s proof")
		//}
		//ev.ProofC = test.ProofC
		//ev.ProofS = test.ProofS
	}

	e, err := ev.deserialize(client.group)
	if err != nil {
		t.Fatal(err)
	}

	// Client unblinding
	if test.Batch == 1 {
		unblindedElement := client.unblind(e.elements[0], 0)

		if !assert.Equal(t, test.UnblindedElement[0], unblindedElement.Bytes(), "unblinded value is not valid.") {
			t.Fatal("not equal")
		}
	} else {
		for i, ee := range e.elements {
			u := client.unblind(ee, i)

			if !assert.Equal(t, test.UnblindedElement[i], u.Bytes(), "unblinded value %d is not valid.", i) {
				t.Fatal("not equal")
			}
		}
	}

	// Client finalize
	if test.Batch == 1 {
		output, err := client.Finalize(ev, test.Info)
		if err != nil {
			t.Fatal(err)
		}

		if !assert.Equal(t, test.Output[0], output, "finalize() output is not valid.") {
			t.Fatal("not equal")
		}

		if !server.VerifyFinalize(test.Input[0], output, test.Info) {
			t.Fatal("VerifyFinalize() returned false.")
		}
	} else {
		output, err := client.FinalizeBatch(ev, test.Info)
		if err != nil {
			t.Fatal(err)
		}

		if !assert.Equal(t, test.Output, output, "finalizeBatch() output is not valid.") {
			t.Fatal("not equal")
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
	suite := v.SuiteID

	privKey, err := hex.DecodeString(v.SkSm)
	if err != nil {
		t.Fatalf("private key decoding errored with %q\nfor sksm %v\n", err, v.SkSm)
	}

	var serverPublicKey []byte
	if mode == Verifiable {
		pksm, err := hex.DecodeString(v.PkSm)
		if err != nil {
			t.Fatalf("error decoding public key %v", err)
		}
		serverPublicKey = pksm
	}

	dst, err := hex.DecodeString(v.DST)
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

			// Set up a new server.
			server, err := getServer(suite, mode, privKey)
			if err != nil {
				t.Fatalf("failed on setting up server %q\nvector value (%d) %v\ndecoded (%d) %v\n", err, len(v.SkSm), v.SkSm, len(privKey), privKey)
			}

			if !assert.Equal(t, string(dst), server.group.DST(), "GroupDST output is not valid.") {
				t.Fatal("not equal")
			}

			// Set up a new client.
			client, err := getClient(suite, mode, Multiplicative, serverPublicKey)
			if err != nil {
				t.Fatal(err)
			}

			if !assert.Equal(t, string(dst), client.group.DST(), "GroupDST output is not valid.") {
				t.Fatal("not equal")
			}

			// test protocol execution
			testOPRF(t, mode, client, server, test)

			log.Printf("Success for %v - %v\n", v.SuiteName, v.Mode)
		})
	}
}

func TestVOPRF(t *testing.T) {
	if err := filepath.Walk("test",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, errOpen := os.Open(path)
			if errOpen != nil {
				return errOpen
			}

			defer file.Close()

			val, errRead := ioutil.ReadAll(file)
			if errRead != nil {
				return errRead
			}

			var v testVectors
			errJSON := json.Unmarshal(val, &v)
			if errJSON != nil {
				return errJSON
			}

			for _, tv := range v {
				t.Run(tv.SuiteName, tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}
