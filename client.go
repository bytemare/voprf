package voprf

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup/group"
)

type ppbEncoded struct {
	BlindedGenerator []byte `json:"g"`
	BlindedPubKey    []byte `json:"p"`
}

// PreprocessedBlind groups pre-computed values to be used as blinding by the CLient/Verifier.
type PreprocessedBlind struct {
	blindedGenerator group.Element
	blindedPubKey    group.Element
}

// Encode returns the encoding of the PreprocessedBlind in the given format.
func (p *PreprocessedBlind) Encode(enc encoding.Encoding) ([]byte, error) {
	e := &ppbEncoded{
		BlindedGenerator: p.blindedGenerator.Bytes(),
		BlindedPubKey:    p.blindedPubKey.Bytes(),
	}

	return enc.Encode(e)
}

// Client holds the client data and state during the OPRF.
type Client struct {
	// input is the original input to be blinded
	input []byte

	blind group.Scalar
	blindedElement group.Element
	unblindedElement group.Element
	serverPublicKey  group.Element

	evaluation        *Evaluation
	preprocessedBLind *PreprocessedBlind
	*oprf
}

// Blind obfuscates the input element with the use of an internal random scalar.
func (c *Client) Blind(input []byte) []byte {
	p := c.group.HashToGroup(input)
	c.input = input

	if c.blinding == Multiplicative {
		c.blind = c.group.NewScalar().Random()
		c.blindedElement = p.Mult(c.blind)
	} else {
		if c.preprocessedBLind == nil {
			panic("preprocessBlind is nil while using additive blinding")
		}
		c.blindedElement = p.Add(c.preprocessedBLind.blindedGenerator)
	}

	return c.blindedElement.Bytes()
}

// Start is a wrapper to Blind() and does strictly the same as Blind().
func (c *Client) Start(input []byte) []byte {
	return c.Blind(input)
}

// Finish groups the client's actions after receiving the server evaluation, and decodes and unblinds it, and returns
// the a hash of the protocol transcript.
func (c *Client) Finish(evaluation []byte, enc encoding.Encoding) (output []byte, err error) {
	if err := c.DecodeEvaluation(evaluation, enc); err != nil {
		return nil, err
	}

	if _, err := c.Unblind(); err != nil {
		return nil, err
	}

	return c.Finalize(), nil
}

// DecodeEvaluation decodes the encoded validation input int eh enc format and stores it internally if it succeeds.
func (c *Client) DecodeEvaluation(input []byte, enc encoding.Encoding) error {
	e, err := decodeEval(c.group, input, enc)
	if err != nil {
		return err
	}

	c.evaluation = e

	return nil
}

// Unblind reverts the blinding using the same scalar used in the blinding step.
func (c *Client) Unblind() ([]byte, error) {
	if c.mode == Verifiable {
		if c.serverPublicKey == nil {
			panic(errInternalNilPubVerifiable)
		}

		if !c.verifyProof() {
			return nil, errProofFailed
		}
	}

	if c.blinding == Multiplicative {
		c.unblindedElement = c.evaluation.element.InvertMult(c.blind)
	} else {
		c.unblindedElement = c.evaluation.element.Copy().Sub(c.preprocessedBLind.blindedPubKey)
	}

	return c.unblindedElement.Bytes(), nil
}

// Finalize hashes the original input data and the server's issued element and returns the resulting digest.
func (c *Client) Finalize() []byte {
	return c.hashTranscript(c.input, c.unblindedElement.Bytes(), c.info)
}

func (c *Client) verifyProof() bool {
	publicKey := c.serverPublicKey
	blindedElementList := []group.Element{c.blindedElement}
	evaluatedElementList := []group.Element{c.evaluation.element}

	a1, a2 := c.computeComposite(nil, publicKey, blindedElementList, evaluatedElementList)

	ab := c.group.Base().Mult(c.evaluation.proofS)
	ap := publicKey.Mult(c.evaluation.proofC)
	a3 := ab.Add(ap)

	bm := a1.Mult(c.evaluation.proofS)
	bz := a2.Mult(c.evaluation.proofC)
	a4 := bm.Add(bz)
	expectedC := c.proofScalar(publicKey, a1, a2, a3, a4)

	return ctEqual(expectedC.Bytes(), c.evaluation.proofC.Bytes())
}
