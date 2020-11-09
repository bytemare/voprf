package voprf

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup/group"
)

type token struct {
	// data represents the unique serialization of an Element
	data []byte
	// blind represents the scalar used to blind the Element
	blind group.Scalar
}

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
	serverPublicKey group.Element
	blindToken      group.Element
	issuedToken     group.Element
	*token
	evaluation        *Evaluation
	preprocessedBLind *PreprocessedBlind
	*oprf
}

// Blind obfuscates the input element with the use of an internal random scalar.
func (c *Client) Blind(input []byte) []byte {
	p := c.group.HashToGroup(input)

	// Create a new token
	c.token = &token{
		data: input,
	}

	if c.blinding == Multiplicative {
		c.token.blind = c.group.NewScalar().Random()
		c.blindToken = p.Mult(c.token.blind)
	} else {
		if c.preprocessedBLind == nil {
			panic("preprocessBlind is nil while using additive blinding")
		}
		// todo: Draft error, the blind is described as a scalar, but blindedPubKey is a point/element.
		//  Also, it's not necessary to actually keep it since it's already in the preprocessedBlind.
		// c.token.blind = c.PreprocessedBlind.blindedPubKey
		c.blindToken = p.Add(c.preprocessedBLind.blindedGenerator)
	}

	return c.blindToken.Bytes()
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
		c.issuedToken = c.evaluation.element.InvertMult(c.token.blind)
	} else {
		c.issuedToken = c.evaluation.element.Copy().Sub(c.preprocessedBLind.blindedPubKey)
	}

	return c.issuedToken.Bytes(), nil
}

// Finalize hashes the original input data and the server's issued element and returns the resulting digest.
func (c *Client) Finalize() []byte {
	return c.hashTranscript(c.token.data, c.issuedToken.Bytes(), c.info)
}

func (c *Client) verifyProof() bool {
	publicKey := c.serverPublicKey
	tokenList := []group.Element{c.blindToken}
	elementList := []group.Element{c.evaluation.element}

	a1, a2 := c.computeComposite(nil, publicKey, tokenList, elementList)

	ab := c.group.Base().Mult(c.evaluation.proofS)
	ap := publicKey.Mult(c.evaluation.proofC)
	a3 := ab.Add(ap)

	bm := a1.Mult(c.evaluation.proofS)
	bz := a2.Mult(c.evaluation.proofC)
	a4 := bm.Add(bz)
	c1 := c.proofScalar(publicKey, a1, a2, a3, a4)

	return ctEqual(c1.Bytes(), c.evaluation.proofC.Bytes())
}
