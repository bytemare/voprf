package voprf

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup/group"
)

type ppbEncoded struct {
	BlindedGenerator []byte `json:"g"`
	BlindedPubKey    []byte `json:"p"`
}

// PreprocessedBlind groups pre-computed values to be used as blinding by the Client/Verifier.
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

func (c *Client) verifyProof(proofC, proofS group.Scalar, blindedElementList, evaluatedElementList []group.Element) bool {
	publicKey := c.serverPublicKey

	a1, a2 := c.computeComposite(nil, publicKey, blindedElementList, evaluatedElementList)

	ab := c.group.Base().Mult(proofS)
	ap := publicKey.Mult(proofC)
	a3 := ab.Add(ap)

	bm := a1.Mult(proofS)
	bz := a2.Mult(proofC)
	a4 := bm.Add(bz)
	expectedC := c.proofScalar(publicKey, a1, a2, a3, a4)

	return ctEqual(expectedC.Bytes(), proofC.Bytes())
}

/*
TODO for info

Curious, I just looked up the different document versions and can't find why I thought it was of a specific format, I built it like "RFCXXX-$contextstring". I think it's this paragraph:

> Note that in the final output, the client computes Finalize over some auxiliary input data info. This parameter SHOULD be used for domain separation in the (V)OPRF protocol. Specifically, any system which has multiple (V)OPRF applications should use separate auxiliary values to ensure finalized outputs are separate. Guidance for constructing info can be found in {{!I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

i.e. build after "app-version-ciphersuite".

But now I see I wasn




Todo: Clarify Batched evaluations

0. Why only in verifiable mode ?
1. Not available in additive mode, since we're using multiple blinds. Explain the rationale.
2. Need API for client when setting up batch
3. Need API for server to know if we're playing with batch
4. Inner workings of Evaluation (done)
5. Client needs a flag to know it's handling a batch
6. Describe client API for unblinding batch (I saw the implem in the poc, but nothing in the I-D)
7. Finalize version of batched unblinded elements

Notes: order MUST be preserved, or unblinding will not have desired result.

I suppose rate-limiting / anti-dos must be implemented by higher level applications.

 */