package voprf

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/hashtogroup/group"
)

var (
	errArrayLength = errors.New("blinding init failed, non-nil array of incompatible length")
	errNilProofC   = errors.New("c proof is nil or empty")
	errNilProofS   = errors.New("s proof is nil or empty")
	errNilPPB      = errors.New("preprocessBlind is nil while using additive blinding")
)

// Client represents the Client/Verifier party in a (V)OPRF protocol session,
// and exposes relevant functions for its execution.
type Client struct {
	serverPublicKey group.Element
	*oprf

	input             [][]byte
	blind             []group.Scalar
	blindedElement    []group.Element
	preprocessedBLind *ppb
}

// State represents a client's state, allowing internal values to be exported and imported to resume a (V)OPRF session
type State struct {
	Ciphersuite	`json:"s"`
	Mode	`json:"m"`
	Blinding	`json:"b"`
	ServerPublicKey []byte	`json:"p,omitempty"`
	Input         [][]byte	`json:"i"`
	Blind         [][]byte	`json:"r"`
	PreprocessedBlind *PreprocessedBlind `json:"pb,omitempty"`
}

func (c *Client) Export() *State {
	s := &State{
		Ciphersuite: c.id,
		Mode:        c.mode,
		Blinding: c.blinding,
	}

	if c.serverPublicKey != nil {
		s.ServerPublicKey = c.serverPublicKey.Bytes()
	}

	if len(c.input) != len(c.blind) {
		panic("different number of input and blind values")
	}

	s.Input = make([][]byte, len(c.input))
	s.Blind = make([][]byte, len(c.blind))

	for i := 0; i < len(c.input); i++ {
		copy(s.Input[i], c.input[i])
		copy(s.Blind[i], c.blind[i].Bytes())
	}

	return s
}

func (c *Client) Import(state *State) error {
	var err error

	if len(state.Input) != len(state.Blind) {
		return errors.New("different number of input and blind values")
	}

	if state.Blinding == Additive && state.PreprocessedBlind == nil {
		return errors.New("state in additive blinding but no preprocessedblind")
	}

	if state.Mode == Verifiable && state.ServerPublicKey == nil {
		return errors.New("state in verifiable mode but no server public key")
	}

	c.oprf = suites[state.Ciphersuite].new(state.Mode, state.Blinding)

	c.serverPublicKey, err = c.group.NewElement().Decode(state.ServerPublicKey)
	if err != nil {
		return err
	}

	if state.PreprocessedBlind != nil {
		c.preprocessedBLind, err = state.PreprocessedBlind.deserialize(c.group)
		if err != nil {
			return err
		}
	}

	c.input = state.Input

	for i, b := range state.Blind {
		c.blind[i], err = c.group.NewScalar().Decode(b)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) initBlinding(length int) error {
	if len(c.input) == 0 {
		c.input = make([][]byte, length)
	} else if len(c.input) != length {
		return errArrayLength
	}

	if len(c.blind) == 0 {
		c.blind = make([]group.Scalar, length)
	} else if len(c.blind) != length {
		return errArrayLength
	}

	if len(c.blindedElement) == 0 {
		c.blindedElement = make([]group.Element, length)
	} else if len(c.blindedElement) != length {
		return errArrayLength
	}

	return nil
}

func (c *Client) blindInput(input []byte, scalar group.Scalar) (group.Scalar, group.Element) {
	p := c.group.HashToGroup(input)

	if c.blinding == Multiplicative {
		if scalar == nil {
			scalar = c.group.NewScalar().Random()
		}

		m := p.Mult(scalar)

		return scalar, m
	}

	if c.preprocessedBLind == nil {
		panic(errNilPPB)
	}

	return nil, p.Add(c.preprocessedBLind.blindedGenerator)
}

func (c *Client) verifyProof(proofC, proofS group.Scalar, blindedElementList, evaluatedElementList []group.Element) bool {
	publicKey := c.serverPublicKey

	a0, a1 := c.computeComposites(nil, publicKey, blindedElementList, evaluatedElementList)

	ab := c.group.Base().Mult(proofS)
	ap := publicKey.Mult(proofC)
	a2 := ab.Add(ap)

	bm := a0.Mult(proofS)
	bz := a1.Mult(proofC)
	a3 := bm.Add(bz)
	expectedC := c.proofScalar(publicKey, a0, a1, a2, a3)

	return ctEqual(expectedC.Bytes(), proofC.Bytes())
}

func (c *Client) innerBlind(input []byte, index int) {
	c.input[index] = input
	c.blind[index], c.blindedElement[index] = c.blindInput(input, c.blind[index])
}

// Blind blinds, or masks, the input with a preset or new random blinding element.
func (c *Client) Blind(input []byte) []byte {
	if err := c.initBlinding(1); err != nil {
		panic(err)
	}

	c.innerBlind(input, 0)

	return c.blindedElement[0].Bytes()
}

// BlindBatch allows blinding of batched input. If internal blinds are not set, new ones are created. In either case,
// the blinds are returned, and can safely be ignored if not needed externally. Subsequent calls on unblinding functions
// will automatically the internal blinds, unless specified otherwise through unblindBatchWithBlinds().
func (c *Client) BlindBatch(input [][]byte) (blinds, blindedElements [][]byte, err error) {
	if err := c.initBlinding(len(input)); err != nil {
		return nil, nil, err
	}

	blinds = make([][]byte, len(input))
	blindedElements = make([][]byte, len(input))

	for i, in := range input {
		c.innerBlind(in, i)
		blinds[i] = c.blind[i].Bytes()
		blindedElements[i] = c.blindedElement[i].Bytes()
	}

	return blindedElements, blindedElements, nil
}

// BlindBatchWithBlinds enables blinding batches while specifying which blinds to use.
func (c *Client) BlindBatchWithBlinds(blinds, input [][]byte) ([][]byte, error) {
	if len(blinds) != len(input) {
		return nil, errParamInputEqualLen
	}

	if err := c.initBlinding(len(blinds)); err != nil {
		return nil, err
	}

	blindedElements := make([][]byte, len(input))

	for i, blind := range blinds {
		s, err := c.group.NewScalar().Decode(blind)
		if err != nil {
			return nil, fmt.Errorf("input blind %d decoding errored with %w", i, err)
		}

		c.input[i] = input[i]
		c.blind[i], c.blindedElement[i] = c.blindInput(input[i], s)
		blindedElements[i] = c.blindedElement[i].Bytes()
	}

	return blindedElements, nil
}

func (c *Client) unblind(evaluated group.Element, index int) group.Element {
	if c.blinding == Multiplicative {
		return evaluated.InvertMult(c.blind[index])
	}

	return evaluated.Sub(c.preprocessedBLind.blindedPubKey)
}

// Finalize finalizes the protocol execution by verifying the proof if necessary,
// unblinding the evaluated element, and hashing the transcript.
func (c *Client) Finalize(e *Evaluation, info []byte) ([]byte, error) {
	output, err := c.FinalizeBatch(e, info)
	if err != nil {
		return nil, err
	}

	return output[0], nil
}

// FinalizeFinalizeBatch finalizes the protocol execution by verifying the proof if necessary,
// unblinding the evaluated elements, and hashing the transcript.
func (c *Client) FinalizeBatch(e *Evaluation, info []byte) ([][]byte, error) {
	if len(e.Elements) != len(c.input) {
		return nil, errParamFinalizeLen
	}

	ev, err := e.deserialize(c.group)
	if err != nil {
		return nil, err
	}

	if c.mode == Verifiable {
		if ev.proofC == nil {
			return nil, errNilProofC
		}

		if ev.proofS == nil {
			return nil, errNilProofS
		}

		if !c.verifyProof(ev.proofC, ev.proofS, c.blindedElement, ev.elements) {
			return nil, errProofFailed
		}
	}

	out := make([][]byte, len(c.input))

	for i, ee := range ev.elements {
		u := c.unblind(ee, i)
		out[i] = c.hashTranscript(c.input[i], u.Bytes(), info)
	}

	return out, nil
}