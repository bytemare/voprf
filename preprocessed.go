package voprf

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
)

// PreprocessedBlind holds the blinding values used in additive blinding.
type PreprocessedBlind struct {
	BlindedGenerators [][]byte `json:"g"`
	BlindedPubKeys    [][]byte `json:"p"`
}

// DecodePreprocessedBlind decodes the encoded input preprocessed values and returns a pointer to an initialised
// PreprocessedBlind structure.
func DecodePreprocessedBlind(input []byte, enc encoding.Encoding) (*PreprocessedBlind, error) {
	p, err := enc.Decode(input, &PreprocessedBlind{})
	if err != nil {
		return nil, fmt.Errorf("could not decode preprocessed blind : %w", err)
	}

	pp, ok := p.(*PreprocessedBlind)
	if !ok {
		return nil, errInternalDecodePPB
	}

	return pp, nil
}

// Encode returns the encoding of the PreprocessedBlind in the given format.
func (p *PreprocessedBlind) Encode(enc encoding.Encoding) ([]byte, error) {
	if enc == 0 {
		return nil, errParamNoEncoding
	}

	return enc.Encode(p)
}

// deserialize returns a structure with the internal representations of the preprocessed values.
func (p *PreprocessedBlind) deserialize(g group.Group) (*ppb, error) {
	var err error

	pp := &ppb{}

	if p.BlindedGenerators == nil {
		return nil, errPPNilGenerator
	}

	if p.BlindedPubKeys == nil {
		return nil, errPPNilPubKey
	}

	pp.blindedGenerators = make([]group.Element, len(p.BlindedGenerators))
	pp.blindedPubKeys = make([]group.Element, len(p.BlindedPubKeys))

	for i, bg := range p.BlindedGenerators {
		pp.blindedGenerators[i], err = g.NewElement().Decode(bg)
		if err != nil {
			return nil, err
		}
	}

	for i, bp := range p.BlindedPubKeys {
		pp.blindedPubKeys[i], err = g.NewElement().Decode(bp)
		if err != nil {
			return nil, err
		}
	}

	return pp, nil
}

// ppb groups pre-computed values to be used as blinding by the Client/Verifier.
type ppb struct {
	blindedGenerators []group.Element
	blindedPubKeys    []group.Element
}

func (p *ppb) serialize() *PreprocessedBlind {
	pb := &PreprocessedBlind{
		BlindedGenerators: make([][]byte, len(p.blindedGenerators)),
		BlindedPubKeys:    make([][]byte, len(p.blindedPubKeys)),
	}

	for i, bg := range p.blindedGenerators {
		pb.BlindedGenerators[i] = bg.Bytes()
	}

	for i, bp := range p.blindedPubKeys {
		pb.BlindedPubKeys[i] = bp.Bytes()
	}

	return pb
}
