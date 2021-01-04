package voprf

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
)

// PreprocessedBlind holds the blinding values used in additive blinding.
type PreprocessedBlind struct {
	BlindedGenerator []byte `json:"g"`
	BlindedPubKey    []byte `json:"p"`
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

	if p.BlindedGenerator == nil {
		return nil, errPPNilGenerator
	}

	pp.blindedGenerator, err = g.NewElement().Decode(p.BlindedGenerator)
	if err != nil {
		return nil, err
	}

	if p.BlindedPubKey == nil {
		return nil, errPPNilPubKey
	}

	pp.blindedPubKey, err = g.NewElement().Decode(p.BlindedPubKey)
	if err != nil {
		return nil, err
	}

	return pp, nil
}

// ppb groups pre-computed values to be used as blinding by the Client/Verifier.
type ppb struct {
	blindedGenerator group.Element
	blindedPubKey    group.Element
}

func (p *ppb) serialize() *PreprocessedBlind {
	return &PreprocessedBlind{
		BlindedGenerator: p.blindedGenerator.Bytes(),
		BlindedPubKey:    p.blindedPubKey.Bytes(),
	}
}
