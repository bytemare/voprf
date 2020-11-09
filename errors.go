package voprf

import "errors"

var (
	errParamNilPPB      = errors.New("can't set up ClientAdditive with nil PreprocessedBlind")
	errParamNilPubAdd   = errors.New("can't set up ClientAdditive with nil server public key")
	errParamNilPubVerif = errors.New("can't set up VerifiableClient with nil server public key")
	errParamInvalidID   = errors.New("invalid Ciphersuite identifier")
	errParamNoEncoding  = errors.New("encoding not set")

	errInternNilPPBArgs         = errors.New("preprocessBlind lacks content")
	errInternalDecodePPB        = errors.New("internal : could not decode/cast to ppbEncoded struct")
	errInternalDecodeEval       = errors.New("internal : could not decode/cast to eval struct")
	errInternalNilPubVerifiable = errors.New("serverPublicKey is nil while in Verifiable mode")

	errProofFailed = errors.New("proof failes")
)
