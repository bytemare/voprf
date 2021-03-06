package voprf

import "errors"

var (
	errParamPPNilBlind  = errors.New("can't PreprocessWithKey() with nil blind")
	errParamPPNilPubKey = errors.New("can't preprocess with nil server public key")
	errPPNilGenerator   = errors.New("preprocessed generator is nil")
	errPPNilPubKey      = errors.New("preprocessed public key is nil")

	errParamNilPPB        = errors.New("can't set up ClientAdditive with nil ppb")
	errParamInvalidID     = errors.New("invalid Ciphersuite identifier")
	errParamNoEncoding    = errors.New("encoding not set")
	errParamFinalizeLen   = errors.New("invalid number of elements in evaluation")
	errParamInputEqualLen = errors.New("input lengths are not equal")

	errInternNilPPBArgs   = errors.New("preprocessBlind lacks content")
	errInternalDecodePPB  = errors.New("internal : could not decode/cast to PreprocessedBlind struct")
	errInternalDecodeEval = errors.New("internal : could not decode/cast to Evaluation struct")

	errStateDiffInput = errors.New("state : different number of input and blinded values")
	errStateDiffBlind = errors.New("state : got blinded elements but different number of blinds")
	errStateNoPPB     = errors.New("state in additive blinding but no preprocessedblind")
	errStateNoPubKey  = errors.New("state in verifiable mode but no server public key")

	errProofFailed = errors.New("proof fails")
)
