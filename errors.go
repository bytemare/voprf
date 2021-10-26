package voprf

import "errors"

var (
	errParamInvalidID     = errors.New("invalid Ciphersuite identifier")
	errParamFinalizeLen   = errors.New("invalid number of elements in evaluation")
	errParamInputEqualLen = errors.New("input lengths are not equal")

	errEvalSerDeMin      = errors.New("evaluation : insufficient header length")
	errEvalSerDeElements = errors.New("evaluation : insufficient number of evaluations")
	errEvalSerDeProofLen = errors.New("evaluation : invalid length of proof")

	errStateDiffInput = errors.New("state : different number of input and blinded values")
	errStateDiffBlind = errors.New("state : got blinded elements but different number of blinds")
	errStateNoPubKey  = errors.New("state in verifiable mode but no server public key")

	errProofFailed = errors.New("proof fails")
)
