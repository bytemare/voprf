// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import "errors"

var (
	errParamInvalidMode   = errors.New("invalid OPRF mode")
	errParamInvalidID     = errors.New("invalid Identifier")
	errParamFinalizeLen   = errors.New("invalid number of elements in evaluation")
	errParamInputEqualLen = errors.New("input lengths are not equal")
	errParamNoPubKey      = errors.New("missing public key")

	errEvalSerDeMin      = errors.New("evaluation : insufficient header length")
	errEvalSerDeElements = errors.New("evaluation : insufficient number of evaluations")
	errEvalSerDeProofLen = errors.New("evaluation : invalid length of proof")

	errStateDiffInput = errors.New("state : different number of input and blinded values")
	errStateDiffBlind = errors.New("state : got blinded elements but different number of blinds")
	errStateNoPubKey  = errors.New("state in verifiable mode but no server public key")

	errProofFailed = errors.New("proof fails")
	errZeroScalar  = errors.New("inversion led to zero scalar")
)
