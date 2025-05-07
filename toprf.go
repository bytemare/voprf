// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

// ThresholdEvaluation is the result of the TOPRF server's evaluation.
type ThresholdEvaluation struct {
	Evaluated  *ecc.Element
	Identifier uint16
}

func delta(g ecc.Group, peers secretsharing.Polynomial, eval *ThresholdEvaluation) *ecc.Element {
	iv, err := peers.DeriveInterpolatingValue(g, g.NewScalar().SetUInt64(uint64(eval.Identifier)))
	if err != nil {
		panic(err)
	}

	return eval.Evaluated.Copy().Multiply(iv)
}

// ThresholdEvaluate is run by a participant server in the TOPRF scheme to evaluate a client's input instead of using
// the basic Evaluate function, upon which the different evaluations must be combined with ThresholdCombine.
// peers is the list of identifiers of all the other active participants.
func ThresholdEvaluate(
	g ecc.Group,
	peers []uint16,
	share *keys.KeyShare,
	blinded *ecc.Element,
) *ThresholdEvaluation {
	eval := &ThresholdEvaluation{
		Identifier: share.Identifier(),
		Evaluated:  Evaluate(share.SecretKey(), blinded),
	}

	peersScalars := secretsharing.NewPolynomialFromIntegers(g, peers)
	eval.Evaluated = delta(g, peersScalars, eval)

	return eval
}

// ThresholdCombine is used to combine evaluations produced by ThresholdEvaluate to return the evaluated element to be
// consumed by the client. This can be done by a proxy or on the client before being provided to the Finalize function.
func ThresholdCombine(evaluations []*ThresholdEvaluation) *ecc.Element {
	result := evaluations[0].Evaluated.Copy()

	for _, ev := range evaluations[1:] {
		result.Add(ev.Evaluated)
	}

	return result
}

// ThresholdProxyCombine is used to combine evaluations if the basic Evaluate was used before using a key share in the
// threshold setup. This requires no modification of the server's Evaluate call. Note that this concentrates some degree
// of computation that could be offloaded to the threshold participants if they use ThresholdEvaluate instead of
// Evaluate, and ThresholdCombine instead of ThresholdProxyCombine.
// This can be done by a proxy or on the client before being provided to the Finalize function.
func ThresholdProxyCombine(g ecc.Group, evaluations []*ThresholdEvaluation) *ecc.Element {
	peers := secretsharing.NewPolynomialFromListFunc(g, evaluations, func(e *ThresholdEvaluation) *ecc.Scalar {
		return g.NewScalar().SetUInt64(uint64(e.Identifier))
	})

	result := g.NewElement()

	for _, ev := range evaluations {
		d := delta(g, peers, ev)
		result.Add(d)
	}

	return result
}
