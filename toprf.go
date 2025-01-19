// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"
)

// ThresholdEvaluation is the result of the TOPRF server's evaluation.
type ThresholdEvaluation struct {
	// The Identifier is the identifier of the participant server that produced the Evaluated value.
	Identifier *group.Scalar

	// Evaluated is the output of the participant server's evaluation of the blinded input.
	Evaluated *group.Element
}

// TOPRFKeyShare identifies the sharded key share for a given participant.
type TOPRFKeyShare struct {
	// Identifier uniquely identifies a key share within secret sharing instance.
	Identifier *group.Scalar

	// SecretKey is the participant's secret share.
	SecretKey *group.Scalar
}

func delta(g group.Group, peers secretsharing.Polynomial, eval *ThresholdEvaluation) *group.Element {
	iv, err := peers.DeriveInterpolatingValue(g, eval.Identifier)
	if err != nil {
		panic(err)
	}

	return eval.Evaluated.Copy().Multiply(iv)
}

// ThresholdEvaluate is run by a participant server in the TOPRF scheme to evaluate a client's input instead of using
// the basic Evaluate function, upon which the different evaluations must be combined with ThresholdCombine. peers is
// the list of all the other active participants.
func ThresholdEvaluate(
	g group.Group,
	peers []*group.Scalar,
	share *TOPRFKeyShare,
	blinded *group.Element,
) *ThresholdEvaluation {
	eval := &ThresholdEvaluation{
		Identifier: share.Identifier,
		Evaluated:  Evaluate(share.SecretKey, blinded),
	}

	eval.Evaluated = delta(g, peers, eval)

	return eval
}

// ThresholdCombine is used to combine evaluations produced by ThresholdEvaluate to produce the evaluated element to be
// consumed by the client. This can be done by a proxy or on the client before being provided to the Finalize function.
func ThresholdCombine(evaluations []*ThresholdEvaluation) *group.Element {
	result := evaluations[0].Evaluated.Copy()

	for _, ev := range evaluations[1:] {
		result.Add(ev.Evaluated)
	}

	return result
}

// ThresholdProxyCombine is used to combine evaluations if the basic Evaluate was used before using a key share in the
// threshold setup. This requires no modification of the server's Evaluate call. Note that this concentrates some degree
// of computation that could be offloaded to the threshold participants using ThresholdEvaluate instead of Evaluate,
// and ThresholdCombine instead of ThresholdProxyCombine. This can be done by a proxy or on the client before being
// provided to the Finalize function.
func ThresholdProxyCombine(g group.Group, evaluations []*ThresholdEvaluation) *group.Element {
	peers := make(secretsharing.Polynomial, len(evaluations))
	for i, ev := range evaluations {
		peers[i] = ev.Identifier
	}

	result := g.NewElement()

	for _, ev := range evaluations {
		d := delta(g, peers, ev)
		result.Add(d)
	}

	return result
}
