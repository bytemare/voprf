// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/voprf"

	secretsharing "github.com/bytemare/secret-sharing"
)

type testTOPRF struct {
	Secret      *ecc.Scalar
	Client      *voprf.Client
	Blind       *ecc.Scalar
	Blinded     *ecc.Element
	Evaluated   *ecc.Element
	Shares      []*keys.KeyShare
	Input       []byte
	Output      []byte
	NPeers      uint16
	NThreshold  uint16
	Ciphersuite voprf.Ciphersuite
	Group       ecc.Group
}

func testSetupShares(t *testing.T, cs voprf.Ciphersuite, n, min uint16, input string) *testTOPRF {
	toprf := &testTOPRF{
		Ciphersuite: cs,
		Group:       cs.Group(),
		Secret:      cs.Group().NewScalar().Random(),
		Shares:      nil,
		Input:       []byte(input),
		NPeers:      n,
		NThreshold:  min,
	}

	shares, err := secretsharing.Shard(cs.Group(), toprf.Secret, min, n)
	if err != nil {
		t.Fatal(err)
	}

	toprf.Shares = shares
	toprf.Blind = toprf.Group.NewScalar().Random()
	toprf.Client = cs.Client()
	toprf.Client.SetBlind(toprf.Blind)
	toprf.Blinded = toprf.Client.Blind(toprf.Input)
	toprf.Evaluated = voprf.Evaluate(toprf.Secret, toprf.Blinded)
	toprf.Output = toprf.Client.Finalize(toprf.Evaluated)

	return toprf
}

func shuffleEvaluations(e []*voprf.ThresholdEvaluation, indexes ...int) []*voprf.ThresholdEvaluation {
	shuffled := make([]*voprf.ThresholdEvaluation, len(indexes))
	for i, index := range indexes {
		shuffled[i] = &voprf.ThresholdEvaluation{
			Identifier: e[index].Identifier,
			Evaluated:  e[index].Evaluated,
		}
	}

	return shuffled
}

func selectParticipants(t *testTOPRF, indexes ...int) ([]uint16, []*keys.KeyShare) {
	ids := make([]uint16, len(indexes))
	shares := make([]*keys.KeyShare, len(indexes))
	for i, index := range indexes {
		ids[i] = t.Shares[index-1].Identifier()
		shares[i] = t.Shares[index-1]
	}

	return ids, shares
}

func Test_TOPRF_Distributed(t *testing.T) {
	const (
		peers     = 5
		threshold = 3
		cs        = voprf.Ristretto255Sha512
		password  = "password"
	)

	test := testSetupShares(t, cs, peers, threshold, password)

	// Evaluate by deriving the interpolation value at each participant, distributing the overhead.
	// This is the list of actual participants.
	indexes, indexesShares := selectParticipants(test, 1, 3, 4)

	newResponses := make([]*voprf.ThresholdEvaluation, threshold)

	for i := range threshold {
		newResponses[i] = voprf.ThresholdEvaluate(test.Group, indexes, indexesShares[i], test.Blinded)
	}

	// Reassemble the distributed responses, but with less overhead.
	combined := voprf.ThresholdCombine(newResponses)
	output := test.Client.Finalize(combined)

	// check for consistency
	if !bytes.Equal(output, test.Output) {
		t.Errorf(
			"OPRF and TOPRF outputs don't match:\n\t%s\n\t%s\n",
			hex.EncodeToString(combined.Encode()),
			hex.EncodeToString(test.Evaluated.Encode()),
		)
	}
}

func Test_TOPRF_ThresholdProxyCombine(t *testing.T) {
	const (
		peers     = 5
		threshold = 3
		cs        = voprf.Ristretto255Sha512
		password  = "password"
	)

	toprf := testSetupShares(t, cs, peers, threshold, password)

	// Calculate distributed evaluations, using the basic Evaluation function with a key share
	var evaluations [peers]*voprf.ThresholdEvaluation
	for i := range peers {
		evaluations[i] = &voprf.ThresholdEvaluation{
			Identifier: toprf.Shares[i].Identifier(),
			Evaluated:  voprf.Evaluate(toprf.Shares[i].SecretKey(), toprf.Blinded),
		}
	}

	// Shuffle evaluations to only take a subset of the distributed responses
	responses := shuffleEvaluations(evaluations[:], 0, 2, 3)

	// Recombine the distributed evaluations
	combined := voprf.ThresholdProxyCombine(toprf.Group, responses[:])

	// Finalize the OPRF.
	output := toprf.Client.Finalize(combined)

	// check for consistency
	if !bytes.Equal(output, toprf.Output) {
		t.Errorf(
			"OPRF and TOPRF outputs don't match:\n\t%s\n\t%s\n",
			hex.EncodeToString(output),
			hex.EncodeToString(toprf.Output),
		)
	}
}
