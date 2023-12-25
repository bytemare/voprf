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
)

const (
	dstComposite = "Composite"
	dstChallenge = "Challenge"
	dstFinalize  = "Finalize"
	dstSeed      = "Seed-"
	dstInfo      = "Info"
)

func (o *oprf) ccScalar(encSeed []byte, index int, ci, di *group.Element) *group.Scalar {
	input := concatenate(encSeed, i2osp2(index),
		lengthPrefixEncode(ci.Encode()),
		lengthPrefixEncode(di.Encode()),
		[]byte(dstComposite))

	return o.HashToScalar(input)
}

func (o *oprf) computeCompositesFast(k *group.Scalar, encSeed []byte, cs, ds []*group.Element) (m, z *group.Element) {
	m = o.group.NewElement().Identity()

	for i, ci := range cs {
		di := o.ccScalar(encSeed, i, ci, ds[i])
		m = ci.Copy().Multiply(di).Add(m)
	}

	return m, m.Copy().Multiply(k)
}

func (o *oprf) computeCompositesClient(encSeed []byte, cs, ds []*group.Element) (m, z *group.Element) {
	m = o.group.NewElement().Identity()
	z = o.group.NewElement().Identity()

	for i, ci := range cs {
		di := o.ccScalar(encSeed, i, ci, ds[i])
		m = ci.Copy().Multiply(di).Add(m)
		z = ds[i].Copy().Multiply(di).Add(z)
	}

	return m, z
}

func (o *oprf) computeComposites(k *group.Scalar, encGk []byte, cs, ds []*group.Element) (m, z *group.Element) {
	// DST
	encSeedDST := lengthPrefixEncode(dst(dstSeed, o.contextString))

	// build seed
	seed := o.hash.Hash(encGk, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if k != nil {
		return o.computeCompositesFast(k, encSeed, cs, ds)
	}

	return o.computeCompositesClient(encSeed, cs, ds)
}

func (o *oprf) challenge(encPks []byte, a0, a1, a2, a3 *group.Element) *group.Scalar {
	encA0 := lengthPrefixEncode(a0.Encode())
	encA1 := lengthPrefixEncode(a1.Encode())
	encA2 := lengthPrefixEncode(a2.Encode())
	encA3 := lengthPrefixEncode(a3.Encode())
	encDST := []byte(dstChallenge)
	input := concatenate(encPks, encA0, encA1, encA2, encA3, encDST)

	return o.HashToScalar(input)
}

func (o *oprf) generateProof(
	random, k *group.Scalar,
	pk *group.Element,
	cs, ds []*group.Element,
) (proofC, proofS *group.Scalar) {
	encPk := lengthPrefixEncode(pk.Encode())
	a0, a1 := o.computeComposites(k, encPk, cs, ds)

	a2 := o.group.Base().Multiply(random)
	a3 := a0.Copy().Multiply(random)

	proofC = o.challenge(encPk, a0, a1, a2, a3)
	proofS = random.Subtract(proofC.Copy().Multiply(k))

	return proofC, proofS
}

func (o *oprf) verifyProof(ev *evaluation, pk *group.Element, cs, ds []*group.Element) error {
	encGk := lengthPrefixEncode(pk.Encode())
	a0, a1 := o.computeComposites(nil, encGk, cs, ds)

	ap := pk.Copy().Multiply(ev.proofC)
	a2 := o.group.Base().Multiply(ev.proofS).Add(ap)

	bm := a0.Copy().Multiply(ev.proofS)
	bz := a1.Copy().Multiply(ev.proofC)
	a3 := bm.Add(bz)
	expectedC := o.challenge(encGk, a0, a1, a2, a3)

	if !ctEqual(expectedC.Encode(), ev.proofC.Encode()) {
		return errProofFailed
	}

	return nil
}
