// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"crypto/subtle"
	"encoding/binary"

	group "github.com/bytemare/crypto"
)

const (
	dstComposite = "Composite"
	dstChallenge = "Challenge"
	dstFinalize  = "Finalize"
	dstSeed      = "Seed-"
	dstInfo      = "Info"
)

func i2osp2(value int) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(value))

	return out
}

func lengthPrefixEncode(input []byte) []byte {
	return append(i2osp2(len(input)), input...)
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

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
	encSeedDST := lengthPrefixEncode(o.dst(dstSeed))

	// build seed
	seed := o.hash.Hash(encGk, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if k != nil {
		return o.computeCompositesFast(k, encSeed, cs, ds)
	}

	return o.computeCompositesClient(encSeed, cs, ds)
}

func concatenate(input ...[]byte) []byte {
	if len(input) == 1 {
		if len(input[0]) == 0 {
			return nil
		}

		return input[0]
	}

	length := 0
	for _, in := range input {
		length += len(in)
	}

	buf := make([]byte, 0, length)

	for _, in := range input {
		buf = append(buf, in...)
	}

	return buf
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
