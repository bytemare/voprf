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

	"github.com/bytemare/crypto/group"
)

const (
	dstComposite = "Composite"
	dstChallenge = "Challenge"
	dstFinalize  = "Finalize"
	dstSeed      = "Seed-"
	dstContext   = "Info"

	p256PointLength  = 33
	p256ScalarLength = 32
	p384PointLength  = 49
	p384ScalarLength = 48
	p521PointLength  = 67
	p521ScalarLength = 66
)

func scalarLength(c Ciphersuite) int {
	switch c {
	case RistrettoSha512:
		return 32
	// case Decaf448Sha512:
	//	return 56
	case P256Sha256:
		return p256ScalarLength
	case P384Sha384:
		return p384ScalarLength
	case P521Sha512:
		return p521ScalarLength
	default:
		panic("invalid suite")
	}
}

func pointLength(c Ciphersuite) int {
	switch c {
	case RistrettoSha512:
		return 32
	// case Decaf448Sha512:
	//	return 56
	case P256Sha256:
		return p256PointLength
	case P384Sha384:
		return p384PointLength
	case P521Sha512:
		return p521PointLength
	default:
		panic("invalid suite")
	}
}

func serializeScalar(s *group.Scalar, length int) []byte {
	e := s.Bytes()
	for len(e) < length {
		e = append([]byte{0x00}, e...)
	}

	return e
}

func serializePoint(e *group.Point, length int) []byte {
	p := e.Bytes()

	for len(p) < length {
		p = append([]byte{0x00}, p...)
	}

	return p
}

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

func (o *oprf) ccScalar(encSeed []byte, index int, ci, di *group.Point) *group.Scalar {
	input := concatenate(encSeed, i2osp2(index),
		lengthPrefixEncode(serializePoint(ci, pointLength(o.id))),
		lengthPrefixEncode(serializePoint(di, pointLength(o.id))),
		[]byte(dstComposite))

	return o.HashToScalar(input)
}

func (o *oprf) computeCompositesFast(k *group.Scalar, encSeed []byte, cs, ds []*group.Point) (m, z *group.Point) {
	m = o.group.Identity()

	for i, ci := range cs {
		di := o.ccScalar(encSeed, i, ci, ds[i])
		m = ci.Mult(di).Add(m)
	}

	return m, m.Mult(k)
}

func (o *oprf) computeCompositesClient(encSeed []byte, cs, ds []*group.Point) (m, z *group.Point) {
	m = o.group.Identity()
	z = o.group.Identity()

	for i, ci := range cs {
		di := o.ccScalar(encSeed, i, ci, ds[i])
		m = ci.Mult(di).Add(m)
		z = ds[i].Mult(di).Add(z)
	}

	return m, z
}

func (o *oprf) computeComposites(k *group.Scalar, encGk []byte, cs, ds []*group.Point) (m, z *group.Point) {
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

func (o *oprf) challenge(encPks []byte, a0, a1, a2, a3 *group.Point) *group.Scalar {
	encA0 := lengthPrefixEncode(serializePoint(a0, pointLength(o.id)))
	encA1 := lengthPrefixEncode(serializePoint(a1, pointLength(o.id)))
	encA2 := lengthPrefixEncode(serializePoint(a2, pointLength(o.id)))
	encA3 := lengthPrefixEncode(serializePoint(a3, pointLength(o.id)))
	encDST := []byte(dstChallenge)
	input := concatenate(encPks, encA0, encA1, encA2, encA3, encDST)

	return o.HashToScalar(input)
}
