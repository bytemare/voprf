// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf_test

import (
	"encoding/binary"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/voprf"
)

const (
	version             = "OPRFV1"
	deriveKeyPairDST    = "DeriveKeyPair"
	hash2groupDSTPrefix = "HashToGroup-"
)

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

func dst(prefix string, contextString []byte) []byte {
	p := []byte(prefix)
	t := make([]byte, 0, len(p)+len(contextString))
	t = append(t, p...)
	t = append(t, contextString...)

	return t
}

func i2osp2(value int) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(value))

	return out
}

func lengthPrefixEncode(input []byte) []byte {
	return append(i2osp2(len(input)), input...)
}

func contextString(mode voprf.Mode, id voprf.Identifier) []byte {
	ctx := make([]byte, 0, len(version)+3+len(id.String()))
	ctx = append(ctx, version...)
	ctx = append(ctx, "-"...)
	ctx = append(ctx, byte(mode))
	ctx = append(ctx, "-"...)
	ctx = append(ctx, id.String()...)

	return ctx
}

func deriveKeyPair(seed, info []byte, mode voprf.Mode, id voprf.Identifier) (*group.Scalar, *group.Element) {
	dst := concatenate([]byte(deriveKeyPairDST), contextString(mode, id))
	deriveInput := concatenate(seed, lengthPrefixEncode(info))

	var counter uint8
	var s *group.Scalar

	for s == nil || s.IsZero() {
		if counter > 255 {
			panic("impossible to generate non-zero scalar")
		}

		s = id.Group().HashToScalar(concatenate(deriveInput, []byte{counter}), dst)
		counter++
	}

	return s, id.Group().Base().Multiply(s)
}
