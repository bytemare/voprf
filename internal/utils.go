// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"crypto/subtle"
	"encoding/binary"

	group "github.com/bytemare/crypto"
)

// KeyPair assembles a VOPRF key pair. The SecretKey can be used as the evaluation key for
// the Group identified by Ciphersuite.
type KeyPair struct {
	PublicKey   *group.Element
	SecretKey   *group.Scalar
	Ciphersuite group.Group
}

// I2osp2 encodes the integer to a 2-byte byte string.
func I2osp2(value int) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(value))

	return out
}

func lengthPrefixEncode(input []byte) []byte {
	return append(I2osp2(len(input)), input...)
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
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

// Dst returns the domain separation tag, i.e. the concatenation of the input.
func Dst(prefix string, contextString []byte) []byte {
	return []byte(prefix + string(contextString))
}
