// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package voprf implements RFC9497 and provides abstracted access to Oblivious Pseudorandom Functions (OPRF) and
// Threshold Oblivious Pseudorandom Functions (TOPRF) using Elliptic Curve Prime Order Groups (EC-OPRF).
// For VOPRF and POPRF use the github.com/bytemare/oprf/voprf package.
package voprf

import group "github.com/bytemare/crypto"

// DecodeElement decodes e to an element in the group.
func (c Ciphersuite) DecodeElement(e []byte) (*group.Element, error) {
	result := group.Group(c).NewElement()

	if err := result.Decode(e); err != nil {
		return nil, err
	}

	return result, nil
}

// DecodeScalar decodes s to a scalar in the group.
func (c Ciphersuite) DecodeScalar(s []byte) (*group.Scalar, error) {
	result := group.Group(c).NewScalar()

	if err := result.Decode(s); err != nil {
		return nil, err
	}

	return result, nil
}
