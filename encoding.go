// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import "github.com/bytemare/ecc"

// DecodeElement decodes e to an element in the group.
func (c Ciphersuite) DecodeElement(e []byte) (*ecc.Element, error) {
	result := ecc.Group(c).NewElement()

	if err := result.Decode(e); err != nil {
		return nil, err
	}

	return result, nil
}

// DecodeScalar decodes s to a scalar in the group.
func (c Ciphersuite) DecodeScalar(s []byte) (*ecc.Scalar, error) {
	result := ecc.Group(c).NewScalar()

	if err := result.Decode(s); err != nil {
		return nil, err
	}

	return result, nil
}
