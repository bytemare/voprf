// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"errors"

	group "github.com/bytemare/crypto"
)

const (
	dstComposite = "Composite"
	dstChallenge = "Challenge"
)

var errProofFailed = errors.New("invalid proof")

// Verifiable enables VOPRF and POPRF functions over OPRF operations.
type Verifiable struct {
	*Core
	POPRFInfo []byte
	seedDST   []byte
}

// NewVerifiable returns a core configuration for VOPRF and POPRF given the ciphersuite and mode.
// The info argument should only be provided in POPRF mode.
func NewVerifiable(c *Core, info []byte) *Verifiable {
	if len(info) != 0 && c.Mode != POPRF {
		panic("internal error: POPRF info provided but POPRF mode not set")
	}

	ctx := ContextString(c.Mode, CiphersuiteIdentifier[c.Group])

	return &Verifiable{
		Core:      c,
		POPRFInfo: info,
		seedDST:   Dst(dstSeed, ctx),
	}
}

func (v Verifiable) challenge(encPks []byte, a0, a1, a2, a3 *group.Element) *group.Scalar {
	encA0 := lengthPrefixEncode(a0.Encode())
	encA1 := lengthPrefixEncode(a1.Encode())
	encA2 := lengthPrefixEncode(a2.Encode())
	encA3 := lengthPrefixEncode(a3.Encode())
	encDST := []byte(dstChallenge)
	input := concatenate(encPks, encA0, encA1, encA2, encA3, encDST)

	return v.HashToScalar(input)
}

func (v Verifiable) pTag(info []byte) *group.Scalar {
	framedInfo := make([]byte, 0, len(dstInfo)+2+len(info)) // dstInfo + lengthPrefixEncode(info)
	framedInfo = append(framedInfo, dstInfo...)
	framedInfo = append(framedInfo, lengthPrefixEncode(info)...)

	return v.HashToScalar(framedInfo)
}

// TweakPrivateKey tweaks the input scalar for use in the POPRF setting.
func (v Verifiable) TweakPrivateKey(privateKey *group.Scalar) (*group.Scalar, *group.Scalar) {
	context := v.pTag(v.POPRFInfo)
	t := privateKey.Copy().Add(context)
	scalar := t.Copy().Invert()

	if scalar.IsZero() {
		panic(errInvalidPOPRFPrivateKey)
	}

	return scalar, t
}

// TweakPublicKey tweaks the input element for use in the POPRF setting.
func (v Verifiable) TweakPublicKey(pubKey *group.Element) *group.Element {
	m := v.pTag(v.POPRFInfo)

	t := v.Group.Base().Multiply(m).Add(pubKey)
	if t.IsIdentity() {
		panic(errInvalidPOPRFPubKey)
	}

	return t
}

// GenerateProof produces a non-interactive zero-knowledge (NIZK) proof on the evaluated elements.
func (v Verifiable) GenerateProof(
	random, k *group.Scalar,
	pk *group.Element,
	cs, ds []*group.Element,
) (*group.Scalar, *group.Scalar) {
	encPk := lengthPrefixEncode(pk.Encode())
	a0, a1 := v.computeComposites(k, encPk, cs, ds)

	a2 := v.Group.Base().Multiply(random)
	a3 := a0.Copy().Multiply(random)

	proofC := v.challenge(encPk, a0, a1, a2, a3)
	proofS := random.Subtract(proofC.Copy().Multiply(k))

	return proofC, proofS
}

// VerifyProof verifies the non-interactive zero-knowledge (NIZK) proof on the evaluated elements produced by
// GenerateProof.
func (v Verifiable) VerifyProof(proofC, proofS *group.Scalar, pubKey *group.Element, cs, ds []*group.Element) error {
	encGk := lengthPrefixEncode(pubKey.Encode())
	a0, a1 := v.computeComposites(nil, encGk, cs, ds)

	ap := pubKey.Copy().Multiply(proofC)
	a2 := v.Group.Base().Multiply(proofS).Add(ap)

	bm := a0.Copy().Multiply(proofS)
	bz := a1.Copy().Multiply(proofC)
	a3 := bm.Add(bz)
	expectedC := v.challenge(encGk, a0, a1, a2, a3)

	if !ctEqual(expectedC.Encode(), proofC.Encode()) {
		return errProofFailed
	}

	return nil
}

func (v Verifiable) ccScalar(encSeed []byte, index int, ci, di *group.Element) *group.Scalar {
	input := concatenate(encSeed, I2osp2(index),
		lengthPrefixEncode(ci.Encode()),
		lengthPrefixEncode(di.Encode()),
		[]byte(dstComposite))

	return v.HashToScalar(input)
}

func (v Verifiable) computeCompositesFast(
	k *group.Scalar,
	encSeed []byte,
	cs, ds []*group.Element,
) (*group.Element, *group.Element) {
	m := v.Group.NewElement().Identity()

	for i, ci := range cs {
		di := v.ccScalar(encSeed, i, ci, ds[i])
		m = ci.Copy().Multiply(di).Add(m)
	}

	return m, m.Copy().Multiply(k)
}

func (v Verifiable) computeCompositesClient(encSeed []byte, cs, ds []*group.Element) (*group.Element, *group.Element) {
	m := v.Group.NewElement().Identity()
	z := v.Group.NewElement().Identity()

	for i, ci := range cs {
		di := v.ccScalar(encSeed, i, ci, ds[i])
		m = ci.Copy().Multiply(di).Add(m)
		z = ds[i].Copy().Multiply(di).Add(z)
	}

	return m, z
}

func (v Verifiable) computeComposites(
	k *group.Scalar,
	encGk []byte,
	cs, ds []*group.Element,
) (*group.Element, *group.Element) {
	encSeedDST := lengthPrefixEncode(v.seedDST)

	// build seed
	seed := v.Hash.Hash(0, encGk, encSeedDST)
	encSeed := lengthPrefixEncode(seed)

	// This means where calling from the server, and can optimize computation of Z, since Zi = sks * Mi
	if k != nil {
		return v.computeCompositesFast(k, encSeed, cs, ds)
	}

	return v.computeCompositesClient(encSeed, cs, ds)
}
