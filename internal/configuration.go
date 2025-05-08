// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal handles all core xOPRF functionalities.
package internal

import (
	"errors"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"
)

// Mode distinguishes execution between the OPRF base, VOPRF, and POPRF modes.
type Mode byte

const (
	// OPRF identifies the base mode.
	OPRF Mode = iota

	// VOPRF identifies the verifiable mode.
	VOPRF

	// POPRF identifies the partially-oblivious mode.
	POPRF
)

const (
	// Version is a string explicitly stating the Version name.
	Version = "OPRFV1"

	hash2groupDSTPrefix  = "HashToGroup-"
	hash2scalarDSTPrefix = "HashToScalar-"
	dstSeed              = "Seed-"
	contextStringPrefix  = Version + "-"
	dstFinalize          = "Finalize"
	dstInfo              = "Info"
	deriveKeyPairDST     = "DeriveKeyPair"
)

var (
	errInvalidInput = errors.New(
		"invalid input - OPRF input deterministically maps to the group identity element",
	)
	errInvalidPOPRFPrivateKey = errors.New(
		"invalid input - POPRF private key tweaking yields the zero scalar",
	)
	errInvalidPOPRFPubKey = errors.New(
		"invalid input - POPRF public key tweaking yields the group identity element",
	)
)

// CiphersuiteIdentifier maps a group to its [RFC9497](https://datatracker.ietf.org/doc/rfc9497) compliant
// identifier.
func CiphersuiteIdentifier(g ecc.Group) string {
	return map[ecc.Group]string{
		ecc.Ristretto255Sha512: "ristretto255-SHA512",
		ecc.P256Sha256:         "P256-SHA256",
		ecc.P384Sha384:         "P384-SHA384",
		ecc.P521Sha512:         "P521-SHA512",
		ecc.Secp256k1Sha256:    "secp256k1-SHA256",
	}[g]
}

// A Core holds the cryptographic configuration and methods used for xOPRF operations.
type Core struct {
	Hash      hash.Hasher
	dstH2gDST []byte
	dstH2sDST []byte
	Group     ecc.Group
	Mode      Mode
}

// ContextString builds the xOPRF constant string used for domain separation tags.
func ContextString(mode Mode, name string) []byte {
	return []byte(contextStringPrefix + string(mode) + "-" + name)
}

func makeCore(g ecc.Group, h hash.Hash, mode Mode) *Core {
	ctx := ContextString(mode, CiphersuiteIdentifier(g))

	return &Core{
		Group:     g,
		Hash:      h.New(),
		Mode:      mode,
		dstH2gDST: Dst(hash2groupDSTPrefix, ctx),
		dstH2sDST: Dst(hash2scalarDSTPrefix, ctx),
	}
}

// LoadConfiguration returns a core configuration given the ciphersuite and mode. The info argument should only be
// provided in POPRF mode.
func LoadConfiguration(g ecc.Group, mode Mode) *Core {
	switch g {
	case ecc.Ristretto255Sha512:
		return makeCore(ecc.Ristretto255Sha512, hash.SHA512, mode)
	case ecc.P256Sha256:
		return makeCore(ecc.P256Sha256, hash.SHA256, mode)
	case ecc.P384Sha384:
		return makeCore(ecc.P384Sha384, hash.SHA384, mode)
	case ecc.P521Sha512:
		return makeCore(ecc.P521Sha512, hash.SHA512, mode)
	case ecc.Secp256k1Sha256:
		return makeCore(ecc.Secp256k1Sha256, hash.SHA256, mode)
	default:
		panic(fmt.Sprintf("invalid OPRF dependency - Group: %v", g))
	}
}

// DeriveKeyPair derives a private-public key pair given a secret seed and instance specific info.
func (c Core) DeriveKeyPair(seed, info []byte) (*ecc.Scalar, *ecc.Element) {
	dst := concatenate([]byte(deriveKeyPairDST), ContextString(c.Mode, CiphersuiteIdentifier(c.Group)))
	deriveInput := concatenate(seed, lengthPrefixEncode(info))

	var (
		counter uint8 // 256 tries at maximum
		sk      *ecc.Scalar
	)

	for sk == nil || sk.IsZero() {
		if counter == 255 {
			panic("failed to generate non-zero scalar 256 times")
		}

		sk = c.Group.HashToScalar(concatenate(deriveInput, []byte{counter}), dst)
		counter++
	}

	return sk, c.Group.Base().Multiply(sk)
}

// HashTranscript hashes a xOPRF run's transcript (without the blind) to produce the protocol's output.
func (c Core) HashTranscript(input, unblinded, poprfInfo []byte) []byte {
	encInput := lengthPrefixEncode(input)
	encElement := lengthPrefixEncode(unblinded)
	encDST := []byte(dstFinalize)

	var h []byte

	if len(poprfInfo) != 0 { // POPRF
		encInfo := lengthPrefixEncode(poprfInfo)
		h = c.Hash.Hash(encInput, encInfo, encElement, encDST)
	} else { // OPRF and VOPRF
		h = c.Hash.Hash(encInput, encElement, encDST)
	}

	return h
}

// HashToScalar maps the input data to a scalar.
func (c Core) HashToScalar(data []byte) *ecc.Scalar {
	return c.Group.HashToScalar(data, c.dstH2sDST)
}

// HashToGroup maps the input data to an element of the Group.
func (c Core) HashToGroup(data []byte) *ecc.Element {
	return c.Group.HashToGroup(data, c.dstH2gDST)
}
