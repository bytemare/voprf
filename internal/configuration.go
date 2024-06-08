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

	group "github.com/bytemare/crypto"
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
	// CiphersuiteIdentifier maps a group to its [RFC9497](https://datatracker.ietf.org/doc/rfc9497) compliant
	// identifier.
	CiphersuiteIdentifier = map[group.Group]string{
		group.Ristretto255Sha512: "ristretto255-SHA512",
		group.P256Sha256:         "P256-SHA256",
		group.P384Sha384:         "P384-SHA384",
		group.P521Sha512:         "P521-SHA512",
		group.Secp256k1:          "secp256k1-SHA256",
	}

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

// A Core holds the cryptographic configuration and methods used for xOPRF operations.
type Core struct {
	Hash      hash.Hasher
	dstH2gDST []byte
	dstH2sDST []byte
	Group     group.Group
	Mode      Mode
}

// ContextString builds the xOPRF constant string used for domain separation tags.
func ContextString(mode Mode, name string) []byte {
	return []byte(contextStringPrefix + string(mode) + "-" + name)
}

func makeCore(g group.Group, h hash.Hash, mode Mode) *Core {
	ctx := ContextString(mode, CiphersuiteIdentifier[g])

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
func LoadConfiguration(g group.Group, mode Mode) *Core {
	switch g {
	case group.Ristretto255Sha512:
		return makeCore(group.Ristretto255Sha512, hash.SHA512, mode)
	case group.P256Sha256:
		return makeCore(group.P256Sha256, hash.SHA256, mode)
	case group.P384Sha384:
		return makeCore(group.P384Sha384, hash.SHA384, mode)
	case group.P521Sha512:
		return makeCore(group.P521Sha512, hash.SHA512, mode)
	case group.Secp256k1:
		return makeCore(group.Secp256k1, hash.SHA256, mode)
	default:
		panic(fmt.Sprintf("invalid OPRF dependency - Group: %v", g))
	}
}

// DeriveKeyPair derives a private-public key pair given a secret seed and instance specific info.
func (c Core) DeriveKeyPair(seed, info []byte) (*group.Scalar, *group.Element) {
	dst := concatenate([]byte(deriveKeyPairDST), ContextString(c.Mode, CiphersuiteIdentifier[c.Group]))
	deriveInput := concatenate(seed, lengthPrefixEncode(info))

	var counter uint8
	var sk *group.Scalar

	for sk == nil || sk.IsZero() {
		if counter > 255 {
			panic("impossible to generate non-zero scalar")
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
		h = c.Hash.Hash(0, encInput, encInfo, encElement, encDST)
	} else { // OPRF and VOPRF
		h = c.Hash.Hash(0, encInput, encElement, encDST)
	}

	return h
}

// HashToScalar maps the input data to a scalar.
func (c Core) HashToScalar(data []byte) *group.Scalar {
	return c.Group.HashToScalar(data, c.dstH2sDST)
}

// HashToGroup maps the input data to an element of the Group.
func (c Core) HashToGroup(data []byte) *group.Element {
	return c.Group.HashToGroup(data, c.dstH2gDST)
}
