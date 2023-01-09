// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package voprf

import (
	"fmt"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
)

// Mode distinguishes between the OPRF base mode and the VOPRF mode.
type Mode byte

const (
	// OPRF identifies the base mode.
	OPRF Mode = iota

	// VOPRF identifies the verifiable mode.
	VOPRF

	// POPRF identifies the partially-oblivious mode.
	POPRF
)

// Identifier of the OPRF compatible cipher suite to be used.
type Identifier string

const (
	// Ristretto255Sha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	Ristretto255Sha512 Identifier = "ristretto255-SHA512"

	// Decaf448Sha512 is the OPRF cipher suite of the Decaf448 group and SHA-512.
	// decaf448Sha512 Identifier = "decaf448-SHAKE256".

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 Identifier = "P256-SHA256"

	// P384Sha384 is the OPRF cipher suite of the NIST P-384 group and SHA-384.
	P384Sha384 Identifier = "P384-SHA384"

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512 Identifier = "P521-SHA512"

	nbIDs = 4

	// version is a string explicitly stating the version name.
	version = "OPRFV1"

	// deriveKeyPairDST is the DST prefix for the DeriveKeyPair function.
	deriveKeyPairDST = "DeriveKeyPair"

	// hash2groupDSTPrefix is the DST prefix to use for HashToGroup operations.
	hash2groupDSTPrefix = "HashToGroup-"

	// hash2scalarDSTPrefix is the DST prefix to use for HashToScalar operations.
	hash2scalarDSTPrefix = "HashToScalar-"
)

var (
	groups = make(map[Identifier]group.Group, nbIDs)
	hashes = make(map[Identifier]hash.Hashing, nbIDs)
)

func (i Identifier) new(mode Mode) *oprf {
	return &oprf{
		hash:          hashes[i].Get(),
		contextString: contextString(mode, i),
		id:            i,
		mode:          mode,
		group:         groups[i],
	}
}

// Available returns whether the Identifier is registered and available for usage.
func (i Identifier) Available() bool {
	// Check for invalid identifiers
	switch i {
	case Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512:
		break
	default:
		return false
	}

	// Check for unregistered groups and hashes
	if _, ok := groups[i]; !ok {
		return false
	}

	if _, ok := hashes[i]; !ok {
		return false
	}

	return true
}

// Group returns the group identifier used in the cipher suite.
func (i Identifier) Group() group.Group {
	return groups[i]
}

// Hash returns the hash function identifier used in the cipher suite.
func (i Identifier) Hash() hash.Hashing {
	return hashes[i]
}

// FromGroup returns a (V)OPRF Identifier given a Group Identifier.
func FromGroup(g group.Group) (Identifier, error) {
	for k, v := range groups {
		if v == g {
			return k, nil
		}
	}

	return "", errParamInvalidID
}

// KeyGen returns a fresh KeyPair for the given cipher suite.
func (i Identifier) KeyGen() *KeyPair {
	sk := i.Group().NewScalar().Random()
	pk := i.Group().Base().Multiply(sk)

	return &KeyPair{
		ID:        i,
		PublicKey: pk.Encode(),
		SecretKey: sk.Encode(),
	}
}

// Client returns a (P|V)OPRF client. For the OPRF mode, serverPublicKey should be nil, and non-nil otherwise.
func (i Identifier) Client(mode Mode, serverPublicKey []byte) (*Client, error) {
	if mode != OPRF && mode != VOPRF && mode != POPRF {
		return nil, errParamInvalidMode
	}

	client := i.client(mode)

	if mode == VOPRF || mode == POPRF {
		if serverPublicKey == nil {
			return nil, errParamNoPubKey
		}

		if err := client.setServerPublicKey(serverPublicKey); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// Server returns a (P|V)OPRF server instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (i Identifier) Server(mode Mode, privateKey []byte) (*Server, error) {
	if mode != OPRF && mode != VOPRF && mode != POPRF {
		return nil, errParamInvalidMode
	}

	return i.server(mode, privateKey)
}

type oprf struct {
	hash          *hash.Hash
	id            Identifier
	contextString []byte
	mode          Mode
	group         group.Group
}

func contextString(mode Mode, id Identifier) []byte {
	ctx := make([]byte, 0, len(version)+3+len(id.String()))
	ctx = append(ctx, version...)
	ctx = append(ctx, "-"...)
	ctx = append(ctx, byte(mode))
	ctx = append(ctx, "-"...)
	ctx = append(ctx, id.String()...)

	return ctx
}

// DeriveKeyPair deterministically generates a private and public key pair from input seed.
func (o *oprf) DeriveKeyPair(seed, info []byte) (*group.Scalar, *group.Element) {
	dst := concatenate([]byte(deriveKeyPairDST), o.contextString)
	deriveInput := concatenate(seed, lengthPrefixEncode(info))

	var counter uint8
	var s *group.Scalar

	for s == nil || s.IsZero() {
		if counter > 255 {
			panic("impossible to generate non-zero scalar")
		}

		s = o.group.HashToScalar(concatenate(deriveInput, []byte{counter}), dst)
		counter++
	}

	return s, o.group.Base().Multiply(s)
}

// HashToGroup maps the input data to an element of the group.
func (o *oprf) HashToGroup(data []byte) *group.Element {
	return o.group.HashToGroup(data, dst(hash2groupDSTPrefix, o.contextString))
}

// HashToScalar maps the input data to a scalar.
func (o *oprf) HashToScalar(data []byte) *group.Scalar {
	return o.group.HashToScalar(data, dst(hash2scalarDSTPrefix, o.contextString))
}

func (i Identifier) client(mode Mode) *Client {
	return &Client{
		tweakedKey:      nil,
		serverPublicKey: nil,
		oprf:            i.new(mode),
		input:           nil,
		blind:           nil,
		blindedElement:  nil,
	}
}

func (c *Client) setServerPublicKey(serverPublicKey []byte) error {
	if serverPublicKey == nil { // OPRF
		return nil
	}

	pub := c.group.NewElement()
	if err := pub.Decode(serverPublicKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	c.serverPublicKey = pub

	return nil
}

func (i Identifier) server(mode Mode, privateKey []byte) (*Server, error) {
	s := &Server{
		privateKey: nil,
		publicKey:  nil,
		oprf:       i.new(mode),
		nonceR:     nil,
	}

	if privateKey == nil {
		s.KeyGen()
	} else {
		sk := s.group.NewScalar()
		if err := sk.Decode(privateKey); err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}

		s.privateKey = sk
		s.publicKey = s.group.Base().Multiply(sk)
	}

	return s, nil
}

func (o *oprf) pTag(info []byte) *group.Scalar {
	framedInfo := make([]byte, 0, len(dstInfo)+2+len(info)) // dstContext + s.contextString + lengthPrefixEncode(info)
	framedInfo = append(framedInfo, dstInfo...)
	framedInfo = append(framedInfo, lengthPrefixEncode(info)...)

	return o.HashToScalar(framedInfo)
}

func (o *oprf) hashTranscript(input, info, unblinded []byte) []byte {
	encInput := lengthPrefixEncode(input)
	encElement := lengthPrefixEncode(unblinded)
	encDST := []byte(dstFinalize)

	var h []byte

	if info == nil { // OPRF and VOPRF
		h = o.hash.Hash(encInput, encElement, encDST)
	} else { // POPRF
		encInfo := lengthPrefixEncode(info)
		h = o.hash.Hash(encInput, encInfo, encElement, encDST)
	}

	return h
}

// String implements the Stringer() interface for the Identifier.
func (i Identifier) String() string {
	return string(i)
}

func (i Identifier) register(g group.Group, h hash.Hashing) {
	if g.Available() && h.Available() {
		groups[i] = g
		hashes[i] = h
	} else {
		panic(fmt.Sprintf("OPRF dependencies not available - Group: %v, Hash: %v", g.Available(), h.Available()))
	}
}

func init() {
	Ristretto255Sha512.register(group.Ristretto255Sha512, hash.SHA512)
	// Decaf448Sha512.register(group.Curve448Sha512, hash.SHA512).
	P256Sha256.register(group.P256Sha256, hash.SHA256)
	P384Sha384.register(group.P384Sha384, hash.SHA384)
	P521Sha512.register(group.P521Sha512, hash.SHA512)
}
