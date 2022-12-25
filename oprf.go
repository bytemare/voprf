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

// Ciphersuite identifies the OPRF compatible cipher suite to be used.
type Ciphersuite byte

const (
	// RistrettoSha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	RistrettoSha512 Ciphersuite = 0x0001

	// Decaf448Sha512 is the OPRF cipher suite of the Decaf448 group and SHA-512.
	// decaf448Sha512 Ciphersuite = 0x0002.

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 Ciphersuite = 0x0003

	// P384Sha384 is the OPRF cipher suite of the NIST P-384 group and SHA-384.
	P384Sha384 Ciphersuite = 0x0004

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512 Ciphersuite = 0x0005

	maxID = 0x0006

	sRistrettoSha512 = "ristretto255-SHA512"
	// sDecaf448Sha512  = "decaf448-SHAKE256".
	sP256Sha256 = "P256-SHA256"
	sP384Sha384 = "P384-SHA384"
	sP521Sha512 = "P521-SHA512"

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
	suites      = make([]*oprf, maxID)
	suitesID    = make(map[string]Ciphersuite)
	groupToOprf = make(map[group.Group]Ciphersuite)
	oprfToGroup = make(map[Ciphersuite]group.Group)
)

// Group returns the group identifier used in the cipher suite.
func (c Ciphersuite) Group() group.Group {
	return oprfToGroup[c]
}

// Hash returns the hash function identifier used in the cipher suite.
func (c Ciphersuite) Hash() hash.Hashing {
	return suites[c].hash.Hashing
}

// FromGroup returns a (V)OPRF Ciphersuite identifier given a Group Identifier.
func FromGroup(id group.Group) (Ciphersuite, error) {
	c, ok := groupToOprf[id]
	if !ok {
		return 0, errParamInvalidID
	}

	return c, nil
}

// KeyGen returns a fresh KeyPair for the given cipher suite.
func (c Ciphersuite) KeyGen() *KeyPair {
	sk := c.Group().NewScalar().Random()
	pk := c.Group().Base().Multiply(sk)

	return &KeyPair{
		ID:        c,
		PublicKey: pk.Encode(),
		SecretKey: sk.Encode(),
	}
}

// Client returns a (P|V)OPRF client. For the OPRF mode, serverPublicKey should be nil, and non-nil otherwise.
func (c Ciphersuite) Client(mode Mode, serverPublicKey []byte) (*Client, error) {
	if mode != OPRF && mode != VOPRF && mode != POPRF {
		return nil, errParamInvalidMode
	}

	if (mode == VOPRF || mode == POPRF) && serverPublicKey == nil {
		return nil, errParamNoPubKey
	}

	client := c.client(mode)

	if err := client.setServerPublicKey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

// Server returns a (P|V)OPRF server instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) Server(mode Mode, privateKey []byte) (*Server, error) {
	if mode != OPRF && mode != VOPRF && mode != POPRF {
		return nil, errParamInvalidMode
	}

	return c.server(mode, privateKey)
}

type oprf struct {
	hash          *hash.Hash
	contextString []byte
	id            Ciphersuite
	mode          Mode
	group         group.Group
}

func contextString(mode Mode, id Ciphersuite) []byte {
	ctx := make([]byte, 0, len(version)+3+len(id.String()))
	ctx = append(ctx, version...)
	ctx = append(ctx, "-"...)
	ctx = append(ctx, byte(mode))
	ctx = append(ctx, "-"...)
	ctx = append(ctx, id.String()...)

	return ctx
}

func (o *oprf) new(mode Mode) *oprf {
	o.mode = mode
	o.contextString = contextString(mode, o.id)
	o.group = oprfToGroup[o.id]

	return o
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

func (c Ciphersuite) client(mode Mode) *Client {
	return &Client{
		tweakedKey:      nil,
		serverPublicKey: nil,
		oprf:            suites[c].new(mode),
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

func (c Ciphersuite) server(mode Mode, privateKey []byte) (*Server, error) {
	s := &Server{
		privateKey: nil,
		publicKey:  nil,
		oprf:       suites[c].new(mode),
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

// String implements the Stringer() interface for the Ciphersuite.
func (c Ciphersuite) String() string {
	switch c {
	case RistrettoSha512:
		return sRistrettoSha512
	// case Decaf448Sha512:
	//	return sDecaf448Sha512
	case P256Sha256:
		return sP256Sha256
	case P384Sha384:
		return sP384Sha384
	case P521Sha512:
		return sP521Sha512
	default:
		return ""
	}
}

func (c Ciphersuite) register(g group.Group, h hash.Hashing, id string) {
	o := &oprf{
		hash:          h.Get(),
		contextString: nil,
		id:            c,
		mode:          0,
		group:         0,
	}

	suites[c] = o
	suitesID[id] = c
	groupToOprf[g] = c
	oprfToGroup[c] = g
}

func init() {
	RistrettoSha512.register(group.Ristretto255Sha512, hash.SHA512, sRistrettoSha512)
	// Decaf448Sha512.register(group.Curve448Sha512, hash.SHA512).
	P256Sha256.register(group.P256Sha256, hash.SHA256, sP256Sha256)
	P384Sha384.register(group.P384Sha384, hash.SHA384, sP384Sha384)
	P521Sha512.register(group.P521Sha512, hash.SHA512, sP521Sha512)
}
