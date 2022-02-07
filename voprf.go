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

	"github.com/bytemare/crypto/group"
	"github.com/bytemare/crypto/hash"
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
	decaf448Sha512 Ciphersuite = 0x0002

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 Ciphersuite = 0x0003

	// P384Sha384 is the OPRF cipher suite of the NIST P-384 group and SHA-384.
	P384Sha384 Ciphersuite = 0x0004

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512 Ciphersuite = 0x0005

	maxID = 0x0006

	sRistrettoSha512 = "RistrettoSha512"
	sDecaf448Sha512  = "Decaf448Sha512"
	sP256Sha256      = "P256Sha256"
	sP384Sha384      = "P384Sha384"
	sP521Sha512      = "P521Sha512"

	// version is a string explicitly stating the version name.
	version = "VOPRF09-"

	// deriveKeyPairDST is the DST prefix for the DeriveKeyPair function.
	deriveKeyPairDST = "DeriveKeyPair"

	// hash2groupDSTPrefix is the DST prefix to use for HashToGroup operations.
	hash2groupDSTPrefix = "HashToGroup-"

	// hash2scalarDSTPrefix is the DST prefix to use for HashToScalar operations.
	hash2scalarDSTPrefix = "HashToScalar-"
)

var (
	suites      = make([]*oprf, maxID)
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

func (c Ciphersuite) register(g group.Group, h hash.Hashing) {
	o := &oprf{
		id:   c,
		hash: h.Get(),
	}

	suites[c] = o
	groupToOprf[g] = c
	oprfToGroup[c] = g
}

// KeyPair assembles a VOPRF key pair. The SecretKey can be used as the evaluation key for the group identified by ID.
type KeyPair struct {
	ID        Ciphersuite
	PublicKey []byte
	SecretKey []byte
}

// KeyGen returns a fresh KeyPair for the given cipher suite.
func (c Ciphersuite) KeyGen() *KeyPair {
	sk := c.Group().NewScalar().Random()
	pk := c.Group().Base().Mult(sk)

	return &KeyPair{
		ID:        c,
		PublicKey: serializePoint(pk, pointLength(c)),
		SecretKey: serializeScalar(sk, scalarLength(c)),
	}
}

type oprf struct {
	id            Ciphersuite
	mode          Mode
	group         group.Group
	hash          *hash.Hash
	contextString []byte
}

func contextString(mode Mode, id Ciphersuite) []byte {
	v := []byte(version)
	ctx := make([]byte, 0, len(v)+1+2)
	ctx = append(ctx, v...)
	ctx = append(ctx, byte(mode))
	ctx = append(ctx, i2osp2(int(id))...)

	return ctx
}

func (o *oprf) dst(prefix string) []byte {
	p := []byte(prefix)
	dst := make([]byte, 0, len(p)+len(o.contextString))
	dst = append(dst, p...)
	dst = append(dst, o.contextString...)

	return dst
}

func (o *oprf) pTag(info []byte) *group.Scalar {
	framedInfo := make([]byte, 0, len(dstInfo)+2+len(info)) // dstContext + s.contextString + lengthPrefixEncode(info)
	framedInfo = append(framedInfo, dstInfo...)
	framedInfo = append(framedInfo, lengthPrefixEncode(info)...)

	return o.HashToScalar(framedInfo)
}

func (o *oprf) new(mode Mode) *oprf {
	o.mode = mode
	o.contextString = contextString(mode, o.id)
	o.group = oprfToGroup[o.id]

	return o
}

// DeriveKeyPair deterministically generates a private and public key pair from input seed.
func (o *oprf) DeriveKeyPair(seed, info []byte) (*group.Scalar, *group.Point) {
	dst := concatenate([]byte(deriveKeyPairDST), o.contextString)
	deriveInput := concatenate(seed, lengthPrefixEncode(info))

	var counter uint8
	var s *group.Scalar

	for s == nil || s.IsZero() {
		if counter > 255 {
			panic("")
		}
		s = o.group.HashToScalar(concatenate(deriveInput, []byte{byte(counter)}), dst)
		counter++
	}

	return s, o.group.Base().Mult(s)
}

// HashToGroup maps the input data to an element of the group.
func (o *oprf) HashToGroup(data []byte) *group.Point {
	return o.group.HashToGroup(data, o.dst(hash2groupDSTPrefix))
}

// HashToScalar maps the input data to a scalar.
func (o *oprf) HashToScalar(data []byte) *group.Scalar {
	return o.group.HashToScalar(data, o.dst(hash2scalarDSTPrefix))
}

func (o *oprf) DeserializeElement(data []byte) (*group.Point, error) {
	p, err := o.group.NewElement().Decode(data)
	if err != nil {
		return nil, fmt.Errorf("could not decode element : %w", err)
	}

	if p.IsIdentity() {
		return nil, errDecodeIdentity
	}

	return p, nil
}

func (o *oprf) DeserializeScalar(data []byte) (*group.Scalar, error) {
	s, err := o.group.NewScalar().Decode(data)
	if err != nil {
		return nil, fmt.Errorf("could not decode scalar : %w", err)
	}

	return s, nil
}

func (c Ciphersuite) client(mode Mode) *Client {
	return &Client{oprf: suites[c].new(mode)}
}

func (c *Client) setServerPubkey(serverPublicKey []byte) error {
	pub, err := c.group.NewElement().Decode(serverPublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	c.serverPublicKey = pub

	return nil
}

// OPRFClient returns an OPRF client.
func (c Ciphersuite) OPRFClient() *Client {
	return c.client(OPRF)
}

// VOPRFClient returns a VOPRF client.
func (c Ciphersuite) VOPRFClient(serverPublicKey []byte) (*Client, error) {
	client := c.client(VOPRF)
	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

// POPRFClient returns a POPRF client.
func (c Ciphersuite) POPRFClient(serverPublicKey []byte) (*Client, error) {
	client := c.client(POPRF)
	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

func (c Ciphersuite) server(mode Mode, privateKey []byte) (*Server, error) {
	s := &Server{
		oprf: suites[c].new(mode),
	}

	if privateKey != nil {
		sk, err := s.group.NewScalar().Decode(privateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}

		s.privateKey = sk
		s.publicKey = s.group.Base().Mult(sk)
	} else {
		s.KeyGen()
	}

	return s, nil
}

// OPRFServer returns an OPRF server instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) OPRFServer(privateKey []byte) (*Server, error) {
	return c.server(OPRF, privateKey)
}

// VOPRFServer returns a VOPRF server/prover instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) VOPRFServer(privateKey []byte) (*Server, error) {
	return c.server(VOPRF, privateKey)
}

// POPRFServer returns a POPRF server/prover instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) POPRFServer(privateKey []byte) (*Server, error) {
	return c.server(POPRF, privateKey)
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

func init() {
	RistrettoSha512.register(group.Ristretto255Sha512, hash.SHA512)
	// Decaf448Sha512.register(group.Curve448Sha512, hash.SHA512)
	P256Sha256.register(group.P256Sha256, hash.SHA256)
	P384Sha384.register(group.P384Sha384, hash.SHA384)
	P521Sha512.register(group.P521Sha512, hash.SHA512)
}
