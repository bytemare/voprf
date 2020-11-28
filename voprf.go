package voprf

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup"
	"github.com/bytemare/cryptotools/hashtogroup/group"
)

// Mode distinguishes between the OPRF base mode and the Verifiable mode.
type Mode byte

const (
	// Base identifies the OPRF non-verifiable, base mode.
	Base Mode = iota

	// Verifiable identifies the OPRF verifiable mode.
	Verifiable
)

// Blinding identifies whether to use multiplicative blinding (VBB) or additive blinding (FBB).
type Blinding byte

const (
	// Multiplicative blinding uses an ephemeral scalar to blind the directly blind the input
	// through scalar multiplication in the group.
	Multiplicative Blinding = iota + 1

	// Additive blinding blinds an element with a fixed based exponentiation,
	// which is more efficient on protocol execution.
	Additive
)

// Ciphersuite identifies the OPRF compatible cipher suite to be used.
type Ciphersuite byte

const (
	// RistrettoSha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	RistrettoSha512 Ciphersuite = iota + 1

	// Decaf448Sha512 is the OPRF cipher suite of the Decaf448 group and SHA2-512.
	Decaf448Sha512

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA2-256.
	P256Sha256

	// P384Sha512 is the OPRF cipher suite of the NIST P-384 group and SHA2-512.
	P384Sha512

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA2-512.
	P521Sha512

	maxID

	// protocol is a string explicitly stating the protocol name.
	protocol = "VOPRF06"

	// hash2groupDSTPrefix is the DST prefix to use for HashToGroup operations.
	hash2groupDSTPrefix = protocol + "-HashToGroup-"
)

var (
	suites    = make([]*oprf, maxID)
	h2gToOprf = make(map[hashtogroup.Ciphersuite]Ciphersuite)
	oprfToh2g = make(map[Ciphersuite]hashtogroup.Ciphersuite)
)

func (c Ciphersuite) register(g hashtogroup.Ciphersuite, h hash.Identifier) {
	o := &oprf{
		id:   c,
		hash: h.Get(),
	}

	suites[c] = o
	h2gToOprf[g] = c
	oprfToh2g[c] = g
}

func preprocess(g group.Group, blind group.Scalar, pubKey []byte) (*PreprocessedBlind, error) {
	pub, err := g.NewElement().Decode(pubKey)
	if err != nil {
		return nil, err
	}

	p := &ppb{
		blindedGenerator: g.Base().Mult(blind),
		blindedPubKey:    pub.Mult(blind),
	}

	return p.serialize(), nil
}

// Preprocess generates a new random blind in the given group, and returns blinding values given the server's public key.
func (c Ciphersuite) Preprocess(serverPublicKey []byte) (*PreprocessedBlind, error) {
	if serverPublicKey == nil {
		return nil, errParamPPNilPubKey
	}

	g := suites[c].new(Base, Additive).group
	r := g.NewScalar().Random()

	return preprocess(g, r, serverPublicKey)
}

// PreprocessWithBlind returns blinding values in the group given the blind and server's public key.
func (c Ciphersuite) PreprocessWithBlind(blind, serverPublicKey []byte) (*PreprocessedBlind, error) {
	if blind == nil {
		return nil, errParamPPNilBlind
	}

	if serverPublicKey == nil {
		return nil, errParamPPNilPubKey
	}

	g := suites[c].new(Base, Additive).group

	s, err := g.NewScalar().Decode(blind)
	if err != nil {
		return nil, err
	}

	return preprocess(g, s, serverPublicKey)
}

// FromHashToGroup returns a VOPRF Ciphersuite identifier given a HashToGroup/Hash-to-Curve Identifier.
func FromHashToGroup(id hashtogroup.Ciphersuite) (Ciphersuite, error) {
	c, ok := h2gToOprf[id]
	if !ok {
		return 0, errParamInvalidID
	}

	return c, nil
}

type oprf struct {
	id            Ciphersuite
	mode          Mode
	blinding      Blinding
	group         group.Group
	hash          *hash.Hash
	contextString []byte
}

func contextString(mode Mode, id Ciphersuite) []byte {
	return append(encoding.I2OSP1(uint(mode)), encoding.I2OSP2(uint(id))...)
}

func (o *oprf) dst(prefix string) []byte {
	return append([]byte(prefix), o.contextString...)
}

func (o *oprf) new(mode Mode, blinding Blinding) *oprf {
	o.mode = mode
	o.blinding = blinding
	o.contextString = contextString(mode, o.id)
	h2gDST := o.dst(hash2groupDSTPrefix)
	o.group = oprfToh2g[o.id].Get(h2gDST)

	return o
}

func (c Ciphersuite) client(mode Mode, blinding Blinding, blind *PreprocessedBlind) *Client {
	client := &Client{
		oprf: suites[c].new(mode, blinding),
	}

	if blind != nil {
		if len(blind.BlindedGenerator) == 0 || len(blind.BlindedPubKey) == 0 {
			panic(errInternNilPPBArgs)
		}

		ppb, err := blind.deserialize(client.group)
		if err != nil {
			panic(err)
		}

		client.preprocessedBLind = ppb
	}

	return client
}

func (c *Client) setServerPubkey(serverPublicKey []byte) error {
	pub, err := c.group.NewElement().Decode(serverPublicKey)
	if err != nil {
		return err
	}

	c.serverPublicKey = pub

	return nil
}

// Client returns an OPRF client for multiplicative blinding.
func (c Ciphersuite) Client(serverPublicKey []byte) (*Client, error) {
	// No public key means we use the base mode
	if serverPublicKey == nil {
		return c.client(Base, Multiplicative, nil), nil
	}
	// A non-nil public key indicates using the verifiable mode
	client := c.client(Verifiable, Multiplicative, nil)
	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

// ClientAdditive returns an OPRF client for additive blinding.
// The blind argument should be generated with the Preprocess function.
func (c Ciphersuite) ClientAdditive(serverPublicKey []byte, blind *PreprocessedBlind) (*Client, error) {
	if blind == nil {
		panic(errParamNilPPB)
	}

	// No public key means we use the base mode
	if serverPublicKey == nil {
		return c.client(Base, Additive, blind), nil
	}
	// A non-nil public key indicates using the verifiable mode
	client := c.client(Verifiable, Additive, blind)
	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

func (c Ciphersuite) server(mode Mode, privateKey []byte) (*Server, error) {
	s := &Server{
		oprf: suites[c].new(mode, Multiplicative),
	}

	if privateKey != nil {
		pk, err := s.group.NewScalar().Decode(privateKey)
		if err != nil {
			return nil, err
		}

		s.privateKey = pk
		s.publicKey = s.group.Base().Mult(pk)
	} else {
		s.KeyGen()
	}

	return s, nil
}

// Server returns an OPRF server instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) Server(privateKey []byte) (*Server, error) {
	return c.server(Base, privateKey)
}

// VerifiableServer returns a VOPRF server/prover instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) VerifiableServer(privateKey []byte) (*Server, error) {
	s, err := c.server(Verifiable, privateKey)
	if err != nil {
		return nil, err
	}

	s.mode = Verifiable

	return s, nil
}

func init() {
	RistrettoSha512.register(hashtogroup.Ristretto255Sha512, hash.SHA512)
	Decaf448Sha512.register(hashtogroup.Curve448Sha512, hash.SHA512)
	P256Sha256.register(hashtogroup.P256Sha256, hash.SHA256)
	P384Sha512.register(hashtogroup.P384Sha512, hash.SHA512)
	P521Sha512.register(hashtogroup.P521Sha512, hash.SHA512)
}
