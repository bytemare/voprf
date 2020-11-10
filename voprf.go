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
	// Base sets the OPRF non-verifiable, base mode.
	Base Mode = iota

	// Verifiable sets the OPRF verifiable mode.
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

// Ciphersuite identifies the OPRF compatible ciphersuite to be used.
type Ciphersuite byte

const (
	// RistrettoSha512 is the OPRF ciphersuite of the Ristretto255 group and SHA-512.
	RistrettoSha512 Ciphersuite = iota + 1

	// Decaf448Sha512 is the OPRF ciphersuite of the Decaf448 group and SHA2-512.
	Decaf448Sha512

	// P256Sha512 is the OPRF ciphersuite of the NIST P-256 group and SHA2-512.
	P256Sha512

	// P384Sha384 is the OPRF ciphersuite of the NIST P-384 group and SHA2-384.
	P384Sha384

	// P521Sha512 is the OPRF ciphersuite of the NIST P-512 group and SHA2-512.
	P521Sha512

	maxID

	// protocol is a string explicitly stating the protocol.
	protocol = "RFCXXXX"

	// hash2groupDSTPrefix is the string prefix to use for HashToGroup operations.
	hash2groupDSTPrefix = protocol + "-HashToGroup-"
)

var (
	suites    = make([]*oprf, maxID)
	h2gToOprf = make(map[hashtogroup.Identifier]Ciphersuite)
	oprfToh2g = make(map[Ciphersuite]hashtogroup.Identifier)
)

func (c Ciphersuite) register(g hashtogroup.Identifier, h hash.Identifier) {
	o := &oprf{
		id:   c,
		hash: h.Get(),
	}

	suites[c] = o
	h2gToOprf[g] = c
	oprfToh2g[c] = g
}

// Preprocess generates a new random blind in the given group, and returns blinding values given the server's public key.
func (c Ciphersuite) Preprocess(serverPublicKey []byte) (*PreprocessedBlind, error) {
	if serverPublicKey == nil {
		panic("can't preprocess with nil server public key")
	}

	g := c.Client().group
	r := g.NewScalar().Random()

	pub, err := g.NewElement().Decode(serverPublicKey)
	if err != nil {
		return nil, err
	}

	return &PreprocessedBlind{
		blindedGenerator: g.Base().Mult(r),
		blindedPubKey:    pub.Mult(r),
	}, nil
}

// DecodePreprocessedBlind attempts to decode the encoded PreprocessedBlind and restore it given the encoding.
func (c Ciphersuite) DecodePreprocessedBlind(encoded []byte, enc encoding.Encoding) (*PreprocessedBlind, error) {
	g := oprfToh2g[c].Get([]byte("DecodePreprocessedBlind"))

	e, err := enc.Decode(encoded, &ppbEncoded{})
	if err != nil {
		return nil, err
	}

	pp, ok := e.(*ppbEncoded)
	if !ok {
		return nil, errInternalDecodePPB
	}

	gen, err := g.NewElement().Decode(pp.BlindedGenerator)
	if err != nil {
		return nil, err
	}

	pub, err := g.NewElement().Decode(pp.BlindedPubKey)
	if err != nil {
		return nil, err
	}

	return &PreprocessedBlind{
		blindedGenerator: gen,
		blindedPubKey:    pub,
	}, nil
}

// FromHashToGroup returns a VOPRF Ciphersuite identifier given a HashToGroup/Hash-to-Curve Identifier.
func FromHashToGroup(id hashtogroup.Identifier) (Ciphersuite, error) {
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
	info          []byte
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
	o.info = o.dst(protocol + "-")
	h2gDST := o.dst(hash2groupDSTPrefix)
	o.group = oprfToh2g[o.id].Get(h2gDST)

	return o
}

func (c Ciphersuite) client(mode Mode, blinding Blinding, blind *PreprocessedBlind) *Client {
	if blind != nil {
		if blind.blindedGenerator == nil || blind.blindedPubKey == nil {
			panic(errInternNilPPBArgs)
		}
	}

	client := &Client{
		oprf:              suites[c].new(mode, blinding),
		preprocessedBLind: blind,
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
func (c Ciphersuite) Client() *Client {
	return c.client(Base, Multiplicative, nil)
}

// ClientAdditive returns an OPRF client for additive blinding.
// The blind argument should be generated with the Preprocess function.
func (c Ciphersuite) ClientAdditive(blind *PreprocessedBlind) *Client {
	if blind == nil {
		panic(errParamNilPPB)
	}

	return c.client(Base, Additive, blind)
}

// VerifiableClient returns a VOPRF client/verifier with multiplicative blinding.
// The serverPublicKey serves to verify the server's proof.
func (c Ciphersuite) VerifiableClient(serverPublicKey []byte) (*Client, error) {
	if serverPublicKey == nil {
		panic(errParamNilPubVerif)
	}

	client := c.client(Verifiable, Multiplicative, nil)

	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

// VerifiableClientAdditive returns a VOPRF client/verifier with additive blinding.
// The blind argument should be generated with the Preprocess function.
// The encoded serverPublicKey serves to verify the server's proof.
func (c Ciphersuite) VerifiableClientAdditive(serverPublicKey []byte, blind *PreprocessedBlind) (*Client, error) {
	if serverPublicKey == nil {
		panic(errParamNilPubAdd)
	}

	if blind == nil {
		panic(errParamNilPPB)
	}

	client := c.client(Verifiable, Additive, blind)

	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

// Server returns an OPRF server instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) Server(privateKey []byte) (*Server, error) {
	s := &Server{
		oprf: suites[c].new(Base, Multiplicative),
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

// VerifiableServer returns a VOPRF server/prover instantiated with the given encoded private key.
// If privateKey is nil, a new private/public key pair is created.
func (c Ciphersuite) VerifiableServer(privateKey []byte) (*Server, error) {
	s, err := c.Server(privateKey)
	if err != nil {
		return nil, err
	}

	s.mode = Verifiable

	return s, nil
}

func init() {
	RistrettoSha512.register(hashtogroup.Ristretto255Sha512, hash.SHA512)
	Decaf448Sha512.register(hashtogroup.Curve448Sha512, hash.SHA512)
	P256Sha512.register(hashtogroup.P256Sha256, hash.SHA256)
	P384Sha384.register(hashtogroup.P384Sha512, hash.SHA512)
	P521Sha512.register(hashtogroup.P521Sha512, hash.SHA512)
}
