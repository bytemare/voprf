package voprf

import (
	"github.com/bytemare/crypto/group"
	"github.com/bytemare/crypto/hash"
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
	// which is more efficient on protocol execution but needs storage.
	Additive
)

// Ciphersuite identifies the OPRF compatible cipher suite to be used.
type Ciphersuite byte

const (
	// RistrettoSha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	RistrettoSha512 Ciphersuite = iota + 1

	// Decaf448Sha512 is the OPRF cipher suite of the Decaf448 group and SHA-512.
	decaf448Sha512

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256

	// P384Sha512 is the OPRF cipher suite of the NIST P-384 group and SHA-512.
	P384Sha512

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512

	maxID

	sRistrettoSha512 = "RistrettoSha512"
	sDecaf448Sha512  = "Decaf448Sha512"
	sP256Sha256      = "P256Sha256"
	sP384Sha512      = "P384Sha512"
	sP521Sha512      = "P521Sha512"

	// version is a string explicitly stating the version name.
	version = "VOPRF07-"

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

func preprocess(g group.Group, blind []*group.Scalar, pubKey []byte) (*PreprocessedBlind, error) {
	pub, err := g.NewElement().Decode(pubKey)
	if err != nil {
		return nil, err
	}

	p := &ppb{
		blindedGenerators: make([]*group.Point, len(blind)),
		blindedPubKeys:    make([]*group.Point, len(blind)),
	}

	for i, b := range blind {
		p.blindedGenerators[i] = g.Base().Mult(b)
		p.blindedPubKeys[i] = pub.Mult(b)
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

	return preprocess(g, []*group.Scalar{r}, serverPublicKey)
}

// PreprocessWithBlinds returns blinding values in the group given the blinds and server's public key.
func (c Ciphersuite) PreprocessWithBlinds(blinds [][]byte, serverPublicKey []byte) (*PreprocessedBlind, error) {
	if blinds == nil {
		return nil, errParamPPNilBlind
	}

	if serverPublicKey == nil {
		return nil, errParamPPNilPubKey
	}

	g := suites[c].new(Base, Additive).group

	s := make([]*group.Scalar, len(blinds))

	for i, b := range blinds {
		_s, err := g.NewScalar().Decode(b)
		if err != nil {
			return nil, err
		}

		s[i] = _s
	}

	return preprocess(g, s, serverPublicKey)
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
		PublicKey: pk.Bytes(),
		SecretKey: sk.Bytes(),
	}
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
	context := make([]byte, 0, len(dstContext)+len(o.contextString)+2+len(info)) // dstContext + s.contextString + lengthPrefixEncode(info)
	context = append(context, dstContext...)
	context = append(context, o.contextString...)
	context = append(context, lengthPrefixEncode(info)...)

	return o.HashToScalar(context)
}

func (o *oprf) new(mode Mode, blinding Blinding) *oprf {
	o.mode = mode
	o.blinding = blinding
	o.contextString = contextString(mode, o.id)
	o.group = oprfToGroup[o.id]

	return o
}

// DeriveKeyPair deterministically generates a private and public key pair from input seed.
func (o *oprf) DeriveKeyPair(seed, dst []byte) (*group.Scalar, *group.Point) {
	s := o.group.HashToScalar(seed, dst)
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

func (c Ciphersuite) client(mode Mode, blinding Blinding, blind *PreprocessedBlind) *Client {
	client := &Client{
		oprf: suites[c].new(mode, blinding),
	}

	if blind != nil {
		if len(blind.BlindedGenerators) == 0 || len(blind.BlindedPubKeys) == 0 {
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
func (c Ciphersuite) Client() *Client {
	return c.client(Base, Multiplicative, nil)
}

func (c Ciphersuite) VerifiableClient(serverPublicKey []byte) (*Client, error) {
	client := c.client(Verifiable, Multiplicative, nil)
	if err := client.setServerPubkey(serverPublicKey); err != nil {
		return nil, err
	}

	return client, nil
}

// ClientAdditive returns an OPRF client for additive blinding.
// The blind argument should be generated with the Preprocess function.
//func (c Ciphersuite) ClientAdditive(serverPublicKey []byte, blind *PreprocessedBlind) (*Client, error) {
//
//	if blind == nil {
//		panic(errParamNilPPB)
//	}
//
//	// No public key means we use the base mode
//	if serverPublicKey == nil {
//		return c.client(Base, Multiplicative, blind), nil
//	}
//	// A non-nil public key indicates using the verifiable mode
//	client := c.client(Verifiable, Multiplicative, blind)
//	if err := client.setServerPubkey(serverPublicKey); err != nil {
//		return nil, err
//	}
//
//	return client, nil
//}

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
	return c.server(Verifiable, privateKey)
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
	case P384Sha512:
		return sP384Sha512
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
	P384Sha512.register(group.P384Sha512, hash.SHA512)
	P521Sha512.register(group.P521Sha512, hash.SHA512)
}
