package voprf

import (
	"fmt"

	"github.com/bytemare/crypto/group"
)

// Server holds the (V)OPRF prover data.
type Server struct {
	privateKey *group.Scalar
	publicKey  *group.Point
	*oprf
	nonceR []byte
}

func (s *Server) generateProof(k *group.Scalar, blindedElements, evaluatedElements []*group.Point) (proofC, proofS *group.Scalar) {
	gk := s.id.Group().Base().Mult(k)
	encGk := lengthPrefixEncode(serializePoint(gk, pointLength(s.id)))
	a0, a1 := s.computeComposites(k, encGk, blindedElements, evaluatedElements)

	var r *group.Scalar
	if s.nonceR == nil {
		r = s.group.NewScalar().Random()
	} else {
		var err error
		r, err = s.group.NewScalar().Decode(s.nonceR)
		if err != nil {
			panic(err)
		}
	}

	a2 := s.group.Base().Mult(r)
	a3 := a0.Mult(r)

	proofC = s.challenge(encGk, a0, a1, a2, a3)
	proofS = r.Sub(proofC.Mult(k))

	return proofC, proofS
}

// KeyGen generates and sets a new private/public key pair.
func (s *Server) KeyGen() {
	s.privateKey = s.group.NewScalar().Random()
	s.publicKey = s.group.Base().Mult(s.privateKey)
}

// Evaluate the input with the private key.
func (s *Server) Evaluate(blindedElement, info []byte) (*Evaluation, error) {
	return s.EvaluateBatch([][]byte{blindedElement}, info)
}

// EvaluateBatch evaluates the input batch of blindedElements and returns a pointer to the Evaluation. If the server
// was set to be un Verifiable mode, the proof will be included in the Evaluation.
func (s *Server) EvaluateBatch(blindedElements [][]byte, info []byte) (*Evaluation, error) {
	ev := &evaluation{}
	ev.elements = make([]*group.Point, len(blindedElements))

	var blinded []*group.Point

	if s.mode == Verifiable {
		blinded = make([]*group.Point, len(blindedElements))
	}

	context := s.pTag(info)
	k := s.privateKey.Add(context)
	inv := k.Invert()

	// decode and evaluate element(s)
	for i, b := range blindedElements {
		b, err := s.group.NewElement().Decode(b)
		if err != nil {
			return nil, fmt.Errorf("OPRF can't evaluate input : %w", err)
		}

		if s.mode == Verifiable {
			blinded[i] = b
		}

		ev.elements[i] = b.Mult(inv)
	}

	if s.mode == Verifiable {
		ev.proofC, ev.proofS = s.generateProof(k, blinded, ev.elements)
	}

	return ev.serialize(s.id), nil
}

// FullEvaluate reproduces the full PRF but without the blinding operations, using the client's input.
// This should output the same digest as the client's Finalize() function.
func (s *Server) FullEvaluate(input, info []byte) []byte {
	p := s.HashToGroup(input)
	k := s.privateKey.Add(s.pTag(info))
	t := p.Mult(k.Invert())

	return s.hashTranscript(serializePoint(p, pointLength(s.id)), info, serializePoint(t, scalarLength(s.id)))
}

// VerifyFinalize takes the client input (the un-blinded element) and the client's finalize() output,
// and returns whether it can match the client's output.
func (s *Server) VerifyFinalize(input, info, output []byte) bool {
	digest := s.FullEvaluate(input, info)
	return ctEqual(digest, output)
}

// VerifyFinalizeBatch takes the batch of client input (the un-blinded elements) and the client's finalize() outputs,
// and returns whether it can match the client's outputs.
func (s *Server) VerifyFinalizeBatch(input, output [][]byte, info []byte) bool {
	res := true

	for i, in := range input {
		res = s.VerifyFinalize(in, info, output[i])
	}

	return res
}

// PrivateKey returns the server's serialized private key.
func (s *Server) PrivateKey() []byte {
	return serializeScalar(s.privateKey, scalarLength(s.id))
}

// PublicKey returns the server's serialized public key.
func (s *Server) PublicKey() []byte {
	return serializePoint(s.publicKey, pointLength(s.id))
}

// Ciphersuite returns the cipher suite used in s' instance.
func (s *Server) Ciphersuite() Ciphersuite {
	return s.id
}
