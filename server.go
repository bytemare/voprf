package voprf

import (
	"fmt"

	"github.com/bytemare/pake/cryptotools/hashtogroup/group"
)

// Server holds the (V)OPRF prover data.
type Server struct {
	privateKey group.Scalar
	publicKey  group.Element
	*oprf
}

// KeyGen generates and sets a new private/public key pair.
func (s *Server) KeyGen() {
	s.privateKey = s.group.NewScalar().Random()
	s.publicKey = s.group.Base().Mult(s.privateKey)
}

// Evaluate the input with the private key.
func (s *Server) Evaluate(blinded []byte) (*Evaluation, error) {
	b, err := s.group.NewElement().Decode(blinded)
	if err != nil {
		return nil, fmt.Errorf("OPRF can't evaluate input : %w", err)
	}

	ev := &Evaluation{
		element: s.evaluate(b),
		proofC:  nil,
		proofS:  nil,
	}

	if s.mode == Verifiable {
		c, s := s.generateProof(b, ev.element)
		ev.proofC = c
		ev.proofS = s
	}

	return ev, nil
}

// FullEvaluate reproduces the full PRF but without the blinding operations, using the client's input.
// This should output the same digest as the client's Finalize() function.
func (s *Server) FullEvaluate(input, info []byte) []byte {
	p := s.group.HashToGroup(input)
	t := s.evaluate(p)

	return s.hashTranscript(input, t.Bytes(), info)
}

// VerifyFinalize takes the client input (the un-blinded element) and the client's Finalize() output,
// and returns whether it can match the client's output.
func (s *Server) VerifyFinalize(input, output, info []byte) bool {
	digest := s.FullEvaluate(input, info)
	return ctEqual(digest, output)
}

// PrivateKey returns the server's private key.
func (s *Server) PrivateKey() []byte {
	return s.privateKey.Bytes()
}

// PublicKey returns the server's public key.
func (s *Server) PublicKey() []byte {
	return s.publicKey.Bytes()
}

func (s *Server) evaluate(blinded group.Element) group.Element {
	return blinded.Mult(s.privateKey)
}

func (s *Server) generateProof(blinded, element group.Element) (c, sc group.Scalar) {
	tokenList := []group.Element{blinded}
	elementList := []group.Element{element}

	a1, a2 := s.computeComposite(s.privateKey, s.publicKey, tokenList, elementList)

	r := s.group.NewScalar().Random()
	a3 := s.group.Base().Mult(r)
	a4 := a1.Mult(r)

	c = s.proofScalar(s.publicKey, a1, a2, a3, a4)
	sc = c.Copy()
	m := sc.Mult(s.privateKey)
	sc = r.Sub(m)

	return c, sc
}
