package main

import (
	"github.com/dedis/cothority/lib/sign"

	"github.com/dedis/cothority/lib/dbg"
)

/*
RoundUpdate is a bare-bones round implementation to be copy-pasted. It
already implements RoundStruct for your convenience.
*/

// The name type of this round implementation
const RoundUpdateType = "update"

type RoundUpdate struct {
	*sign.RoundStruct
	*sign.RoundException
	Hash      []byte
	Signature chan sign.SignatureBroadcastMessage
}

func init() {
	sign.RegisterRoundFactory(RoundUpdateType,
		func(node *sign.Node) sign.Round {
			return NewRoundUpdate(node)
		})
}

func NewRoundUpdate(node *sign.Node) *RoundUpdate {
	dbg.Lvl3("Making new RoundUpdate", node.Name())
	round := &RoundUpdate{}
	round.RoundStruct = sign.NewRoundStruct(node, RoundUpdateType)
	// If you're sub-classing from another round-type, don't forget to remove
	// the above line, call the constructor of your parent round and add
	round.RoundException = sign.NewRoundException(node)
	round.Signature = make(chan sign.SignatureBroadcastMessage, 1)
	round.Type = RoundUpdateType
	return round
}

func (round *RoundUpdate) Announcement(viewNbr, roundNbr int, in *sign.SigningMessage, out []*sign.SigningMessage) error {
	return round.RoundException.Announcement(viewNbr, roundNbr, in, out)
}

func (round *RoundUpdate) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {
		// MTRoot contains the hash to be signed by everybody
		out.Com.MTRoot = round.Hash
	}
	return round.RoundException.Commitment(in, out)
}

func (round *RoundUpdate) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	if !round.IsRoot {
		round.Hash = in.Chm.MTRoot
	}
	return round.RoundException.Challenge(in, out)
}

func (round *RoundUpdate) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if !round.IsRoot {
		// Check on something, when it fails, call
		// round.RaiseException()
	}
	return round.RoundException.Response(in, out)
}

func (round *RoundUpdate) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	err := round.RoundException.SignatureBroadcast(in, out)
	if round.IsRoot {
		dbg.Print("Broadcasting signature")
		round.Signature <- *in.SBm
	}
	return err
}
