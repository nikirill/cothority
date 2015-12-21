package main

import (
	"github.com/dedis/cothority/lib/sign"

	"github.com/dedis/cothority/lib/dbg"
)

/*
RoundSwsign is a bare-bones round implementation to be copy-pasted. It
already implements RoundStruct for your convenience.
*/

// The name type of this round implementation
const RoundSwsignType = "swsign"

var commitToSign SignedCommit

type RoundSwsign struct {
	*sign.RoundStruct
	*sign.RoundException
	Hash      []byte
	Signature chan sign.SignatureBroadcastMessage
}

func init() {
	sign.RegisterRoundFactory(RoundSwsignType,
		func(node *sign.Node) sign.Round {
			return NewRoundSwsign(node)
		})
}

func NewRoundSwsign(node *sign.Node) *RoundSwsign {
	dbg.Lvl3("Making new RoundSwsign", node.Name())
	round := &RoundSwsign{}
	round.RoundStruct = sign.NewRoundStruct(node, RoundSwsignType)
	// If you're sub-classing from another round-type, don't forget to remove
	// the above line, call the constructor of your parent round and add
	round.RoundException = sign.NewRoundException(node)
	round.Signature = make(chan sign.SignatureBroadcastMessage, 1)
	round.Type = RoundSwsignType
	return round
}

func (round *RoundSwsign) Announcement(viewNbr, roundNbr int, in *sign.SigningMessage, out []*sign.SigningMessage) error {
	if round.IsRoot {
		// MTRoot contains the hash to be signed by everybody
		for i := range out {
			*out[i].Am.Message = round.Hash
		}
	}
	return round.RoundException.Announcement(viewNbr, roundNbr, in, out)
}

func (round *RoundSwsign) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {
		// MTRoot contains the hash to be signed by everybody
		out.Com.MTRoot = round.Hash
	} else {
		// Leaves receive commitID that needs to be signed and verify if there is an approval in their map
		commitToSign = Releases[string(in.Com.Message)]
		dbg.Print(string(in.Com.Message))
	}
	return round.RoundException.Commitment(in, out)
}

func (round *RoundSwsign) Challenge(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	if !round.IsRoot {
		round.Hash = in.Chm.MTRoot
	}
	return round.RoundException.Challenge(in, out)
}

func (round *RoundSwsign) Response(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if !round.IsRoot {
		if commitToSign.CommitID == "" {
			dbg.Lvl1("The cothority server has not received information about this release from its developers")
			round.RaiseException()
		}

		if !commitToSign.Approval {
			dbg.Printf("Threshold = %+v", commitToSign.Policy.Threshold)
			dbg.Printf("ID = %+v", commitToSign.CommitID)
			dbg.Lvl1("Developers haven't approved this release")
			round.RaiseException()
		}
		// Check on something, when it fails, call
		// round.RaiseException()
	}
	return round.RoundException.Response(in, out)
}

func (round *RoundSwsign) SignatureBroadcast(in *sign.SigningMessage, out []*sign.SigningMessage) error {
	err := round.RoundException.SignatureBroadcast(in, out)
	if round.IsRoot {
		dbg.Print("Broadcasting signature")
		round.Signature <- *in.SBm
	}
	return err
}
