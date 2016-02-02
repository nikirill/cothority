package main

import (
	"sync"

	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/sign"
)

// The name type of this round implementation
const RoundSwsignType = "swsign"

var entry CommitEntry

var wg sync.WaitGroup

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

func verify(metadata *CommitEntry, beSigned string) {
	defer wg.Done()
	var err error
	metadata.decision, err = ApprovalCheck(metadata.policy, metadata.signatures, beSigned)
	if err != nil {
		dbg.Lvl1("Problem with verifying approval of developers")
	}
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
	err := round.RoundException.Announcement(viewNbr, roundNbr, in, out)
	if round.IsRoot {
		// If root, send hash to be signed to all outgoing channels (children)
		for i := range out {
			out[i].Am.Message = round.Hash
		}
	} else {
		// If child, retrieve corresponding commit from a table to check approval later
		// commitToSign = Releases[string(in.Am.Message)]
		msg := string(in.Am.Message)
		entry = Releases[msg]
		if entry.policy == "" || entry.signatures == "" {
			dbg.Lvl1("The cothority server has not received information about this release from its developers")
		} else {
			wg.Add(1)
			go verify(&entry, msg)
		}

	}

	return err
}

func (round *RoundSwsign) Commitment(in []*sign.SigningMessage, out *sign.SigningMessage) error {
	if round.IsRoot {
		// MTRoot contains the hash to be signed by everybody
		out.Com.MTRoot = round.Hash
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
		// if entry.policy == "" || entry.signatures == "" {
		// 	dbg.Lvl1("The cothority server has not received information about this release from its developers")
		// 	round.RaiseException()
		// }

		// pgp := monitor.NewMeasure("pgp")
		// decision, err := ApprovalCheck(entry.policy, entry.signatures, msg)
		// pgp.Measure()
		wg.Wait()

		if !entry.decision {
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
