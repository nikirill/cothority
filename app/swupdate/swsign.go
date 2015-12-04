package main

import (
	"github.com/dedis/cothority/lib/dbg"
)

var (
	PolicyFile     = "example/policy.txt"
	SignaturesFile = "example/signatures.txt"
	CommitIdFile   = "example/commitid.txt"
)

func main() {
	answer, err := ApprovalCheck(PolicyFile, SignaturesFile, CommitIdFile)
	if err != nil {
		dbg.Panic("Problem with verifying approval of developers")
	}
	dbg.Lvl1("Is release approved by developers?", answer)
}
