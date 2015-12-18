package main

import (
	"testing"

	"github.com/dedis/cothority/lib/dbg"
)

func TestVerification(t *testing.T) {
	dbg.TestOutput(testing.Verbose(), 4)
	var (
		PolicyFile     = "example/policy.txt"
		SignaturesFile = "example/signatures.txt"
		CommitIdFile   = "example/commitid.txt"
	)

	answer, err := ApprovalCheck(PolicyFile, SignaturesFile, CommitIdFile)
	if err != nil {
		dbg.Panic("Problem with verifying approval of developers", err)
	}

	dbg.Printf("How many signatures have been read? %+v", len(Commit.Signatures))
	dbg.Printf("What is a threshold value? %+v", Commit.Policy.Threshold)
	dbg.Printf("Is commit approved? %+v", answer)
}
