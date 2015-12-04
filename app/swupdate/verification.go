package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/dedis/cothority/lib/dbg"

	"golang.org/x/crypto/openpgp"
)

var (
	PolicyFile     = "example/policy.txt"
	SignaturesFile = "example/signatures.txt"
	CommitIdFile   = "example/commitid.txt"
)

type commitPolicy struct {
	Threshold  int      // Sufficient number of developers that must signed off to approve a commit
	DevPubKeys []string // Developers' personal PGP public keys
	CothKey    string   // Public key of cothority server that this group of developers sends approval to
}

type Signedcommit struct {
	commitID   string       // ID of a git commit that has been signed oof by developers
	Policy     commitPolicy // Security policy for this very commit
	Signatures []string     // Signatures of developers on the commit
}

func checkFileError(err error, filename string) {
	if err != nil {
		dbg.Lvl1("Could not read file", filename)
	}
}

func main() {
	var (
		commit     Signedcommit
		developers openpgp.EntityList
		approvers  map[string]*openpgp.Entity // Map of developers who provided a valid signature. Indexed by public key id (openpgp.PrimaryKey.KeyIdString)
		err        error
	)

	commit.Policy.Threshold, commit.Policy.DevPubKeys, commit.Policy.CothKey, err = PolicyScanner(PolicyFile)
	checkFileError(err, PolicyFile)
	commit.Signatures, err = SigScanner(SignaturesFile)
	checkFileError(err, SignaturesFile)
	commit.commitID, err = CommitScanner(CommitIdFile)
	checkFileError(err, CommitIdFile)

	approvers = make(map[string]*openpgp.Entity)

	// Creating openpgp entitylist from list of public keys
	developers = make(openpgp.EntityList, 0)

	for _, pubkey := range commit.Policy.DevPubKeys {
		keybuf, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pubkey))
		if err != nil {
			dbg.Error("Could not decode armored public key", err)
		}
		for _, entity := range keybuf {
			developers = append(developers, entity)
		}
	}

	// Verifying every signature in the list and counting valid ones
	for _, signature := range commit.Signatures {
		result, err := openpgp.CheckArmoredDetachedSignature(developers, bytes.NewBufferString(commit.commitID), strings.NewReader(signature))
		if err != nil {
			dbg.Lvl1("The signature is invalid or cannot be verified due to", err)
		} else {
			if approvers[result.PrimaryKey.KeyIdString()] == nil { // We need to check that this is a unique signature
				approvers[result.PrimaryKey.KeyIdString()] = result
			}
		}
	}

	fmt.Printf("Update is approved? %t", len(approvers) >= commit.Policy.Threshold)

	//fmt.Println(entityList)
	// body, _ := ioutil.ReadAll(block.Body)
	// fmt.Println(block.Type)
	// fmt.Println(string(body))

	// bufbytes := bytes.NewBuffer(buf)
	// result, err := armor.Decode(bufbytes)
	// if err != nil {
	// 	log.Fatal("Couldn't decode signatures", err)
	// }
	// body, _ := ioutil.ReadAll(result.Body)
	// fmt.Println(result.Type, result.Header, string(body))
}
