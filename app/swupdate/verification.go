package main

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp"

	"github.com/dedis/cothority/lib/debug_lvl"
)

var (
	PolicyFile     = "example/policy.txt"
	SignaturesFile = "example/signatures.txt"
	CommitIdFile   = "example/commitid.txt"
)

type CommitPolicy struct {
	Threshold  int      // Sufficient number of developers that must signed off to approve a commit
	DevPubKeys []string // Developers' personal PGP public keys
	CothKey    string   // Public key of cothority server that this group of developers sends approval to
}

type SignedCommit struct {
	CommitID   string       // ID of a git commit that has been signed oof by developers
	Policy     CommitPolicy // Security policy for this very commit
	Signatures []string     // Signatures of developers on the commit
}

func checkFileError(err error, filename string) {
	if err != nil {
		debug_lvl.Lvl1("Could not read file", filename)
	}
}

func main() {
	var (
		Commit SignedCommit
		err    error
	)

	Commit.Policy.Threshold, Commit.Policy.DevPubKeys, Commit.Policy.CothKey, err = PolicyScanner(PolicyFile)
	checkFileError(err, PolicyFile)
	Commit.Signatures, err = SigScanner(SignaturesFile)
	checkFileError(err, SignaturesFile)
	Commit.CommitID, err = CommitScanner(CommitIdFile)
	checkFileError(err, CommitIdFile)

	// Creating openpgp entitylist from list of public keys
	var developers openpgp.EntityList
	developers = make(openpgp.EntityList, 0)

	for _, pubkey := range Commit.Policy.DevPubKeys {
		keybuf, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pubkey))
		if err != nil {
			debug_lvl.Error("Could not decode armored public key", err)
		}
		for _, entity := range keybuf {
			developers = append(developers, entity)
		}
	}

	// Verifying every signature in the list and counting valid ones
	for _, signature := range Commit.Signatures {
		result, err := openpgp.CheckArmoredDetachedSignature(developers, bytes.NewBufferString(Commit.CommitID), strings.NewReader(signature))
		if err != nil {
			debug_lvl.Error("Did not manage to verify signature", err)
		}
		fmt.Println("Author of signature is", result.Identities)
	}

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

	// result, err = armor.Decode(bufbytes)
	// if err != nil {
	// 	log.Fatal("Couldn't decode signatures", err)
	// }
	// body, _ = ioutil.ReadAll(result.Body)
	// fmt.Println(result.Type, result.Header, string(body))

	/*

		comfile, err := os.Open("example/commitid.txt")
		if err != nil {
			panic(err)
		}
		defer comfile.Close()

		b1 := make([]byte, 40)
		n1, err := comfile.Read(b1)
		ci.CommitID = string(b1)

		fmt.Println(ci.CommitID)
		fmt.Println("example printing", n1)
	*/
}
