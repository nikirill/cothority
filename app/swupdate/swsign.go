package main

import (
	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/monitor"
)

var (
	PolicyFile     = "example/policy.txt"
	SignaturesFile = "example/signatures.txt"
	CommitIdFile   = "example/commitid.txt"
)

// var Releases map[string]SignedCommit
var Releases map[string]CommitEntry

type CommitEntry struct {
	policy     string
	signatures string
}

// func ReleaseInformation() {
// 	c, err := ApprovalCheck(PolicyFile, SignaturesFile, CommitIdFile)
// 	if err != nil {
// 		dbg.Panic("Problem with verifying approval of developers", err)
// 	} else {
// 		Releases[c.CommitID] = c
// 		dbg.Lvl3("Retrieved information about release\n")
// 	}
// }

func ReadRelease(pf, sf, cif string) {
	cid, err := CommitScanner(cif)
	if err != nil {
		dbg.Panic("Cannot read commitid corresponding to the release")
	} else {
		Releases[cid] = CommitEntry{pf, sf}
		dbg.Lvl3("Added a new entry to release table")
	}

}

func main() {
	conf := &app.ConfigColl{}
	app.ReadConfig(conf)

	// we must know who we are
	if app.RunFlags.Hostname == "" {
		dbg.Fatal("Hostname empty: Abort")
	}

	// Do some common setup
	if app.RunFlags.Mode == "client" {
		app.RunFlags.Hostname = app.RunFlags.Name
	}
	hostname := app.RunFlags.Hostname
	if hostname == conf.Hosts[0] {
		dbg.Lvlf3("Tree is %+v", conf.Tree)
	}
	dbg.Lvl3(hostname, "Starting to run")

	app.RunFlags.StartedUp(len(conf.Hosts))
	peer := conode.NewPeer(hostname, conf.ConfigConode)

	Releases = make(map[string]CommitEntry)
	//ReleaseInformation()
	ReadRelease(PolicyFile, SignaturesFile, CommitIdFile)

	if app.RunFlags.AmRoot {
		err := peer.WaitRoundSetup(len(conf.Hosts), 5, 2)
		if err != nil {
			dbg.Fatal(err)
		}
		dbg.Lvl1("Starting the rounds")
	}

	if app.RunFlags.AmRoot {
		for round := 0; round < conf.Rounds; round++ {
			dbg.Lvl1("Doing round", round, "of", conf.Rounds)
			wallTime := monitor.NewMeasure("round")
			hashToSign, _ := CommitScanner(CommitIdFile) // retrieve commitid/hash that the root is willing to get signed

			entry := Releases[hashToSign]
			if entry.policy != "" && entry.signatures != "" {
				rootpgpTime := monitor.NewMeasure("rootpgp")
				decision, err := ApprovalCheck(entry.policy, entry.signatures, hashToSign)
				rootpgpTime.Measure()

				if decision && err == nil {
					round := NewRoundSwsign(peer.Node)
					round.Hash = []byte(hashToSign) // passing hash of the file that we want to produce a signature for
					peer.StartAnnouncement(round)

					wallTime.Measure()
					Signature := <-round.Signature
					dbg.Lvlf1("Received signature %+v", Signature)
				} else {
					dbg.Fatal("Developers related to the root haven't approved the release so the root didn't start signing process")
				}
			} else {
				dbg.Error("There is no input with such commitid", hashToSign)
			}
		}
		peer.SendCloseAll()
	} else {
		peer.LoopRounds(RoundSwsignType, conf.Rounds)
	}

	dbg.Lvlf3("Done - flags are %+v", app.RunFlags)
	monitor.End()
}
