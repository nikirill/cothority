package main

import (
	"time"

	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/cothority/lib/monitor"
	"github.com/dedis/cothority/lib/sign"
)

var (
	PolicyFile     = "example/policy.txt"
	SignaturesFile = "example/signatures.txt"
	CommitIdFile   = "example/commitid.txt"
)

var Releases map[string]SignedCommit

func ReleaseInformation() {
	c, err := ApprovalCheck(PolicyFile, SignaturesFile, CommitIdFile)
	if err != nil {
		dbg.Panic("Problem with verifying approval of developers", err)
	} else {
		Releases[c.CommitID] = c
		dbg.Lvl3("Retrieved information about release\n")
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

	Releases = make(map[string]SignedCommit)
	ReleaseInformation()

	if app.RunFlags.AmRoot {
		for {
			time.Sleep(time.Second)
			setupRound := sign.NewRoundSetup(peer.Node)
			peer.StartAnnouncementWithWait(setupRound, 5*time.Second)
			counted := <-setupRound.Counted
			dbg.Lvl1("Number of peers counted:", counted)
			if counted == len(conf.Hosts) {
				dbg.Lvl1("All hosts replied")
				break
			}
		}
	}

	if app.RunFlags.AmRoot {
		hashToSign, _ := CommitScanner(CommitIdFile) // retrieve commitid/hash that the root is willing to get signed
		commitToSign := Releases[hashToSign]
		if commitToSign.Approval {
			round := NewRoundSwsign(peer.Node)
			round.Hash = []byte(hashToSign) // passing hash of the file that we want to produce a signature for
			peer.StartAnnouncement(round)

			Signature := <-round.Signature
			peer.SendCloseAll()

			dbg.Lvlf1("Received signature %+v", Signature)
		} else {
			dbg.Fatal("Developers related to the root haven't approved the release so the root didn't start signing process")
		}
	} else {
		peer.LoopRounds(RoundSwsignType, conf.Rounds)
	}

	dbg.Lvlf3("Done - flags are %+v", app.RunFlags)
	monitor.End()
}
