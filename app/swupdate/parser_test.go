package main

import (
	"io/ioutil"
	"testing"

	"github.com/dedis/cothority/lib/debug_lvl"
)

func TestSigScanner(t *testing.T) {
	debug_lvl.TestOutput(testing.Verbose(), 4)
	signame := "/tmp/sigs.txt"
	ioutil.WriteFile(signame, []byte(TestFileSignatures), 0660)
	blocks, err := SigScanner(signame)
	if err != nil {
		t.Fatal("Error while parsing blocks:", err)
	}

	debug_lvl.Printf("%+v", blocks)
}

func TestPolicyScanner(t *testing.T) {
	debug_lvl.TestOutput(testing.Verbose(), 4)
	polname := "/tmp/policy.txt"
	ioutil.WriteFile(polname, []byte(TestFilePolicy), 0660)
	thres, devkeys, cothkey, err := PolicyScanner(polname)
	if err != nil {
		t.Fatal("Error while parsing blocks:", err)
	}

	debug_lvl.Printf("%+v\n %+v\n %+v\n", thres, devkeys, cothkey)
}
