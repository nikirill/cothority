package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/cothority/lib/dbg"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	const text = `cf0b83954b84c27b2e7c345e1356b4d0f9de9a33`
	const amount = 10
	const poname = "policy.txt"
	const cothk = `BFZMf2MBCADjrCHk+W+MTXh9ZiwAScnaROwEER39zuieHdz0g9whVVTubl8SakGp
sCw7ZjHJARC+YqRH2oiqqLQ0ZYp7SFLcByin4FLJBqHeuCONhP1j6DHj5yDfNcyP`

	var developers openpgp.EntityList

	for i := 0; i < amount; i++ {
		entity, err := openpgp.NewEntity(strconv.Itoa(i), "", "", nil)
		developers = append(developers, entity)
		if err != nil {
			dbg.Errorf("PGP entity %+v has not been created %+v", i, err)
		}
	}

	// Creating a policy file
	w := new(bytes.Buffer)
	_, err := w.WriteString("Threshold:\n")
	_, err = w.WriteString(strconv.Itoa(amount))
	_, err = w.WriteString("\n\n\nDevelopers Public Keys:\n")
	err = ioutil.WriteFile(poname, w.Bytes(), 0660)
	w.Reset()

	f, _ := os.OpenFile(poname, os.O_APPEND|os.O_WRONLY, 0660)
	defer f.Close()

	for _, entity := range developers {
		asciiwr := new(bytes.Buffer)
		arm, _ := armor.Encode(asciiwr, openpgp.PublicKeyType, nil)
		err := entity.SerializePrivate(arm, nil)
		err = entity.Serialize(arm)
		if err != nil {
			dbg.Error("Problem with serializing public key", err)
		}
		arm.Close()

		asciiwr.WriteByte(byte('\n'))
		n, er := f.Write(asciiwr.Bytes())
		if er != nil {
			dbg.Error("Could not write a public key to policy file", n)
		}
	}

	_, err = f.WriteString("\n\nCothority Public Key:\n")
	_, err = f.WriteString(cothk)

	if err != nil {
		dbg.Error("Could not write to policy a file", err)
	}

	for _, entity := range developers {
		openpgp.ArmoredDetachSign(w, entity, strings.NewReader(text), nil)
		w.WriteByte(byte('\n'))
	}

	err = ioutil.WriteFile("signatures.txt", w.Bytes(), 0660)
	if err != nil {
		dbg.Error("Could not write to a signatures file", err)
	}

	//fmt.Println(w.String())
}
