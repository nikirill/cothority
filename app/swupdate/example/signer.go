package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/dedis/cothority/lib/dbg"
	"golang.org/x/crypto/openpgp"
)

func main() {
	const text = `cf0b83954b84c27b2e7c345e1356b4d0f9de9a33`

	const privatering = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

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
ehUiAg==
=eWT7
-----END PGP PRIVATE KEY BLOCK-----`

	developers, err := openpgp.ReadArmoredKeyRing(strings.NewReader(privatering))
	if err != nil {
		dbg.Error("Could not read private keyring", err)
	}

	w := new(bytes.Buffer)
	for _, entity := range developers {
		openpgp.ArmoredDetachSign(w, entity, strings.NewReader(text), nil)
		w.WriteByte(byte('\n'))
	}

	err = ioutil.WriteFile("signatures.txt", w.Bytes(), 0660)
	if err != nil {
		dbg.Error("Could not write to a file", err)
	}

	fmt.Println(w.String())
}
