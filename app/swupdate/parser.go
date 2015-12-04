package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/dedis/cothority/lib/dbg"
)

// Scanner for a file contatining singatures
func SigScanner(filename string) ([]string, error) {
	var blocks []string
	head := "-----BEGIN PGP SIGNATURE-----"
	dbg.Lvl3("Reading file", filename)

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		dbg.Lvl1("Couldn't open file", file, err)
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	var block []string
	for scanner.Scan() {
		text := scanner.Text()
		dbg.Lvl3("Decoding", text)
		// end of the first part
		if text == head {
			dbg.Lvl2("Found header")
			if len(block) > 0 {
				blocks = append(blocks, strings.Join(block, "\n"))
				block = make([]string, 0)
			}
		}
		block = append(block, text)
	}
	blocks = append(blocks, strings.Join(block, "\n"))
	return blocks, nil
}

// Scanner for a file containing policy
func PolicyScanner(filename string) (int, []string, string, error) {
	var threshold int
	var cothkey string

	dbg.Lvl3("Reading file", filename)

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		dbg.Lvl1("Couldn't open file", file, err)
		return -1, nil, "", err
	}

	scanner := bufio.NewScanner(file)
	keyblock := make([]string, 0)
	devkeys := make([]string, 0)
	for scanner.Scan() {
		text := scanner.Text()
		dbg.Lvl3("Decoding", text)

		switch text {
		case "Threshold:":
			// reading threshold number
			dbg.Lvl2("Found Threshold")
			// if we have found "threshold" word, we know that the value is
			// in the next line so we scan next line and if it is not empty,
			// we save the value as the threshold
			scanner.Scan()
			text := scanner.Text()
			if len(text) > 0 {
				threshold, err = strconv.Atoi(text)
			}
			if err != nil {
				dbg.Error("Could not convert threshold into a number")
			}
			// If there is a key block being constructed when we encounter the threshold,
			// we know that the key block is fulfilled so we have have to append it to
			// the array of developer keys
			if len(keyblock) > 0 {
				devkeys = append(devkeys, strings.Join(keyblock, "\n"))
				keyblock = make([]string, 0)
			}

		case "-----BEGIN PGP PUBLIC KEY BLOCK-----":
			// reading developers' public keys
			dbg.Lvl2("Found Developers' public keys")
			if len(keyblock) > 0 {
				// if keyblock already exsits, it means that we encounter beggining of a new key,
				// so we need to save the previous one and start constructing a new one
				devkeys = append(devkeys, strings.Join(keyblock, "\n"))
				keyblock = make([]string, 0)
			}
			keyblock = append(keyblock, text)

		case "Cothority Public Key:":
			// reading cothority public key
			dbg.Lvl2("Found Cothority public key")
			if len(keyblock) > 0 {
				devkeys = append(devkeys, strings.Join(keyblock, "\n"))
				keyblock = make([]string, 0)
			}

			scanner.Scan()
			text := scanner.Text()
			for text != "" {
				keyblock = append(keyblock, text)
				err := scanner.Scan()
				if err != false {
					text = scanner.Text()
				} else {
					break
				}
			}

			cothkey = strings.Join(keyblock, "")
			keyblock = make([]string, 0)

		case "":
			if len(keyblock) == 0 {
				continue
			}
			keyblock = append(keyblock, text)

		default:
			if text != "Developers Public Keys:" {
				// All parameters except PGP keys follow at next line from a name of the parameter
				// so by default we a new line to a current key block
				keyblock = append(keyblock, text)
			}
		}
	}

	return threshold, devkeys, cothkey, err
}

// Scanner for a file containing commit id
func CommitScanner(filename string) (string, error) {
	dbg.Lvl3("Reading file", filename)

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		dbg.Lvl1("Couldn't open file", file, err)
		return "", err
	}

	comid := make([]byte, 40)
	_, err = file.Read(comid)
	if err != nil {
		dbg.Lvl1("Couldn't read from file", filename, err)
		return "", err
	}

	return string(comid), err
}
