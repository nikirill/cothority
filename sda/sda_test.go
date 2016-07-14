package sda

import (
	"testing"

	"github.com/dedis/cothority/log"
)

// To avoid setting up testing-verbosity in all tests
func TestMain(m *testing.M) {
	log.MainTest(m)
}
