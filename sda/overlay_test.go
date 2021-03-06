package sda_test

import (
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/sda"
)

type ProtocolOverlay struct {
	*sda.TreeNodeInstance
	done bool
}

func (po *ProtocolOverlay) Start() error {
	// no need to do anything
	return nil
}

func (po *ProtocolOverlay) Dispatch() error {
	return nil
}

func (po *ProtocolOverlay) Release() {
	// call the Done function
	po.Done()
}

func TestOverlayDone(t *testing.T) {
	defer log.AfterTest(t)

	log.TestOutput(testing.Verbose(), 4)
	// setup
	h1 := sda.NewLocalHost(2000)
	defer h1.Close()
	fn := func(n *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {
		ps := ProtocolOverlay{
			TreeNodeInstance: n,
		}
		return &ps, nil
	}
	el := sda.NewRoster([]*network.ServerIdentity{h1.ServerIdentity})
	h1.AddRoster(el)
	tree := el.GenerateBinaryTree()
	h1.AddTree(tree)
	sda.ProtocolRegisterName("ProtocolOverlay", fn)
	p, err := h1.CreateProtocol("ProtocolOverlay", tree)
	if err != nil {
		t.Fatal("error starting new node", err)
	}
	po := p.(*ProtocolOverlay)
	// release the resources
	var count int
	po.OnDoneCallback(func() bool {
		count++
		if count >= 2 {
			return true
		}
		return false
	})
	po.Release()
	overlay := h1.Overlay()
	if _, ok := overlay.TokenToNode(po.Token()); !ok {
		t.Fatal("Node should exists after first call Done()")
	}
	po.Release()
	if _, ok := overlay.TokenToNode(po.Token()); ok {
		t.Fatal("Node should NOT exists after call Done()")
	}
}
