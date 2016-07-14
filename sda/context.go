package sda

import "github.com/dedis/cothority/network"

// Context is the interface that is given to a Service
type Context struct {
	overlay *Overlay
	host    *Host
	servID  ServiceID
}

// defaultContext is the implementation of the Context interface. It is
// instantiated for each Service.

func newContext(h *Host, o *Overlay, servID ServiceID) *Context {
	return &Context{
		overlay: o,
		host:    h,
		servID:  servID,
	}
}

// NewTreeNodeInstance is a Context method
func (c *Context) NewTreeNodeInstance(t *Tree, tn *TreeNode, protoName string) *TreeNodeInstance {
	return c.overlay.NewTreeNodeInstanceFromService(t, tn, ProtocolNameToID(protoName), c.servID)
}

// SendRaw sends a message to the entity
func (c *Context) SendRaw(e *network.ServerIdentity, msg interface{}) error {
	return c.host.SendRaw(e, msg)
}

// ServerIdentity returns the entity the service uses
func (c *Context) ServerIdentity() *network.ServerIdentity {
	return c.host.ServerIdentity
}

// ServiceID returns the service-id
func (c *Context) ServiceID() ServiceID {
	return c.servID
}

// CreateProtocolService makes a TreeNodeInstance from the root-node of the tree and
// prepares for a 'name'-protocol. The ProtocolInstance has to be added later.
func (c *Context) CreateProtocolService(t *Tree, name string) (ProtocolInstance, error) {
	pi, err := c.overlay.CreateProtocolService(c.servID, t, name)
	return pi, err
}

// CreateProtocolSDA is like CreateProtocolService but doesn't bind a service to it,
// so it will be handled automatically by the SDA.
func (c *Context) CreateProtocolSDA(t *Tree, name string) (ProtocolInstance, error) {
	pi, err := c.overlay.CreateProtocolSDA(t, name)
	return pi, err
}

// RegisterProtocolInstance registers a new instance of a protocol using overlay
func (c *Context) RegisterProtocolInstance(pi ProtocolInstance) error {
	return c.overlay.RegisterProtocolInstance(pi)
}
