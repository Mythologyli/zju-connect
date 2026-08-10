package atrust

import (
	"io"
	"net"
	"sync"
)

type L3Conn struct {
	l3Tunnel    *L3Tunnel
	writePacket func([]byte) error
	recvLock    sync.Mutex
	closeCh     chan struct{}
	closeOnce   sync.Once
}

// try best to read, if return err!=nil, please panic
func (c *L3Conn) Read(p []byte) (n int, err error) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	select {
	case data := <-c.l3Tunnel.dataChan:
		n = copy(p, data)
		return n, nil
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-c.l3Tunnel.closeCh:
		return 0, io.EOF
	}
}

// try best to write, if return err!=nil, please panic
func (c *L3Conn) Write(p []byte) (n int, err error) {
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-c.l3Tunnel.closeCh:
		return 0, net.ErrClosed
	default:
	}
	n = len(p)
	if c.writePacket != nil {
		err = c.writePacket(p)
	} else {
		err = c.l3Tunnel.processIPV4(p)
	}
	return n, err
}

func (c *L3Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (t *L3Tunnel) NewL3Conn() (io.ReadWriteCloser, error) {
	conn := &L3Conn{
		l3Tunnel: t,
		closeCh:  make(chan struct{}),
	}

	return conn, nil
}
