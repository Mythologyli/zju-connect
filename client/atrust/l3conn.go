package atrust

import (
	"io"
	"sync"
)

type L3Conn struct {
	l3Tunnel *L3Tunnel
	sendLock sync.Mutex
	recvLock sync.Mutex
}

// try best to read, if return err!=nil, please panic
func (c *L3Conn) Read(p []byte) (n int, err error) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	var data []byte
	var ok bool
	data, ok = <-c.l3Tunnel.dataChan
	if !ok {
		return 0, io.EOF
	}
	n = copy(p, data)
	return
}

// try best to write, if return err!=nil, please panic
func (c *L3Conn) Write(p []byte) (n int, err error) {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()
	n = len(p)
	err = c.l3Tunnel.processIPV4(p)
	return n, err
}

func (c *L3Conn) Close() error {
	// TODO: implement close logic
	return nil
}

func (t *L3Tunnel) NewL3Conn() (io.ReadWriteCloser, error) {
	conn := &L3Conn{
		l3Tunnel: t,
	}

	return conn, nil
}
