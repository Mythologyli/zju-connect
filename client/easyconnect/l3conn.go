package easyconnect

import (
	"io"
	"sync"

	"github.com/mythologyli/zju-connect/log"
)

type L3Conn struct {
	easyConnectClient *Client

	sendConn     io.WriteCloser
	sendLock     sync.Mutex
	sendErrCount int

	recvConn     io.ReadCloser
	recvLock     sync.Mutex
	recvErrCount int
}

// try best to read, if return err!=nil, please panic
func (c *L3Conn) Read(p []byte) (n int, err error) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	for n, err = c.recvConn.Read(p); err != nil && c.recvErrCount < 5; {

		log.Printf("Error occurred while receiving, retrying: %v", err)

		// Do handshake again and create a new recvConn
		_ = c.recvConn.Close()
		c.recvConn, err = c.easyConnectClient.RecvConn()
		if err != nil {
			return 0, err
		}
		c.recvErrCount++
		if c.recvErrCount >= 5 {
			return 0, err
		}
	}
	return
}

// try best to write, if return err!=nil, please panic
func (c *L3Conn) Write(p []byte) (n int, err error) {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()
	for n, err = c.sendConn.Write(p); err != nil && c.sendErrCount < 5; {
		log.Printf("Error occurred while sending, retrying: %v", err)

		// Do handshake again and create a new sendConn
		_ = c.sendConn.Close()
		c.sendConn, err = c.easyConnectClient.SendConn()
		if err != nil {
			return 0, err
		}
		c.sendErrCount++
		if c.sendErrCount >= 5 {
			return 0, err
		}
	}
	return
}

func (c *L3Conn) Close() error {
	if c.sendConn != nil {
		_ = c.sendConn.Close()
	}
	if c.recvConn != nil {
		_ = c.recvConn.Close()
	}
	return nil
}

func (c *Client) NewL3Conn() (io.ReadWriteCloser, error) {
	conn := &L3Conn{
		easyConnectClient: c,
		sendErrCount:      0,
		recvErrCount:      0,
	}

	var err error
	conn.sendConn, err = c.SendConn()
	if err != nil {
		log.Printf("Error occurred while creating sendConn: %v", err)
		return nil, err
	}

	conn.recvConn, err = c.RecvConn()
	if err != nil {
		log.Printf("Error occurred while creating recvConn: %v", err)
		return nil, err
	}
	return conn, nil
}
