package easyconnect

import (
	"github.com/mythologyli/zju-connect/log"
	"io"
	"sync"
)

type RvpnConn struct {
	easyConnectClient *Client

	sendConn     io.WriteCloser
	sendLock     sync.Mutex
	sendErrCount int

	recvConn     io.ReadCloser
	recvLock     sync.Mutex
	recvErrCount int
}

// try best to read, if return err!=nil, please panic
func (r *RvpnConn) Read(p []byte) (n int, err error) {
	r.recvLock.Lock()
	defer r.recvLock.Unlock()
	for n, err = r.recvConn.Read(p); err != nil && r.recvErrCount < 5; {

		log.Printf("Error occurred while receiving, retrying: %v", err)

		// Do handshake again and create a new recvConn
		_ = r.recvConn.Close()
		r.recvConn, err = r.easyConnectClient.RecvConn()
		if err != nil {
			return 0, err
		}
		r.recvErrCount++
		if r.recvErrCount >= 5 {
			return 0, err
		}
	}
	return
}

// try best to write, if return err!=nil, please panic
func (r *RvpnConn) Write(p []byte) (n int, err error) {
	r.sendLock.Lock()
	defer r.sendLock.Unlock()
	for n, err = r.sendConn.Write(p); err != nil && r.sendErrCount < 5; {
		log.Printf("Error occurred while sending, retrying: %v", err)

		// Do handshake again and create a new sendConn
		_ = r.sendConn.Close()
		r.sendConn, err = r.easyConnectClient.SendConn()
		if err != nil {
			return 0, err
		}
		r.sendErrCount++
		if r.sendErrCount >= 5 {
			return 0, err
		}
	}
	return
}

func (r *RvpnConn) Close() error {
	if r.sendConn != nil {
		_ = r.sendConn.Close()
	}
	if r.recvConn != nil {
		_ = r.recvConn.Close()
	}
	return nil
}

func NewRvpnConn(ec *Client) (*RvpnConn, error) {
	c := &RvpnConn{
		easyConnectClient: ec,
		sendErrCount:      0,
		recvErrCount:      0,
	}

	var err error
	c.sendConn, err = ec.SendConn()
	if err != nil {
		log.Printf("Error occurred while creating sendConn: %v", err)
		return nil, err
	}

	c.recvConn, err = ec.RecvConn()
	if err != nil {
		log.Printf("Error occurred while creating recvConn: %v", err)
		return nil, err
	}
	return c, nil
}
