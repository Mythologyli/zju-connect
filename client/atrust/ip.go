package atrust

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

func (c *Client) getIP() error {
	addr := c.BestNodes[c.MajorNodeGroup]
	if addr == "" {
		for _, node := range c.BestNodes {
			addr = node
			break
		}
	}
	if addr == "" {
		return fmt.Errorf("no reachable node for ip request")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	msg := []byte{0x05, 0x01, 0xd0, 0x53, 0x00, 0x00, 0x53}
	msg = append(msg, []byte(fmt.Sprintf(`{"sid":"%s"}`, c.SID))...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	msg = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	for {
		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			return err
		}

		header := make([]byte, 2)
		_, err = io.ReadFull(conn, header)
		if err != nil {
			return err
		}
		if header[0] == 0x53 && header[1] == 0x00 {
			lengthBytes := make([]byte, 2)
			_, err = io.ReadFull(conn, lengthBytes)
			if err != nil {
				return err
			}
			length := binary.BigEndian.Uint16(lengthBytes)
			data := make([]byte, length)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return err
			}

			if !strings.Contains(string(data), "OK") {
				return fmt.Errorf("failed to connect to the server: %s", string(data))
			}
		} else if header[0] == 0x05 && header[1] == 0x00 {
			data := make([]byte, 6)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return err
			}
			if data[0] != 0x00 || data[1] != 0x01 {
				return fmt.Errorf("unexpected response: %x", data)
			}

			c.ip = net.IPv4(data[2], data[3], data[4], data[5])
			log.Printf("Received IP: %s", c.ip.String())
			return nil
		}
	}
}
