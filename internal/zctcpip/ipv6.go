package zctcpip

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	IPv6HeaderSize      = 40
	IPv6PacketMinLength = IPv6HeaderSize
	IPv6Version         = 6
)

type IPv6Packet []byte

func (p IPv6Packet) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(p[4:6])
}

func (p IPv6Packet) TotalLen() int {
	return IPv6HeaderSize + int(p.PayloadLength())
}

func (p IPv6Packet) NextHeader() IPProtocol {
	return p[6]
}

func (p IPv6Packet) SourceIP() net.IP {
	return append(net.IP(nil), p[8:24]...)
}

func (p IPv6Packet) DestinationIP() net.IP {
	return append(net.IP(nil), p[24:40]...)
}

func (p IPv6Packet) Valid() bool {
	return len(p) >= IPv6HeaderSize && p[0]>>4 == IPv6Version && p.TotalLen() <= len(p)
}

func (p IPv6Packet) TransportPayload() (IPProtocol, []byte, error) {
	if !p.Valid() {
		return 0, nil, ErrInvalidLength
	}
	next := p.NextHeader()
	offset := IPv6HeaderSize
	total := p.TotalLen()
	for {
		switch next {
		case 0, 43, 60: // Hop-by-hop, routing, and destination options.
			if offset+2 > total {
				return 0, nil, ErrInvalidLength
			}
			headerLen := (int(p[offset+1]) + 1) * 8
			if offset+headerLen > total {
				return 0, nil, ErrInvalidLength
			}
			next = p[offset]
			offset += headerLen
		case 44: // Fragment header.
			if offset+8 > total {
				return 0, nil, ErrInvalidLength
			}
			if binary.BigEndian.Uint16(p[offset+2:offset+4])&0xfff8 != 0 {
				return 0, nil, fmt.Errorf("non-initial IPv6 fragment has no transport header")
			}
			next = p[offset]
			offset += 8
		case 51: // Authentication header.
			if offset+2 > total {
				return 0, nil, ErrInvalidLength
			}
			headerLen := (int(p[offset+1]) + 2) * 4
			if offset+headerLen > total {
				return 0, nil, ErrInvalidLength
			}
			next = p[offset]
			offset += headerLen
		case 59:
			return next, nil, nil
		case 50:
			return 0, nil, fmt.Errorf("IPv6 ESP payload is not inspectable")
		default:
			return next, p[offset:total], nil
		}
	}
}
