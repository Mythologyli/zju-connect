package zcdns

import (
	"context"

	"github.com/miekg/dns"
	"net"
)

type LocalServer interface {
	HandleDnsMsg(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	CheckDnsHijack(dstIP net.IP) bool
}
