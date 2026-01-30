package zcdns

import (
	"context"

	"net"

	"github.com/miekg/dns"
)

type LocalServer interface {
	HandleDnsMsg(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	CheckDnsHijack(dstIP net.IP) bool
}
