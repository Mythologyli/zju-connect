package zcdns

import (
	"context"

	"github.com/miekg/dns"
)

type LocalServer interface {
	HandleDnsMsg(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}
