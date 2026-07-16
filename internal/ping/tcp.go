package ping

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

// TCPing ...
type TCPing struct {
	target *Target
	done   chan struct{}
	result *Result
	dial   func(context.Context, string, string) (net.Conn, error)
}

// SetDialContext overrides the system dialer used by TCPing.
func (tcping *TCPing) SetDialContext(dial func(context.Context, string, string) (net.Conn, error)) {
	tcping.dial = dial
}

var _ Pinger = (*TCPing)(nil)

// NewTCPing return a new TCPing
func NewTCPing() *TCPing {
	tcping := TCPing{
		done: make(chan struct{}),
	}
	return &tcping
}

// SetTarget set target for TCPing
func (tcping *TCPing) SetTarget(target *Target) {
	tcping.target = target
	if tcping.result == nil {
		tcping.result = &Result{Target: target}
	}
}

// Result return the result
func (tcping TCPing) Result() *Result {
	return tcping.result
}

// Start a tcping
func (tcping TCPing) Start() <-chan struct{} {
	go func() {
		t := time.NewTicker(tcping.target.Interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if tcping.result.Counter >= tcping.target.Counter && tcping.target.Counter != 0 {
					tcping.Stop()
					return
				}
				duration, remoteAddr, err := tcping.ping()
				tcping.result.Counter++

				if err != nil {
					log.DebugPrintf("Ping %s - failed: %s\n", tcping.target, err)
				} else {
					log.DebugPrintf("Ping %s(%s) - Connected - time=%s\n", tcping.target, remoteAddr, duration)

					if tcping.result.MinDuration == 0 {
						tcping.result.MinDuration = duration
					}
					if tcping.result.MaxDuration == 0 {
						tcping.result.MaxDuration = duration
					}
					tcping.result.SuccessCounter++
					if duration > tcping.result.MaxDuration {
						tcping.result.MaxDuration = duration
					} else if duration < tcping.result.MinDuration {
						tcping.result.MinDuration = duration
					}
					tcping.result.TotalDuration += duration
				}
			case <-tcping.done:
				return
			}
		}
	}()
	return tcping.done
}

// Stop the tcping
func (tcping *TCPing) Stop() {
	tcping.done <- struct{}{}
}

func (tcping TCPing) ping() (time.Duration, net.Addr, error) {
	var remoteAddr net.Addr
	duration, errIfce := timeIt(func() interface{} {
		ctx, cancel := context.WithTimeout(context.Background(), tcping.target.Timeout)
		defer cancel()
		dial := (&net.Dialer{}).DialContext
		if tcping.dial != nil {
			dial = tcping.dial
		}
		conn, err := dial(ctx, "tcp", fmt.Sprintf("%s:%d", tcping.target.Host, tcping.target.Port))
		if err != nil {
			return err
		}
		remoteAddr = conn.RemoteAddr()
		conn.Close()
		return nil
	})
	if errIfce != nil {
		err := errIfce.(error)
		return 0, remoteAddr, err
	}
	return time.Duration(duration), remoteAddr, nil
}
