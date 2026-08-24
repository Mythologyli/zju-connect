package ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
)

// TCPing ...
type TCPing struct {
	target *Target
	done   chan struct{}
	stop   chan struct{}
	result *Result
	dial   client.DialContextFunc
	keyLog io.Writer

	startOnce sync.Once
	stopOnce  sync.Once
	runMu     sync.Mutex
	cancelRun context.CancelFunc
}

// SetDialContext overrides the system dialer used by TCPing.
func (tcping *TCPing) SetDialContext(dial client.DialContextFunc) {
	tcping.dial = dial
}

// SetKeyLogWriter records probe TLS secrets in NSS key log format.
func (tcping *TCPing) SetKeyLogWriter(writer io.Writer) {
	tcping.keyLog = writer
}

var _ Pinger = (*TCPing)(nil)

// NewTCPing return a new TCPing
func NewTCPing() *TCPing {
	return &TCPing{
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}
}

// SetTarget set target for TCPing
func (tcping *TCPing) SetTarget(target *Target) {
	tcping.target = target
	if tcping.result == nil {
		tcping.result = &Result{Target: target}
	}
}

// Result return the result
func (tcping *TCPing) Result() *Result {
	return tcping.result
}

// Start preserves the historical background-context API.
func (tcping *TCPing) Start() <-chan struct{} {
	return tcping.StartContext(context.Background())
}

// StartContext starts the probe loop with caller-owned cancellation.
func (tcping *TCPing) StartContext(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		ctx = context.Background()
	}
	tcping.startOnce.Do(func() {
		runCtx, cancelRun := context.WithCancel(ctx)
		tcping.runMu.Lock()
		tcping.cancelRun = cancelRun
		tcping.runMu.Unlock()
		go func() {
			defer close(tcping.done)
			defer func() {
				cancelRun()
				tcping.runMu.Lock()
				tcping.cancelRun = nil
				tcping.runMu.Unlock()
			}()
			tcping.run(runCtx)
		}()
	})
	return tcping.done
}

func (tcping *TCPing) run(ctx context.Context) {
	if tcping.target == nil || tcping.result == nil {
		return
	}
	ticker := time.NewTicker(tcping.target.Interval)
	defer ticker.Stop()
	for {
		if tcping.target.Counter != 0 && tcping.result.Counter >= tcping.target.Counter {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tcping.stop:
			return
		case <-ticker.C:
		}

		duration, remoteAddr, err := tcping.pingContext(ctx)
		if ctx.Err() != nil {
			return
		}
		tcping.result.Counter++
		if err != nil {
			log.DebugPrintf("Ping %s - failed: %s\n", tcping.target, err)
			continue
		}
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
}

// Stop interrupts the current probe, including an in-flight dial or TLS handshake.
func (tcping *TCPing) Stop() {
	tcping.stopOnce.Do(func() {
		close(tcping.stop)
	})
	tcping.runMu.Lock()
	cancelRun := tcping.cancelRun
	tcping.runMu.Unlock()
	if cancelRun != nil {
		cancelRun()
	}
}

func (tcping *TCPing) pingContext(parent context.Context) (time.Duration, net.Addr, error) {
	ctx, cancel := context.WithTimeout(parent, tcping.target.Timeout)
	defer cancel()

	startedAt := time.Now()
	dial := (&net.Dialer{}).DialContext
	if tcping.dial != nil {
		dial = tcping.dial
	}
	conn, err := dial(ctx, "tcp", fmt.Sprintf("%s:%d", tcping.target.Host, tcping.target.Port))
	if err != nil {
		return 0, nil, contextError(ctx, err)
	}
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         tcping.target.Host,
		InsecureSkipVerify: true,
		KeyLogWriter:       tcping.keyLog,
	})
	stopClose := context.AfterFunc(ctx, func() {
		_ = tlsConn.Close()
	})
	defer stopClose()
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, remoteAddr, contextError(ctx, err)
	}
	return time.Since(startedAt), remoteAddr, nil
}

func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
