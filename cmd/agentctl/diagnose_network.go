package main

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/ultherego/flotestro/internal/ctl"
)

// The network checks are the ones the tool of the relay runs as well: the
// clock, the names and the handshakes are questions about the path to the
// panel, not about which component asks.

// network wires the shared checks to the dialers of this diagnosis.
func (d diagnostics) network() ctl.Network {
	return ctl.Network{Now: d.Now, Timeout: d.Timeout, Dial: d.Dial, LookupHost: d.LookupHost}
}

// checkClock compares the clock of the host with the one of the endpoint.
func (d diagnostics) checkClock(ctx context.Context, target endpoint, pool *x509.CertPool) Check {
	return d.network().CheckClock(ctx, target, pool)
}

// clockCheck judges the offset from the Date header alone.
func clockCheck(local time.Time, date string) Check { return ctl.ClockCheck(local, date) }

// checkDNS resolves the name of the endpoint.
func (d diagnostics) checkDNS(ctx context.Context, target endpoint) Check {
	return d.network().CheckDNS(ctx, target)
}

// checkTLS opens the connection and completes the handshake.
func (d diagnostics) checkTLS(ctx context.Context, target endpoint, pool *x509.CertPool,
	poolErr error, resolved bool) Check {
	return d.network().CheckTLS(ctx, target, pool, poolErr, resolved)
}

// tlsError maps a handshake error onto a stable code and a detail that says
// what to fix.
func tlsError(host string, err error) (code, detail string) { return ctl.TLSError(host, err) }
