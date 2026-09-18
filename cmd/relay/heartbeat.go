package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/ctl"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/relay"
)

// heartbeatInterval says how often the relay reports itself to the centre.
//
// The sessions of the agents mark the relay as seen only when they open,
// and a site that works steadily opens none for hours. Without a heartbeat
// of its own such a relay would look silent to the panel exactly when it
// works best. One call a minute is well inside the ten minutes after which
// the panel counts a relay as silent, and costs the centre nothing.
const heartbeatInterval = time.Minute

// heartbeat reports the state of the relay to the centre and to the state
// file on the machine.
//
// The call carries the fill of the buffer: the panel is the place where the
// operator looks for a site whose results do not arrive, and a growing
// buffer is the first sign of that. The answer carries how many sessions
// the centre sees through this relay; a divergence from the local count
// means a session hanging on one side, which neither side can see alone.
func heartbeat(ctx context.Context, proxy *relay.Relay, live *relay.Live,
	state *ctl.RelayStateWriter, log *slog.Logger) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		sendHeartbeat(ctx, proxy, live, state, log)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sendHeartbeat makes one report.
func sendHeartbeat(ctx context.Context, proxy *relay.Relay, live *relay.Live,
	state *ctl.RelayStateWriter, log *slog.Logger) {
	sessions, buffer, upstreamOK := proxy.Stats()
	now := time.Now().UTC()
	// The buffer is observed before the call: the state file is to show
	// the fill even when the centre does not answer - that is when the
	// operator on the site looks at it.
	state.Update(func(s *ctl.RelayState) {
		s.Gateway = proxy.Gateway()
		s.Sessions = sessions
		s.BufferBytes = int64(buffer.Bytes)
		s.BufferMaxBytes = int64(buffer.MaxBytes)
		s.BufferedItems = buffer.Messages
		s.BufferDropped = int64(buffer.Dropped)
		s.UpstreamOK = upstreamOK
		switch {
		case buffer.Messages == 0:
			s.BufferingSince = nil
		case s.BufferingSince == nil:
			s.BufferingSince = &now
		}
		s.CertificateNotAfter = live.Current().NotAfter
	})

	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request := &agentv1.RelayPingRequest{
		Build:              &agentv1.AgentBuild{AgentVersion: version},
		BufferBytes:        uint64(buffer.Bytes),
		BufferedItems:      uint32(buffer.Messages),
		BufferMaxBytes:     uint64(buffer.MaxBytes),
		BufferDroppedTotal: uint64(buffer.Dropped),
		Sessions:           uint32(sessions),
		// The panel reads a restart of the relay off a change of the
		// instance, and an outage off the state of the link. Neither can
		// be recovered from the numbers alone: the drop counter starts
		// again with the process, and a full buffer looks the same whether
		// the link is down or the centre is slow.
		InstanceId:      proxy.InstanceID(),
		UpstreamState:   proxy.UpstreamState(),
		SpoolBytesLimit: uint64(buffer.MaxBytes),
	}
	response, err := relayCentre(live.Current(), proxy.Gateway()).Ping(callCtx, connect.NewRequest(request))
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		state.Update(func(s *ctl.RelayState) {
			s.LastUpstreamError = err.Error()
			s.LastUpstreamErrorAt = &now
		})
		log.Warn("the heartbeat did not reach the centre", "gateway", proxy.Gateway(), "err", err)
		return
	}
	centreSessions := int(response.Msg.GetSessions())
	state.Update(func(s *ctl.RelayState) {
		s.LastUpstreamAt = &now
		s.LastUpstreamError = ""
		s.LastUpstreamErrorAt = nil
		s.CentreSessions = &centreSessions
	})
	if centreSessions != sessions {
		log.Info("the centre counts the sessions of this relay differently",
			"local", sessions, "centre", centreSessions)
	}
}

// relayCentre assembles the client of the relay service in the centre with
// the current identity.
//
// Built for every call rather than once: the certificate changes at a
// renewal, and the heartbeat is to go with the one the panel recognises the
// relay by.
func relayCentre(identity relay.Identity, gateway string) agentv1connect.RelayServiceClient {
	return agentv1connect.NewRelayServiceClient(
		&http.Client{
			Timeout: 30 * time.Second,
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{identity.Certificate},
					RootCAs:      identity.CAPool,
					MinVersion:   tls.VersionTLS13,
				},
			},
		},
		gateway,
	)
}
