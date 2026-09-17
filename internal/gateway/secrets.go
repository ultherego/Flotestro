package gateway

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/relayproof"
	"github.com/ultherego/flotestro/internal/secrets"
)

// SecretIssuing describes what the gateway has to be able to do with the
// secret store.
//
// An interface rather than a concrete store: the gateway is to release a value
// on the basis of a lease rather than know how the secrets are kept.
type SecretIssuing interface {
	Redeem(ctx context.Context, jobID, hostID, name string, version int) ([]byte, int, error)
}

// SecretLeases describes the leases issued for a job.
type SecretLeases interface {
	Leases(ctx context.Context, jobID string) ([]secrets.Lease, error)
	// Revoke closes the leases of a task that has finished.
	Revoke(ctx context.Context, jobID string) error
}

// SetSecrets connects the secret store.
func (s *AgentService) SetSecrets(store SecretIssuing) { s.secrets = store }

// SetSecretLeases connects the reading of the leases.
func (s *AgentService) SetSecretLeases(store SecretLeases) { s.leases = store }

// FetchSecret releases the value of a secret for the duration of one job.
//
// The value does not travel in the envelope of the job. The host gets a
// reference and reaches for the content only when it starts the operation -
// and the release is possible only when the panel itself issued a lease: for
// this host, for this job and for a short moment. A lease is one-time.
//
// The identity of the host comes from the client certificate, never from the
// content of the job: otherwise knowing somebody else's attempt identifier
// would be enough.
//
// Through a relay the certificate is the relay's, so the request carries
// the host's own proof - the identity envelope - and a one-time X25519 key
// signed by the host key; the value then goes back sealed to that key and
// the relay, which forwards the call without spooling it, sees routing
// metadata and cipher text. A relayed fetch without the proof is refused
// under every mode: it was never possible without one.
func (s *AgentService) FetchSecret(ctx context.Context,
	req *connect.Request[agentv1.FetchSecretRequest],
) (*connect.Response[agentv1.FetchSecretResponse], error) {
	who, _, err := s.identifyCaller(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	hostID := who.HostID
	// A direct caller was checked against the record of the certificate
	// it presented, the way Connect checks it: a revoked or unknown one,
	// or one of a host that is no longer active, fetches nothing - even
	// with a lease issued before the revocation. A relayed caller is
	// checked against the certificate its envelope names, here.
	var sealTo []byte
	if who.RelayID != "" {
		verified, problem := s.verifySecretEnvelope(ctx, who, req.Msg)
		if problem != nil {
			return nil, problem
		}
		s.learnPublicKey(ctx, hostID, verified)
		sealTo = req.Msg.GetEphemeralPublicKey()
	}
	if s.secrets == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("this panel has no secret store"))
	}

	name := req.Msg.GetSecretName()
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the name of the secret is missing"))
	}
	// A host that is not active does not get secrets - also when the lease was
	// issued before the quarantine. A secret released to a machine we have
	// just stopped trusting is exactly what a quarantine is to prevent.
	host, err := s.hosts.Get(ctx, hostID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if host == nil || !hosts.Active(host.LifecycleState) {
		s.refuseSecret(ctx, hostID, name, "lifecycle")
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("the host is not active"))
	}
	// The agent knows the identifier of the attempt; the lease is issued for
	// the operation.
	jobID, _ := s.attemptContext(ctx, req.Msg.GetTaskId(), hostID)
	if jobID == "" {
		s.refuseSecret(ctx, hostID, name, "unknown_task")
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("an unknown job"))
	}

	value, version, err := s.secrets.Redeem(ctx, jobID, hostID, name, int(req.Msg.GetSecretVersion()))
	switch {
	case errors.Is(err, secrets.ErrNoLease):
		s.refuseSecret(ctx, hostID, name, "no_lease")
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrDestroyed),
		errors.Is(err, secrets.ErrRetired):
		s.refuseSecret(ctx, hostID, name, "unavailable")
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// The audit notes the fact of the release: who, what, which version and
	// within which operation, and whether it went out sealed. The value is
	// neither here nor in any other record.
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "secret.fetch", TargetType: "secret", TargetID: name,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"job_id": jobID, "host_id": hostID, "version": version,
			"size_bytes": len(value), "relay_id": nullableRelay(who.RelayID),
			"sealed": sealTo != nil,
		},
	})
	if sealTo == nil {
		return connect.NewResponse(&agentv1.FetchSecretResponse{
			Value: value, Version: uint32(version), Sha256: secrets.Fingerprint(value),
		}), nil
	}
	// Sealed to the host's one-time key under the lease as associated data:
	// the plaintext leaves this process only inside the cipher text, and
	// the digest stays out - the cipher authenticates the content, and a
	// digest of a short value in a relay's journal would be a hint.
	sealed, nonce, serverPublic, err := relayproof.Seal(sealTo, value,
		relayproof.SecretAAD(req.Msg.GetTaskId(), name, uint32(version)))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&agentv1.FetchSecretResponse{
		Version:         uint32(version),
		SealedValue:     sealed,
		SealedNonce:     nonce,
		ServerPublicKey: serverPublic,
		Sealing:         relayproof.Sealing,
	}), nil
}

// verifySecretEnvelope checks the host's proof on a relayed fetch: the
// envelope over the request with its identity cleared, then the one-time
// key under the certificate the envelope named, for this task and this
// secret.
func (s *AgentService) verifySecretEnvelope(ctx context.Context, who peer,
	request *agentv1.FetchSecretRequest) (*Verified, error) {
	hostID := who.HostID
	if request.GetIdentity() == nil || len(request.GetEphemeralPublicKey()) == 0 {
		s.refused(ctx, hostID, hosts.RefusalBlockedUpgradeRequired,
			"a secret fetch through relay "+who.RelayID+" without the host's proof ("+relayproof.Capability+" "+
				relayproof.Feature+"); upgrade the agent")
		s.refuseSecret(ctx, hostID, request.GetSecretName(), hosts.RefusalBlockedUpgradeRequired)
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("a secret fetch through a relay needs the host's proof"))
	}
	body := proto.Clone(request).(*agentv1.FetchSecretRequest)
	body.Identity = nil
	verified, err := s.envelopes.VerifyRequest(ctx, who.Relay, request.GetIdentity(), relayproof.KindFetchSecret, body)
	if err != nil {
		if refusal := RelayRefusalOf(err); refusal != nil {
			s.refuseSecret(ctx, hostID, request.GetSecretName(), refusal.Code)
		}
		return nil, s.refuseEnvelope(ctx, hostID, err)
	}
	if err := relayproof.VerifyEphemeralKey(verified.PublicKey, request.GetTaskId(), request.GetSecretName(),
		request.GetEphemeralPublicKey(), request.GetEphemeralKeySignature()); err != nil {
		s.refused(ctx, hostID, hosts.RefusalRelayHostSignatureInvalid,
			"the one-time key of the secret fetch is not signed by certificate "+verified.Serial+": "+err.Error())
		s.refuseSecret(ctx, hostID, request.GetSecretName(), hosts.RefusalRelayHostSignatureInvalid)
		metrics.RelayEnvelopeRefusal.Inc(hosts.RefusalRelayHostSignatureInvalid)
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the one-time key is not signed by the host"))
	}
	return verified, nil
}

// refuseSecret records a refusal together with its reason.
func (s *AgentService) refuseSecret(ctx context.Context, hostID, name, reason string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "secret.fetch", TargetType: "secret", TargetID: name,
		Outcome: audit.OutcomeDenied,
		Detail:  map[string]any{"host_id": hostID, "reason": reason},
	})
	s.log.Warn("the release of the secret was refused", "host_id", hostID, "secret", name, "reason", reason)
}
