package gateway

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/pki"
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
func (s *AgentService) FetchSecret(ctx context.Context,
	req *connect.Request[agentv1.FetchSecretRequest],
) (*connect.Response[agentv1.FetchSecretResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
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
	jobID, _ := s.attemptContext(ctx, req.Msg.GetTaskId())
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
	// within which operation. The value is neither here nor in any other
	// record.
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "secret.fetch", TargetType: "secret", TargetID: name,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"job_id": jobID, "host_id": hostID, "version": version,
			"size_bytes": len(value),
		},
	})
	return connect.NewResponse(&agentv1.FetchSecretResponse{
		Value: value, Version: uint32(version), Sha256: secrets.Fingerprint(value),
	}), nil
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
