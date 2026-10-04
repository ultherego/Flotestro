package gateway

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/relayproof"
	"github.com/ultherego/flotestro/internal/secrets"
)

// SecretIssuing describes what the gateway has to be able to do with the
// secret store.
type SecretIssuing interface {
	// Redeem spends the lease and returns the value. The record hook runs in the
	// same transaction, so the trail of the release commits with the lease or the
	// secret does not go out.
	Redeem(ctx context.Context, jobID, hostID, name string, version int,
		record func(tx pgx.Tx, released int) error) ([]byte, int, error)
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

// FetchSecret releases the value of a secret for the duration of one job. The
// value does not travel in the envelope of the job.
func (s *AgentService) FetchSecret(ctx context.Context,
	req *connect.Request[agentv1.FetchSecretRequest],
) (*connect.Response[agentv1.FetchSecretResponse], error) {
	who, _, err := s.identifyCaller(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	hostID := who.HostID
	// A direct caller was already checked against the record of the certificate
	// it presented: a revoked or unknown one fetches nothing.
	// A host that offers a one-time key is answered sealed, relay or no relay:
	// the agent refuses an answer in the clear to a fetch it offered a key for,
	// because an answer in the clear is one a carrier could have replaced.
	// Through a relay the key is first proved by the envelope; on a direct
	// connection the request arrived over the host's own authenticated channel,
	// which is what the certificate check above established.
	var sealTo []byte
	if who.RelayID != "" {
		verified, problem := s.verifySecretEnvelope(ctx, who, req.Msg)
		if problem != nil {
			return nil, problem
		}
		s.learnPublicKey(ctx, hostID, verified)
		sealTo = req.Msg.GetEphemeralPublicKey()
	} else if len(req.Msg.GetEphemeralPublicKey()) > 0 {
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
	// issued before the quarantine.
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

	// The trail of the release commits with the lease: no entry, no secret. The
	// version comes from the lease that was spent, so the entry is written from
	// inside the redemption.
	value, version, err := s.secrets.Redeem(ctx, jobID, hostID, name, int(req.Msg.GetSecretVersion()),
		func(tx pgx.Tx, released int) error {
			return s.audit.RecordTx(ctx, tx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: hostID,
				Action: "secret.fetch", TargetType: "secret", TargetID: name,
				Outcome: audit.OutcomeSuccess,
				Detail: map[string]any{
					"job_id": jobID, "host_id": hostID, "version": released,
					"relay_id": nullableRelay(who.RelayID), "sealed": sealTo != nil,
				},
			})
		})
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

	// The receipt: what the panel signed over the bytes it is releasing. The
	// helper refuses a write from a secret without one, because the capability
	// cannot carry the digest - version 0 means "whatever is current when the
	// task is delivered", so the consent was signed before the content was
	// known.
	receipt, err := s.secretReceipt(hostID, req.Msg.GetTaskId(), name, uint32(version), value)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if sealTo == nil {
		return connect.NewResponse(&agentv1.FetchSecretResponse{
			Value: value, Version: uint32(version), Sha256: secrets.Fingerprint(value),
			// Beside the value, because on a direct session the digest is
			// already in sha256 above: the receipt discloses nothing more.
			SecretReceipt: receipt,
		}), nil
	}
	marshalled, err := proto.Marshal(receipt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// Sealed to the host's one-time key under the lease as associated data: the
	// plaintext leaves this process inside the cipher text, without a digest.
	sealed, nonce, serverPublic, err := relayproof.Seal(sealTo, value,
		relayproof.SecretAAD(req.Msg.GetTaskId(), name, uint32(version)))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// The receipt is sealed too, and that is the whole reason it has its own
	// fields: sha256 above is deliberately empty on a sealed answer, because a
	// digest of a short secret in a relay's log would be a hint this protocol
	// does not give. A receipt in the clear would hand the relay exactly that.
	sealedReceipt, receiptNonce, receiptKey, err := relayproof.Seal(sealTo, marshalled,
		relayproof.SecretReceiptAAD(req.Msg.GetTaskId(), name, uint32(version)))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&agentv1.FetchSecretResponse{
		Version:                uint32(version),
		SealedValue:            sealed,
		SealedNonce:            nonce,
		ServerPublicKey:        serverPublic,
		Sealing:                relayproof.Sealing,
		SealedReceipt:          sealedReceipt,
		SealedReceiptNonce:     receiptNonce,
		SealedReceiptServerKey: receiptKey,
	}), nil
}

// secretReceipt signs the release of a secret's bytes. A panel without a
// helper signer issues none, and the helper then refuses the write - which is
// the right way round: a helper that writes a secret nobody vouched for is the
// hole this closes.
func (s *AgentService) secretReceipt(hostID, taskID, name string, version uint32,
	value []byte) (*helperv1.SecretReceipt, error) {
	if s.helperSigner == nil {
		return nil, errors.New("this panel has no helper signing key, so it cannot vouch for the bytes of a secret")
	}
	return s.helperSigner.IssueReceipt(helpercap.Release{
		HostID: hostID, TaskID: taskID, SecretName: name,
		Version: version, SHA256: secrets.Fingerprint(value),
	})
}

// verifySecretEnvelope checks the host's proof on a relayed fetch: the
// envelope over the request with its identity cleared, then the one-time key
// under the certificate the envelope named, for this task and this secret.
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
