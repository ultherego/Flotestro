package gateway

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/relayproof"
)

// RelayPeer is what the gateway established about a relayed call before it
// reads the envelope: the relay from its handshake and its record, the host
// the relay named, and the certificate the relay presented as the host's.
type RelayPeer struct {
	RelayID     string
	Site        string
	Environment string
	Revoked     bool
	HostID      string
	// HostCertificate is the certificate the relay saw in its own handshake
	// with the host, nil for a relay from before it sent it. It is not
	// trusted for anything by itself: the gateway takes its key only once
	// the fingerprint on record confirms it is the issued certificate.
	HostCertificate *x509.Certificate
}

// RelayRefusal is a typed refusal of an envelope: the code the host record
// and the trail carry, and the detail for the operator.
type RelayRefusal struct {
	Code   string
	Detail string
	// Redelivery marks a relay_sequence_replayed that is no replay at
	// all: the sequence is one the same session spent already, so the
	// message is one the panel consumed and the relay carried again
	// because the acknowledgement never reached it. The caller drops the
	// message, acknowledges it once more and writes nothing on the host.
	Redelivery bool
}

func (r *RelayRefusal) Error() string { return r.Code + ": " + r.Detail }

// RelayRefusalOf returns the refusal behind an error, or nil for an error
// of another kind - the database, the encoding.
func RelayRefusalOf(err error) *RelayRefusal {
	var refusal *RelayRefusal
	if errors.As(err, &refusal) {
		return refusal
	}
	return nil
}

// The records the verifier reads. Interfaces rather than the store, so a
// test drives the verifier with a certificate and a host of its own making
// and without a database.
type certificateRecords interface {
	LookupCertificateBySerial(ctx context.Context, serial string) (hosts.CertificateStatus, error)
}

type hostRecords interface {
	Get(ctx context.Context, hostID string) (*hosts.Host, error)
}

// sequenceRecords accepts a sequence of a session once and refuses it the
// second time. The last sequence the session accepted comes back with the
// refusal, so that the caller can tell a message consumed before - the
// relay carrying its spool again - from a number the session never took.
type sequenceRecords interface {
	Accept(ctx context.Context, hostID, sessionID string, sequence uint64) (accepted bool, last uint64, err error)
}

// RelayVerifier checks the inner identity envelope of a relayed message
// the way the security document lays it out: the relay is the one that
// forwarded the message, the certificate the envelope names is on record,
// live and the host's own, the host lies in the relay's site and
// environment, the payload is the one the host signed, the signature
// verifies under the certificate's key, and the sequence has not been
// seen.
type RelayVerifier struct {
	certs     certificateRecords
	hosts     hostRecords
	sequences sequenceRecords
	now       func() time.Time
}

// NewRelayVerifier assembles the verifier over the stores of the panel.
func NewRelayVerifier(certs certificateRecords, hostStore hostRecords, sequences sequenceRecords) *RelayVerifier {
	return &RelayVerifier{certs: certs, hosts: hostStore, sequences: sequences, now: time.Now}
}

// Verified is what a verified envelope established, for the caller to
// record: the certificate the host signed with, its key, and the key's DER
// when the record had none and the relay's certificate supplied it.
type Verified struct {
	Serial    string
	PublicKey crypto.PublicKey
	// LearnedKeyDER is set when the key came from the certificate the relay
	// presented rather than from the record; the caller writes it on the
	// record so the next session needs no relay to supply it.
	LearnedKeyDER []byte
}

// VerifyMessage checks the envelope of a message of the stream. The
// sequence is consumed: a message that verifies is one the session has
// accepted and will not accept again. There is no time window - a result
// the relay buffered for a day is still the host's result.
func (v *RelayVerifier) VerifyMessage(ctx context.Context, peer RelayPeer, msg *agentv1.AgentMessage) (*Verified, error) {
	kind, body, err := relayproof.Payload(msg)
	if err != nil {
		return nil, &RelayRefusal{Code: hosts.RefusalRelayEnvelopeInvalid, Detail: err.Error()}
	}
	return v.verify(ctx, peer, msg.GetEnvelope(), kind, body, true, 0)
}

// VerifyRequest checks the envelope of a unary request - a renewal, a
// secret fetch. The body is the request with its identity field cleared,
// as the agent signed it. No sequence is consumed: the challenge and the
// lease are one-time on their own, and a short window on issued_at keeps
// an old envelope from being replayed on either.
func (v *RelayVerifier) VerifyRequest(ctx context.Context, peer RelayPeer, envelope *agentv1.RelayedEnvelope,
	kind string, body proto.Message) (*Verified, error) {
	return v.verify(ctx, peer, envelope, kind, body, false, relayproof.UnaryWindow)
}

func (v *RelayVerifier) verify(ctx context.Context, peer RelayPeer, envelope *agentv1.RelayedEnvelope,
	kind string, body proto.Message, consumeSequence bool, window time.Duration) (*Verified, error) {
	invalid := func(detail string) error {
		return &RelayRefusal{Code: hosts.RefusalRelayEnvelopeInvalid, Detail: detail}
	}
	if envelope == nil {
		return nil, invalid("the message carries no identity envelope")
	}
	if err := relayproof.CheckShape(envelope); err != nil {
		return nil, invalid(err.Error())
	}
	// The relay first: the envelope names the relay the host connected to,
	// and it has to be the one that forwarded the message. A relay that
	// was revoked meanwhile forwards nothing, whatever the host signed.
	if peer.Revoked {
		return nil, invalid("the relay " + peer.RelayID + " was revoked")
	}
	if envelope.GetRelayId() != peer.RelayID {
		return nil, invalid("the envelope names relay " + envelope.GetRelayId() +
			", the message came through relay " + peer.RelayID)
	}
	if envelope.GetHostId() != peer.HostID {
		return nil, invalid("the envelope names host " + envelope.GetHostId() +
			", the relay named host " + peer.HostID)
	}
	if envelope.GetMessageKind() != kind {
		return nil, invalid("the envelope is signed for a " + envelope.GetMessageKind() +
			", the message is a " + kind)
	}

	// The certificate by serial: on record, live and the host's own, the
	// same checks a direct handshake goes through, with the same codes.
	certificate, err := v.certs.LookupCertificateBySerial(ctx, envelope.GetCertificateSerial())
	if err != nil {
		return nil, err
	}
	if code, detail := certificateStatusRefusal(certificate, peer.HostID, v.now()); code != "" {
		return nil, &RelayRefusal{Code: code, Detail: detail}
	}

	// The host in the relay's scope. The relay is checked against the
	// host again here rather than trusted from the handshake alone: the
	// envelope may name a session the relay buffered before the host moved.
	host, err := v.hosts.Get(ctx, peer.HostID)
	if err != nil {
		return nil, err
	}
	if host.Site != peer.Site {
		return nil, &RelayRefusal{Code: hosts.RefusalRelayScopeMismatch,
			Detail: "relay " + peer.RelayID + " serves site " + peer.Site + ", the host is in site " + host.Site}
	}
	if peer.Environment != "" && host.Environment != peer.Environment {
		return nil, &RelayRefusal{Code: hosts.RefusalRelayScopeMismatch,
			Detail: "relay " + peer.RelayID + " serves environment " + peer.Environment +
				", the host is in environment " + host.Environment}
	}

	verified := &Verified{Serial: certificate.Serial}
	verified.PublicKey, verified.LearnedKeyDER, err = publicKeyOf(certificate, peer.HostCertificate)
	if err != nil {
		return nil, invalid(err.Error())
	}

	// The payload, then the signature: a digest that does not match says
	// the content changed on the way, and that is worth naming apart from
	// a signature that does not verify at all.
	matches, err := relayproof.DigestMatches(envelope, body)
	if err != nil {
		return nil, invalid("the payload cannot be digested: " + err.Error())
	}
	if !matches {
		return nil, &RelayRefusal{Code: hosts.RefusalRelayBodyHashMismatch,
			Detail: "the " + kind + " does not match the digest the host signed (sequence " +
				strconv.FormatUint(envelope.GetSequence(), 10) + ")"}
	}
	if err := relayproof.Verify(verified.PublicKey, envelope); err != nil {
		return nil, &RelayRefusal{Code: hosts.RefusalRelayHostSignatureInvalid,
			Detail: "the signature over the " + kind + " does not verify under certificate " +
				certificate.Serial + ": " + err.Error()}
	}

	if window > 0 {
		issued := time.Unix(envelope.GetIssuedAtUnix(), 0)
		if skew := v.now().Sub(issued); skew > window || skew < -window {
			return nil, invalid("the envelope was issued at " + issued.UTC().Format(time.RFC3339) +
				", outside the window of " + window.String())
		}
	}
	if consumeSequence {
		if _, err := uuid.Parse(envelope.GetSessionId()); err != nil {
			return nil, invalid("the session identifier is not a UUID")
		}
		accepted, last, err := v.sequences.Accept(ctx, peer.HostID, envelope.GetSessionId(), envelope.GetSequence())
		if err != nil {
			return nil, err
		}
		if !accepted {
			// A number at or below the one the same session last spent is
			// a message this panel consumed already: the relay holds it in
			// its spool until an acknowledgement arrives, and a link that
			// broke in between means it sends it once more. That is the
			// spool working, not a host or a relay to suspect. Anything
			// else under this code is a sequence the session never took.
			if envelope.GetSequence() <= last {
				return nil, &RelayRefusal{Code: hosts.RefusalRelaySequenceReplayed, Redelivery: true,
					Detail: "sequence " + strconv.FormatUint(envelope.GetSequence(), 10) +
						" of session " + envelope.GetSessionId() + " was consumed before (the session is at " +
						strconv.FormatUint(last, 10) + ")"}
			}
			return nil, &RelayRefusal{Code: hosts.RefusalRelaySequenceReplayed,
				Detail: "sequence " + strconv.FormatUint(envelope.GetSequence(), 10) +
					" of session " + envelope.GetSessionId() + " was accepted before"}
		}
	}
	return verified, nil
}

// publicKeyOf finds the key the envelope is checked against: the one on
// record, or - for a certificate issued before the record carried keys -
// the one in the certificate the relay presented, once its fingerprint is
// the fingerprint on record. The fingerprint is the SHA-256 of the whole
// certificate, so a certificate that matches it is the issued one and its
// key is the issued key. The DER comes back for the caller to record.
func publicKeyOf(certificate hosts.CertificateStatus, presented *x509.Certificate) (crypto.PublicKey, []byte, error) {
	if len(certificate.PublicKeyDER) > 0 {
		key, err := x509.ParsePKIXPublicKey(certificate.PublicKeyDER)
		if err != nil {
			return nil, nil, fmt.Errorf("the public key on record for certificate %s does not parse: %v", certificate.Serial, err)
		}
		return key, nil, nil
	}
	if presented == nil {
		return nil, nil, errors.New("no public key is on record for certificate " + certificate.Serial +
			" and the relay did not present the certificate; upgrade the relay, or let the host renew directly")
	}
	sum := sha256.Sum256(presented.Raw)
	if subtle.ConstantTimeCompare(sum[:], certificate.Fingerprint) != 1 {
		return nil, nil, errors.New("the certificate the relay presented is not the one on record for serial " +
			certificate.Serial)
	}
	return presented.PublicKey, presented.RawSubjectPublicKeyInfo, nil
}

// relaySequences keeps the sequences in relay_host_sequences.
type relaySequences struct {
	pool *pgxpool.Pool
}

// Accept records the sequence when it is greater than the last one of the
// session, in one statement: two gateways serving a host's buffered
// messages at once cannot both accept the same number. The number the
// session stood at before the statement comes back with the answer: the
// write of the common table expression is not visible to the rest of the
// query, so the read gives the state the message met rather than the one
// it left behind. A session nobody has spoken in stands at zero.
func (r relaySequences) Accept(ctx context.Context, hostID, sessionID string,
	sequence uint64) (bool, uint64, error) {
	var accepted bool
	var last int64
	err := r.pool.QueryRow(ctx, `
		with taken as (
			insert into relay_host_sequences (host_id, session_id, last_sequence, updated_at)
			values ($1, $2, $3, now())
			on conflict (host_id, session_id) do update
			   set last_sequence = excluded.last_sequence, updated_at = now()
			 where relay_host_sequences.last_sequence < excluded.last_sequence
			returning last_sequence
		)
		select exists (select 1 from taken),
		       coalesce((select last_sequence from relay_host_sequences
		                  where host_id = $1 and session_id = $2), 0)`,
		hostID, sessionID, int64(sequence)).Scan(&accepted, &last)
	if err != nil {
		return false, 0, fmt.Errorf("recording the sequence: %w", err)
	}
	if last < 0 {
		last = 0
	}
	return accepted, uint64(last), nil
}

// sequenceRetention is how long a session's last sequence is kept after
// its last message. A relay buffers results for the length of an outage,
// and a result signed in a session that ended arrives under that
// session's number; a month covers any outage a relay's buffer survives,
// and a number older than that guards nothing a replay could still use.
const sequenceRetention = 30 * 24 * time.Hour

// Sweep removes the sequences of sessions nobody has spoken in for longer
// than the retention.
func (r relaySequences) Sweep(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		delete from relay_host_sequences where updated_at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(sequenceRetention.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SweepRelayProofs removes what the relay proofs leave behind and nobody
// can use any more: expired challenges and the sequences of long-silent
// sessions. The housekeeping calls it on its cycle.
func (s *AgentService) SweepRelayProofs(ctx context.Context) error {
	challenges, err := s.challenges.Sweep(ctx)
	if err != nil {
		return fmt.Errorf("sweeping the identity challenges: %w", err)
	}
	sequences, err := relaySequences{pool: s.pool}.Sweep(ctx)
	if err != nil {
		return fmt.Errorf("sweeping the relay sequences: %w", err)
	}
	if challenges > 0 || sequences > 0 {
		s.log.Info("the relay proofs were swept", "challenges", challenges, "sequences", sequences)
	}
	return nil
}

// identityChallenges keeps the one-time renewal challenges.
type identityChallenges struct {
	pool *pgxpool.Pool
}

// Issue stores the digest of a challenge for the host, bound to the relay
// it was asked through (empty for a direct call), for the challenge's
// lifetime.
func (c identityChallenges) Issue(ctx context.Context, hostID, relayID string, digest []byte, expires time.Time) error {
	_, err := c.pool.Exec(ctx, `
		insert into identity_challenges (id, host_id, relay_id, challenge_hash, expires_at)
		values ($1, $2, nullif($3, '')::uuid, $4, $5)`,
		uuid.NewString(), hostID, relayID, digest, expires)
	if err != nil {
		return fmt.Errorf("storing the challenge: %w", err)
	}
	return nil
}

// Consume spends a challenge: it has to be the host's, asked through the
// same relay, unspent and unexpired. False is a challenge that is none of
// that, which the caller refuses without saying which.
func (c identityChallenges) Consume(ctx context.Context, hostID, relayID string, digest []byte) (bool, error) {
	tag, err := c.pool.Exec(ctx, `
		update identity_challenges set consumed_at = now()
		 where challenge_hash = $1 and host_id = $2
		   and coalesce(relay_id::text, '') = $3
		   and consumed_at is null and expires_at > now()`,
		digest, hostID, relayID)
	if err != nil {
		return false, fmt.Errorf("consuming the challenge: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Sweep removes the challenges nobody can use any more: expired or spent
// for longer than an hour. The trail of a renewal is in the audit; the
// row has no further use.
func (c identityChallenges) Sweep(ctx context.Context) (int64, error) {
	tag, err := c.pool.Exec(ctx, `
		delete from identity_challenges
		 where expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
