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
	"github.com/jackc/pgx/v5"
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
	// HostCertificate is the certificate the relay saw in its own handshake with
	// the host, nil for a relay from before it sent it.
	HostCertificate *x509.Certificate
}

// RelayRefusal is a typed refusal of an envelope: the code the host record
// and the trail carry, and the detail for the operator.
type RelayRefusal struct {
	Code   string
	Detail string
	// Redelivery marks a relay_sequence_replayed that is no replay: the relay
	// carried the message again because its acknowledgement did not arrive.
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

// The records the verifier reads.
type certificateRecords interface {
	LookupCertificateBySerial(ctx context.Context, serial string) (hosts.CertificateStatus, error)
}

type hostRecords interface {
	Get(ctx context.Context, hostID string) (*hosts.Host, error)
}

// sequenceRecords accepts a sequence of a session once and refuses it the
// second time.
type sequenceRecords interface {
	Claim(ctx context.Context, hostID, sessionID string, sequence uint64) (Claim, error)
}

// RelayVerifier checks the inner identity envelope of a relayed message the
// way the security document lays it out, against the panel's own records.
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

// Verified is what a verified envelope established, for the caller to record:
// the certificate the host signed with, its key, and the key's DER when the
// record had none and the relay's certificate supplied it.
type Verified struct {
	Serial    string
	PublicKey crypto.PublicKey
	// LearnedKeyDER is set when the key came from the certificate the relay
	// presented rather than from the record; the caller writes it on the record
	// so the next session needs no relay to supply it.
	LearnedKeyDER []byte
	// Redelivered says the sequence had been spent before and the message was
	// never applied: the relay is carrying it again and this delivery is the one
	// that does the work.
	Redelivered bool
}

// VerifyMessage checks the envelope of a message of the stream.
func (v *RelayVerifier) VerifyMessage(ctx context.Context, peer RelayPeer, msg *agentv1.AgentMessage) (*Verified, error) {
	kind, body, err := relayproof.Payload(msg)
	if err != nil {
		return nil, &RelayRefusal{Code: hosts.RefusalRelayEnvelopeInvalid, Detail: err.Error()}
	}
	return v.verify(ctx, peer, msg.GetEnvelope(), kind, body, true, 0)
}

// VerifyRequest checks the envelope of a unary request - a renewal, a secret
// fetch.
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
	// The relay first: the envelope names the relay the host connected to, and it
	// has to be the one that forwarded the message.
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

	// The host in the relay's scope.
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

	// The payload, then the signature: a digest that does not match says the
	// content changed on the way, and that is worth naming apart from a signature
	// that does not verify at all.
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
		claim, err := v.sequences.Claim(ctx, peer.HostID, envelope.GetSessionId(), envelope.GetSequence())
		if err != nil {
			return nil, err
		}
		switch {
		case claim.Applied:
			// The panel has this message. The relay carried it again because the
			// acknowledgement never reached it.
			return nil, &RelayRefusal{Code: hosts.RefusalRelaySequenceReplayed, Redelivery: true,
				Detail: "sequence " + strconv.FormatUint(envelope.GetSequence(), 10) +
					" of session " + envelope.GetSessionId() + " was applied before (the session is at " +
					strconv.FormatUint(claim.Last, 10) + ")"}
		case claim.Dead:
			return nil, &RelayRefusal{Code: hosts.RefusalRelaySequenceReplayed, Redelivery: true,
				Detail: "sequence " + strconv.FormatUint(envelope.GetSequence(), 10) +
					" of session " + envelope.GetSessionId() + " was set aside after " +
					strconv.Itoa(claim.Attempts) + " failed attempts"}
		case claim.Retry:
			// The number was spent and the work was not done: this delivery does it.
			// This is the case that used to be indistinguishable from a duplicate,
			// and the message was dropped with an acknowledgement.
			verified.Redelivered = true
		}
	}
	return verified, nil
}

// publicKeyOf finds the key the envelope is checked against: the one on
// record, or the one in the presented certificate once its fingerprint matches.
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

// Claim is what the panel knows about one relayed message.
type Claim struct {
	// Fresh says this sequence had not been seen before.
	Fresh bool
	// Retry says it had been seen and its message was never applied, so this
	// delivery is the one that applies it. The number is spent either way; what
	// the number does not say is whether the work was done.
	Retry bool
	// Applied says the panel has the message already: a repeat, to be
	// acknowledged and dropped.
	Applied bool
	// Dead says the message was refused often enough to be set aside. The relay
	// is told to stop carrying it.
	Dead bool
	// Last is the watermark of the session, and Attempts how many times this
	// message has been tried.
	Last     uint64
	Attempts int
}

// Claim records the sequence and says what became of the message it names. The
// watermark moves in the same statement, so two gateways serving one host's
// spool cannot both take the same number.
func (r relaySequences) Claim(ctx context.Context, hostID, sessionID string,
	sequence uint64) (Claim, error) {
	var moved, noted bool
	var last int64
	var state string
	var attempts int
	err := r.pool.QueryRow(ctx, `
		with taken as (
			insert into relay_host_sequences (host_id, session_id, last_sequence, updated_at)
			values ($1, $2, $3, now())
			on conflict (host_id, session_id) do update
			   set last_sequence = excluded.last_sequence, updated_at = now()
			 where relay_host_sequences.last_sequence < excluded.last_sequence
			returning last_sequence
		),
		noted as (
			insert into relay_inbox (host_id, session_id, sequence) values ($1, $2, $3)
			on conflict (host_id, session_id, sequence) do nothing
			returning 1
		)
		select exists (select 1 from taken), exists (select 1 from noted),
		       coalesce((select last_sequence from relay_host_sequences
		                  where host_id = $1 and session_id = $2), 0),
		       coalesce((select state from relay_inbox
		                  where host_id = $1 and session_id = $2 and sequence = $3), ''),
		       coalesce((select attempts from relay_inbox
		                  where host_id = $1 and session_id = $2 and sequence = $3), 0)`,
		hostID, sessionID, int64(sequence)).Scan(&moved, &noted, &last, &state, &attempts)
	if err != nil {
		return Claim{}, fmt.Errorf("recording the sequence: %w", err)
	}
	if last < 0 {
		last = 0
	}
	claim := Claim{Last: uint64(last), Attempts: attempts}
	switch {
	case noted && moved:
		// The row was created by this statement, so the two selects above - which
		// read the snapshot the statement began with - saw nothing. The watermark
		// moved with it, so this number is new work.
		claim.Fresh = true
	case noted:
		// The inbox has no memory of this number and the watermark says it is
		// spent: the record was swept after its retention, or somebody is
		// presenting the numbers of a session that is over. Either way the panel
		// does not do the work again, and the row it just made says so.
		claim.Applied = true
		if _, err := r.pool.Exec(ctx, `
			update relay_inbox set state = 'applied', applied_at = now()
			 where host_id = $1 and session_id = $2 and sequence = $3`,
			hostID, sessionID, int64(sequence)); err != nil {
			return Claim{}, fmt.Errorf("recording a spent sequence: %w", err)
		}
	case state == "applied":
		claim.Applied = true
	case state == "dead":
		claim.Dead = true
	default:
		// The number was spent and the work was not finished. Whichever gateway
		// spent it, this delivery is the one that does the work.
		claim.Retry = true
	}
	return claim, nil
}

// NoteApplied records that the panel has the message. A redelivery of it is a
// repeat from here on.
func (r relaySequences) NoteApplied(ctx context.Context, hostID, sessionID string, sequence uint64) error {
	_, err := r.pool.Exec(ctx, `
		update relay_inbox set state = 'applied', applied_at = now(), last_error = ''
		 where host_id = $1 and session_id = $2 and sequence = $3 and state <> 'applied'`,
		hostID, sessionID, int64(sequence))
	return err
}

// inboxAttempts is how many times a message is applied before the panel sets it
// aside. A message the panel will never take would otherwise be carried by the
// relay for as long as the relay lives.
const inboxAttempts = 8

// NoteFailure counts a failed apply and says whether the message was set aside.
func (r relaySequences) NoteFailure(ctx context.Context, hostID, sessionID string,
	sequence uint64, cause error) (bool, error) {
	reason := ""
	if cause != nil {
		reason = cause.Error()
	}
	var state string
	err := r.pool.QueryRow(ctx, `
		update relay_inbox
		   set attempts = attempts + 1, last_error = $4,
		       state = case when attempts + 1 >= $5 then 'dead' else state end
		 where host_id = $1 and session_id = $2 and sequence = $3
		returning state`,
		hostID, sessionID, int64(sequence), reason, inboxAttempts).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		// A session from before the inbox existed: nothing to count.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return state == "dead", nil
}

// sequenceRetention is how long a session's last sequence is kept after its
// last message.
const sequenceRetention = 30 * 24 * time.Hour

// Sweep removes the sequences of sessions nobody has spoken in for longer
// than the retention, and with them what was recorded about their messages.
// A message still owed is kept: it is work the panel has not done.
func (r relaySequences) Sweep(ctx context.Context) (int64, error) {
	if _, err := r.pool.Exec(ctx, `
		delete from relay_inbox
		 where state <> 'received' and coalesce(applied_at, received_at) < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(sequenceRetention.Seconds()))); err != nil {
		return 0, fmt.Errorf("sweeping the relay inbox: %w", err)
	}
	tag, err := r.pool.Exec(ctx, `
		delete from relay_host_sequences where updated_at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(sequenceRetention.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SweepRelayProofs removes what the relay proofs leave behind and nobody can
// use any more: expired challenges and the sequences of long-silent sessions.
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

// Issue stores the digest of a challenge for the host, bound to the relay it
// was asked through (empty for a direct call), for the challenge's lifetime.
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

// Consume spends a challenge: it has to be the host's, asked through the same
// relay, unspent and unexpired.
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

// Sweep removes the challenges nobody can use any more: expired or spent for
// longer than an hour.
func (c identityChallenges) Sweep(ctx context.Context) (int64, error) {
	tag, err := c.pool.Exec(ctx, `
		delete from identity_challenges
		 where expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
