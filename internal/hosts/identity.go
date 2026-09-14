package hosts

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// The verdicts the panel reaches about logins on a host cut off from the
// directory. The host reports the facts - the SSSD policy and the cache age -
// and the panel says what they mean; the host never judges itself.
const (
	// VerdictCachedLoginsUntil: users who logged in before the outage can keep
	// logging in, but no later than the Until timestamp.
	VerdictCachedLoginsUntil = "cached_logins_until"
	// VerdictCachedLoginsIndefinitely: cached credentials never expire.
	VerdictCachedLoginsIndefinitely = "cached_logins_indefinitely"
	// VerdictNoCachedLogins: SSSD keeps no credentials, so nobody from the
	// directory can log in while it is unreachable.
	VerdictNoCachedLogins = "no_cached_logins"
	// VerdictUnknown: a fact needed for the verdict is missing. Unknown is not
	// "no cached logins" and not "fine": the reason says what is missing.
	VerdictUnknown = "unknown"
)

// OfflineVerdict is the panel's conclusion about logins during a directory
// outage, with the one sentence that justifies it.
type OfflineVerdict struct {
	Verdict string `json:"verdict"`
	// Until is set only for VerdictCachedLoginsUntil: the latest moment a
	// cached credential can still be accepted.
	Until *time.Time `json:"until,omitempty"`
	// InForce says whether the host is cut off from the directory right now.
	// The verdict is a projection of the policy either way; in force means
	// the outage is happening, not that it may happen.
	InForce bool `json:"in_force"`
	// Reason is the one sentence behind the verdict, meant for the operator.
	Reason string `json:"reason"`
}

// IdentityFacts are the reported facts the verdict is judged from. A nil
// pointer is a fact the host did not report, never a zero.
type IdentityFacts struct {
	// SSSDOnline is the last known connection state of SSSD.
	SSSDOnline *bool
	// CacheAgeSeconds is the age of the SSSD cache database when the host
	// observed it, so the verdict has to anchor it at ObservedAt.
	CacheAgeSeconds *uint64
	// ObservedAt is the moment the host measured the cache age. A zero time
	// means the age was never measured.
	ObservedAt time.Time
	// CacheCredentials is the cache_credentials key of the joined domain.
	CacheCredentials *bool
	// OfflineCredentialsExpirationDays is offline_credentials_expiration;
	// zero means the cached credentials never expire.
	OfflineCredentialsExpirationDays *uint32
	// PolicyUnavailableReason is what the host said about a policy it could
	// not read, so the verdict can repeat it instead of guessing.
	PolicyUnavailableReason string
}

// JudgeOfflineLogins decides what happens to directory logins on the host
// when the directory is unreachable.
//
// The cache age is an upper bound for the age of any cached credential: the
// cache database is written on every refresh, so no credential in it was
// obtained after the last write. The expiry of the freshest credential is
// therefore no later than the last write plus the expiration window, and
// that is the timestamp the verdict names.
func JudgeOfflineLogins(facts IdentityFacts) OfflineVerdict {
	verdict := OfflineVerdict{
		Verdict: VerdictUnknown,
		InForce: facts.SSSDOnline != nil && !*facts.SSSDOnline,
	}

	switch {
	case facts.CacheCredentials == nil:
		verdict.Reason = "The host did not report whether SSSD caches credentials"
		if facts.PolicyUnavailableReason != "" {
			verdict.Reason += ": " + facts.PolicyUnavailableReason
		}
		verdict.Reason += "."
		return verdict

	case !*facts.CacheCredentials:
		verdict.Verdict = VerdictNoCachedLogins
		verdict.Reason = "SSSD does not cache credentials (cache_credentials = false), " +
			"so nobody from the directory can log in while it is unreachable."
		return verdict

	case facts.OfflineCredentialsExpirationDays == nil:
		verdict.Reason = "SSSD caches credentials, but the host did not report " +
			"for how long they stay valid (offline_credentials_expiration)"
		if facts.PolicyUnavailableReason != "" {
			verdict.Reason += ": " + facts.PolicyUnavailableReason
		}
		verdict.Reason += "."
		return verdict

	case *facts.OfflineCredentialsExpirationDays == 0:
		verdict.Verdict = VerdictCachedLoginsIndefinitely
		verdict.Reason = "SSSD caches credentials and they never expire " +
			"(offline_credentials_expiration = 0), so users who logged in " +
			"before the outage can keep logging in."
		return verdict

	case facts.CacheAgeSeconds == nil || facts.ObservedAt.IsZero():
		verdict.Reason = fmt.Sprintf("Cached credentials expire %s after the last "+
			"online login, but the age of the SSSD cache is unknown, so the "+
			"deadline cannot be named.", days(*facts.OfflineCredentialsExpirationDays))
		return verdict
	}

	lastWrite := facts.ObservedAt.Add(-time.Duration(*facts.CacheAgeSeconds) * time.Second)
	until := lastWrite.Add(time.Duration(*facts.OfflineCredentialsExpirationDays) * 24 * time.Hour)
	verdict.Verdict = VerdictCachedLoginsUntil
	verdict.Until = &until
	verdict.Reason = fmt.Sprintf("Cached credentials expire %s after the last online "+
		"login; the SSSD cache was last written %s, so cached logins end no later than %s.",
		days(*facts.OfflineCredentialsExpirationDays),
		lastWrite.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339))
	return verdict
}

func days(count uint32) string {
	if count == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", count)
}

// identityFragment is the part of the identity inventory module the verdict
// reads. The module is the agent's own JSON, so the names are the agent's.
type identityFragment struct {
	CacheAgeSeconds *uint64 `json:"cache_age_seconds"`
	OfflinePolicy   *struct {
		CacheCredentials                 *bool   `json:"cache_credentials"`
		OfflineCredentialsExpirationDays *uint32 `json:"offline_credentials_expiration_days"`
		UnavailableReason                string  `json:"unavailable_reason"`
	} `json:"sssd_offline_policy"`
	UnavailableReason string `json:"unavailable_reason"`
}

// judgeFromFragment builds the verdict from the stored identity module. A
// host that has not reported the module gets an unknown verdict with that
// reason; a broken payload likewise, because a payload the panel cannot
// read is not a host without a cache.
func judgeFromFragment(sssdOnline *bool, payload []byte, observedAt *time.Time) *OfflineVerdict {
	facts := IdentityFacts{SSSDOnline: sssdOnline}
	if len(payload) == 0 || observedAt == nil {
		facts.PolicyUnavailableReason = "the host has not reported its identity module yet"
		verdict := JudgeOfflineLogins(facts)
		return &verdict
	}

	var fragment identityFragment
	if err := json.Unmarshal(payload, &fragment); err != nil {
		facts.PolicyUnavailableReason = "the stored identity module could not be read"
		verdict := JudgeOfflineLogins(facts)
		return &verdict
	}

	facts.CacheAgeSeconds = fragment.CacheAgeSeconds
	facts.ObservedAt = *observedAt
	switch {
	case fragment.OfflinePolicy != nil:
		facts.CacheCredentials = fragment.OfflinePolicy.CacheCredentials
		facts.OfflineCredentialsExpirationDays = fragment.OfflinePolicy.OfflineCredentialsExpirationDays
		facts.PolicyUnavailableReason = fragment.OfflinePolicy.UnavailableReason
	case fragment.UnavailableReason != "":
		facts.PolicyUnavailableReason = fragment.UnavailableReason
	default:
		// An agent from before the policy was read sends no such field; it
		// is the agent that is old, not the cache that is empty.
		facts.PolicyUnavailableReason = "the agent on the host does not report the SSSD offline policy"
	}
	verdict := JudgeOfflineLogins(facts)
	return &verdict
}

// OfflineHost is one host cut off from the directory, with the verdict on
// its logins, for the fleet view of the identity status.
type OfflineHost struct {
	ID          string         `json:"id"`
	Hostname    string         `json:"hostname"`
	Site        string         `json:"site,omitempty"`
	Environment string         `json:"environment,omitempty"`
	CheckedAt   *time.Time     `json:"checked_at,omitempty"`
	Verdict     OfflineVerdict `json:"offline_verdict"`
}

// OfflineFromDirectory lists the enrolled hosts whose SSSD last reported
// itself offline, retired hosts excluded, each with the panel's verdict on
// its logins. The identity module comes along in the same query so the
// fleet view does not fetch it host by host.
func (s *Store) OfflineFromDirectory(ctx context.Context) ([]OfflineHost, error) {
	const query = `
		select h.id, h.hostname, h.site, h.environment, h.identity_checked_at,
		       h.identity_sssd_online, i.payload, i.observed_at
		  from hosts h
		  left join host_module_inventory i
		    on i.host_id = h.id and i.module = 'identity'
		 where h.identity_enrolled
		   and h.identity_sssd_online = false
		   and h.lifecycle_state <> 'retired'
		 order by h.hostname, h.id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []OfflineHost{}
	for rows.Next() {
		var (
			host       OfflineHost
			online     *bool
			payload    []byte
			observedAt *time.Time
		)
		if err := rows.Scan(&host.ID, &host.Hostname, &host.Site, &host.Environment,
			&host.CheckedAt, &online, &payload, &observedAt); err != nil {
			return nil, err
		}
		host.Verdict = *judgeFromFragment(online, payload, observedAt)
		result = append(result, host)
	}
	return result, rows.Err()
}
