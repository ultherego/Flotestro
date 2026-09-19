package hosts

import (
	"strings"
	"testing"
	"time"
)

func boolPtr(value bool) *bool       { return &value }
func uint32Ptr(value uint32) *uint32 { return &value }
func uint64Ptr(value uint64) *uint64 { return &value }

// The verdict follows the reported policy and never fills a missing fact with
// a value: no policy is unknown, a policy without a cache is no cached logins,
// a cache without expiry is indefinite, and a cache with an expiry names the
func TestJudgeOfflineLogins(t *testing.T) {
	observed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	offline := boolPtr(false)

	cases := []struct {
		name        string
		facts       IdentityFacts
		wantVerdict string
		wantUntil   *time.Time
		wantInForce bool
		wantReason  string // a substring
	}{
		{
			name:        "no policy reported",
			facts:       IdentityFacts{SSSDOnline: offline},
			wantVerdict: VerdictUnknown,
			wantInForce: true,
			wantReason:  "did not report whether SSSD caches credentials",
		},
		{
			name: "policy unreadable on the host, with its reason",
			facts: IdentityFacts{SSSDOnline: offline,
				PolicyUnavailableReason: "/etc/sssd/sssd.conf is missing"},
			wantVerdict: VerdictUnknown,
			wantInForce: true,
			wantReason:  "/etc/sssd/sssd.conf is missing",
		},
		{
			name: "no cached credentials",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(false),
				OfflineCredentialsExpirationDays: uint32Ptr(7),
				CacheAgeSeconds:                  uint64Ptr(60), ObservedAt: observed},
			wantVerdict: VerdictNoCachedLogins,
			wantInForce: true,
			wantReason:  "nobody from the directory can log in",
		},
		{
			name: "cache without a known expiry",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(true),
				CacheAgeSeconds: uint64Ptr(60), ObservedAt: observed},
			wantVerdict: VerdictUnknown,
			wantInForce: true,
			wantReason:  "for how long they stay valid",
		},
		{
			name: "cache that never expires",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(0)},
			wantVerdict: VerdictCachedLoginsIndefinitely,
			wantInForce: true,
			wantReason:  "never expire",
		},
		{
			name: "cache with an expiry but no cache age",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(7), ObservedAt: observed},
			wantVerdict: VerdictUnknown,
			wantInForce: true,
			wantReason:  "age of the SSSD cache is unknown",
		},
		{
			name: "cache with an expiry but no observation time",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(7), CacheAgeSeconds: uint64Ptr(60)},
			wantVerdict: VerdictUnknown,
			wantInForce: true,
			wantReason:  "age of the SSSD cache is unknown",
		},
		{
			name: "cache with an expiry names the deadline",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(7),
				CacheAgeSeconds:                  uint64Ptr(3600), ObservedAt: observed},
			wantVerdict: VerdictCachedLoginsUntil,
			wantUntil:   timePtr(observed.Add(-time.Hour).Add(7 * 24 * time.Hour)),
			wantInForce: true,
			wantReason:  "no later than 2026-09-21T11:00:00Z",
		},
		{
			name: "one day is singular",
			facts: IdentityFacts{SSSDOnline: offline, CacheCredentials: boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(1),
				CacheAgeSeconds:                  uint64Ptr(0), ObservedAt: observed},
			wantVerdict: VerdictCachedLoginsUntil,
			wantUntil:   timePtr(observed.Add(24 * time.Hour)),
			wantInForce: true,
			wantReason:  "expire 1 day after",
		},
		{
			name: "a host still online gets the projection, not in force",
			facts: IdentityFacts{SSSDOnline: boolPtr(true), CacheCredentials: boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(0)},
			wantVerdict: VerdictCachedLoginsIndefinitely,
			wantInForce: false,
		},
		{
			name:        "an unknown connection state is not an outage",
			facts:       IdentityFacts{CacheCredentials: boolPtr(false)},
			wantVerdict: VerdictNoCachedLogins,
			wantInForce: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := JudgeOfflineLogins(tc.facts)
			if got.Verdict != tc.wantVerdict {
				t.Fatalf("verdict %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if got.InForce != tc.wantInForce {
				t.Fatalf("in_force %v, want %v", got.InForce, tc.wantInForce)
			}
			switch {
			case tc.wantUntil == nil && got.Until != nil:
				t.Fatalf("an until %s was named without a deadline to name", got.Until)
			case tc.wantUntil != nil && (got.Until == nil || !got.Until.Equal(*tc.wantUntil)):
				t.Fatalf("until %v, want %v", got.Until, tc.wantUntil)
			}
			if got.Reason == "" {
				t.Fatal("every verdict carries a reason")
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Fatalf("reason %q does not mention %q", got.Reason, tc.wantReason)
			}
		})
	}
}

// The stored module is the agent's JSON; a missing module, a broken payload
// and an agent from before the policy all end as unknown with a reason that
// names the actual gap.
func TestJudgeFromFragment(t *testing.T) {
	observed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	offline := boolPtr(false)

	cases := []struct {
		name        string
		payload     string
		observedAt  *time.Time
		wantVerdict string
		wantReason  string
	}{
		{
			name:        "module not reported",
			wantVerdict: VerdictUnknown,
			wantReason:  "has not reported its identity module",
		},
		{
			name:        "broken payload",
			payload:     "{not json",
			observedAt:  &observed,
			wantVerdict: VerdictUnknown,
			wantReason:  "could not be read",
		},
		{
			name:        "agent from before the policy",
			payload:     `{"enrolled":true,"cache_age_seconds":30,"sssd_online":false}`,
			observedAt:  &observed,
			wantVerdict: VerdictUnknown,
			wantReason:  "does not report the SSSD offline policy",
		},
		{
			name:        "helper could not read the whole probe",
			payload:     `{"enrolled":true,"unavailable_reason":"keytab: /etc/krb5.keytab is missing"}`,
			observedAt:  &observed,
			wantVerdict: VerdictUnknown,
			wantReason:  "keytab: /etc/krb5.keytab is missing",
		},
		{
			name: "policy with a deadline",
			payload: `{"enrolled":true,"cache_age_seconds":7200,` +
				`"sssd_offline_policy":{"cache_credentials":true,"offline_credentials_expiration_days":3}}`,
			observedAt:  &observed,
			wantVerdict: VerdictCachedLoginsUntil,
			wantReason:  "no later than 2026-09-17T10:00:00Z",
		},
		{
			name: "policy with an unreadable expiry keeps the host's reason",
			payload: `{"enrolled":true,"cache_age_seconds":7200,` +
				`"sssd_offline_policy":{"cache_credentials":true,` +
				`"unavailable_reason":"offline_credentials_expiration has an unreadable value \"soon\""}}`,
			observedAt:  &observed,
			wantVerdict: VerdictUnknown,
			wantReason:  "for how long they stay valid",
		},
		{
			name:        "policy without a cache",
			payload:     `{"enrolled":true,"sssd_offline_policy":{"cache_credentials":false,"defaulted":["cache_credentials"]}}`,
			observedAt:  &observed,
			wantVerdict: VerdictNoCachedLogins,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := judgeFromFragment(offline, []byte(tc.payload), tc.observedAt)
			if got == nil {
				t.Fatal("no verdict")
			}
			if got.Verdict != tc.wantVerdict {
				t.Fatalf("verdict %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if !got.InForce {
				t.Fatal("a host whose SSSD is offline is in the outage")
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Fatalf("reason %q does not mention %q", got.Reason, tc.wantReason)
			}
		})
	}
}

func timePtr(value time.Time) *time.Time { return &value }
