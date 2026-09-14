package helper

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeSSSDFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The parser never fills a hole with a number that looks measured: a missing
// file or section leaves everything unknown with a reason, an absent key
// takes the SSSD default and is named as defaulted, and a value that does
// not parse is unknown rather than false or zero.
func TestParseSSSDOfflinePolicy(t *testing.T) {
	cases := []struct {
		name       string
		domain     string
		main       string // empty means no main file
		dropIns    map[string]string
		want       sssdOfflinePolicy
		wantReason string // a substring; empty means no reason at all
	}{
		{
			name:       "missing file",
			domain:     "lab.example",
			wantReason: "sssd.conf is missing",
		},
		{
			name:       "missing domain name",
			domain:     "",
			main:       "[sssd]\ndomains = lab.example\n",
			wantReason: "the domain name is missing",
		},
		{
			name:       "missing section",
			domain:     "lab.example",
			main:       "[sssd]\ndomains = lab.example\n\n[domain/other.example]\ncache_credentials = true\n",
			wantReason: "no [domain/lab.example] section",
		},
		{
			name:   "defaults for an empty section",
			domain: "lab.example",
			main:   "[sssd]\ndomains = lab.example\n\n[domain/lab.example]\nid_provider = ipa\n",
			want: sssdOfflinePolicy{
				CacheCredentials:                 boolPtr(false),
				OfflineCredentialsExpirationDays: uint32Ptr(0),
				EntryCacheTimeoutSeconds:         uint32Ptr(5400),
				StorePasswordIfOffline:           boolPtr(false),
				Defaulted: []string{"cache_credentials", "offline_credentials_expiration",
					"entry_cache_timeout", "krb5_store_password_if_offline"},
			},
		},
		{
			name:   "configured values",
			domain: "lab.example",
			main: "[domain/lab.example]\n" +
				"# offline logins for a week\n" +
				"cache_credentials = True\n" +
				"offline_credentials_expiration=7\n" +
				"entry_cache_timeout = 600\n" +
				"krb5_store_password_if_offline = false\n" +
				"; trailing comment\n" +
				"[sssd]\ndomains = lab.example\n",
			want: sssdOfflinePolicy{
				CacheCredentials:                 boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(7),
				EntryCacheTimeoutSeconds:         uint32Ptr(600),
				StorePasswordIfOffline:           boolPtr(false),
			},
		},
		{
			name:   "section name is matched without regard to case",
			domain: "Lab.Example",
			main:   "[domain/lab.example]\ncache_credentials = true\n",
			want: sssdOfflinePolicy{
				CacheCredentials:                 boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(0),
				EntryCacheTimeoutSeconds:         uint32Ptr(5400),
				StorePasswordIfOffline:           boolPtr(false),
				Defaulted: []string{"offline_credentials_expiration",
					"entry_cache_timeout", "krb5_store_password_if_offline"},
			},
		},
		{
			name:   "garbage values are unknown, not defaults",
			domain: "lab.example",
			main: "[domain/lab.example]\n" +
				"cache_credentials = yes\n" +
				"offline_credentials_expiration = -3\n" +
				"entry_cache_timeout = soon\n" +
				"krb5_store_password_if_offline = 1\n",
			want:       sssdOfflinePolicy{},
			wantReason: "cache_credentials has an unreadable value \"yes\"",
		},
		{
			name:   "a drop-in overrides the main file",
			domain: "lab.example",
			main:   "[domain/lab.example]\ncache_credentials = false\noffline_credentials_expiration = 3\n",
			dropIns: map[string]string{
				"10-site.conf":  "[domain/lab.example]\ncache_credentials = true\n",
				"20-later.conf": "[domain/lab.example]\noffline_credentials_expiration = 14\n",
				"ignored.txt":   "[domain/lab.example]\noffline_credentials_expiration = 99\n",
				".hidden.conf":  "[domain/lab.example]\noffline_credentials_expiration = 98\n",
			},
			want: sssdOfflinePolicy{
				CacheCredentials:                 boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(14),
				EntryCacheTimeoutSeconds:         uint32Ptr(5400),
				StorePasswordIfOffline:           boolPtr(false),
				Defaulted:                        []string{"entry_cache_timeout", "krb5_store_password_if_offline"},
			},
		},
		{
			name:   "a drop-in alone defines the section",
			domain: "lab.example",
			main:   "[sssd]\ndomains = lab.example\n",
			dropIns: map[string]string{
				"domain.conf": "[domain/lab.example]\ncache_credentials = true\noffline_credentials_expiration = 0\n",
			},
			want: sssdOfflinePolicy{
				CacheCredentials:                 boolPtr(true),
				OfflineCredentialsExpirationDays: uint32Ptr(0),
				EntryCacheTimeoutSeconds:         uint32Ptr(5400),
				StorePasswordIfOffline:           boolPtr(false),
				Defaulted:                        []string{"entry_cache_timeout", "krb5_store_password_if_offline"},
			},
		},
		{
			name:   "keys outside the section do not count",
			domain: "lab.example",
			main:   "[sssd]\ncache_credentials = true\n\n[domain/lab.example]\nid_provider = ipa\n\n[pam]\noffline_credentials_expiration = 9\n",
			want: sssdOfflinePolicy{
				CacheCredentials:                 boolPtr(false),
				OfflineCredentialsExpirationDays: uint32Ptr(0),
				EntryCacheTimeoutSeconds:         uint32Ptr(5400),
				StorePasswordIfOffline:           boolPtr(false),
				Defaulted: []string{"cache_credentials", "offline_credentials_expiration",
					"entry_cache_timeout", "krb5_store_password_if_offline"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mainPath := filepath.Join(dir, "sssd.conf")
			dropInDir := filepath.Join(dir, "conf.d")
			if tc.main != "" {
				writeSSSDFile(t, mainPath, tc.main)
			}
			for name, content := range tc.dropIns {
				writeSSSDFile(t, filepath.Join(dropInDir, name), content)
			}

			got := parseSSSDOfflinePolicy(tc.domain, mainPath, dropInDir)

			if tc.wantReason == "" && got.UnavailableReason != "" {
				t.Fatalf("unexpected reason %q", got.UnavailableReason)
			}
			if tc.wantReason != "" && !strings.Contains(got.UnavailableReason, tc.wantReason) {
				t.Fatalf("reason %q does not mention %q", got.UnavailableReason, tc.wantReason)
			}
			got.UnavailableReason = ""
			if derefPolicy(got) != derefPolicy(tc.want) {
				t.Fatalf("policy mismatch\n got: %s\nwant: %s", derefPolicy(got), derefPolicy(tc.want))
			}
		})
	}
}

// The garbage case must leave every value nil: a partial default next to an
// unreadable value would be exactly the "looks measured" mistake.
func TestParseSSSDOfflinePolicyGarbageLeavesEverythingUnknown(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "sssd.conf")
	writeSSSDFile(t, mainPath, "[domain/lab.example]\ncache_credentials = maybe\n"+
		"offline_credentials_expiration = 4294967296\nentry_cache_timeout = 1e3\n"+
		"krb5_store_password_if_offline = on\n")

	got := parseSSSDOfflinePolicy("lab.example", mainPath, filepath.Join(dir, "conf.d"))
	if got.CacheCredentials != nil || got.OfflineCredentialsExpirationDays != nil ||
		got.EntryCacheTimeoutSeconds != nil || got.StorePasswordIfOffline != nil {
		t.Fatalf("a garbage value produced a number: %s", derefPolicy(got))
	}
	if len(got.Defaulted) != 0 {
		t.Fatalf("garbage must not be reported as defaulted: %v", got.Defaulted)
	}
	for _, key := range []string{"cache_credentials", "offline_credentials_expiration",
		"entry_cache_timeout", "krb5_store_password_if_offline"} {
		if !strings.Contains(got.UnavailableReason, key) {
			t.Errorf("the reason %q does not name %s", got.UnavailableReason, key)
		}
	}
}

// The proto carries nil as unset and a value as a value; nothing is
// invented on the way.
func TestSSSDOfflinePolicyToProtoKeepsUnknown(t *testing.T) {
	message := sssdOfflinePolicyToProto(sssdOfflinePolicy{
		CacheCredentials:  boolPtr(true),
		Defaulted:         []string{"entry_cache_timeout"},
		UnavailableReason: "offline_credentials_expiration has an unreadable value \"x\"",
	})
	if message.CacheCredentials == nil || !message.GetCacheCredentials() {
		t.Fatal("cache_credentials was lost")
	}
	if message.OfflineCredentialsExpirationDays != nil || message.EntryCacheTimeoutSeconds != nil ||
		message.Krb5StorePasswordIfOffline != nil {
		t.Fatal("an unknown value became a number on the wire")
	}
	if len(message.GetDefaulted()) != 1 || message.GetUnavailableReason() == "" {
		t.Fatal("the defaulted list or the reason was lost")
	}
}

// derefPolicy renders the pointers as text so a mismatch is readable and
// comparable without caring about pointer identity.
func derefPolicy(policy sssdOfflinePolicy) string {
	show := func(value any) string {
		switch v := value.(type) {
		case *bool:
			if v == nil {
				return "?"
			}
			if *v {
				return "true"
			}
			return "false"
		case *uint32:
			if v == nil {
				return "?"
			}
			return strconv.FormatUint(uint64(*v), 10)
		}
		return "?"
	}
	return "cache_credentials=" + show(policy.CacheCredentials) +
		" offline_credentials_expiration=" + show(policy.OfflineCredentialsExpirationDays) +
		" entry_cache_timeout=" + show(policy.EntryCacheTimeoutSeconds) +
		" krb5_store_password_if_offline=" + show(policy.StorePasswordIfOffline) +
		" defaulted=" + strings.Join(policy.Defaulted, ",")
}
