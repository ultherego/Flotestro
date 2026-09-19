package config

import "testing"

// TestAnEmptyFeedAddressReallyDisablesItsSource guards the difference between
// a key the packaging left blank and a key an air-gapped site cleared on
// purpose: the first takes the default, the second must not reach the vendor.
func TestAnEmptyFeedAddressReallyDisablesItsSource(t *testing.T) {
	const key = "FLOTESTRO_TEST_FEED_URL"
	const fallback = "https://vendor.example.test/data"

	if got := EnvMeaningfullyEmpty(key, fallback); got != fallback {
		t.Fatalf("unset reads %q, expected the default", got)
	}
	t.Setenv(key, "")
	if got := EnvMeaningfullyEmpty(key, fallback); got != "" {
		t.Fatalf("an empty value reads %q; a site that cleared it would still reach the vendor", got)
	}
	// Env keeps the older meaning, because the packaging ships empty lines.
	if got := Env(key, fallback); got != fallback {
		t.Fatalf("Env on an empty value reads %q, expected the default", got)
	}
	t.Setenv(key, "file:///srv/feeds")
	if got := EnvMeaningfullyEmpty(key, fallback); got != "file:///srv/feeds" {
		t.Fatalf("a set value reads %q", got)
	}
}
