package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/secrets"
)

// fixedKeys is a key provider over one key held in memory.
type fixedKeys struct{ cipher *secrets.Cipher }

func newFixedKeys(t *testing.T) fixedKeys {
	t.Helper()
	key := make([]byte, secrets.KeyLength)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := secrets.NewCipher(key)
	if err != nil {
		t.Fatalf("the test key: %v", err)
	}
	return fixedKeys{cipher: cipher}
}

func (k fixedKeys) ActiveKeyID(context.Context) (string, error) { return "test", nil }

func (k fixedKeys) Wrap(_ context.Context, keyID string, dek []byte) ([]byte, error) {
	nonce, ciphertext, err := k.cipher.Encrypt(dek, keyID, 1)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func (k fixedKeys) Unwrap(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	size := k.cipher.NonceSize()
	if len(wrapped) < size {
		return nil, errors.New("the wrapped key is too short")
	}
	return k.cipher.Decrypt(wrapped[:size], wrapped[size:], keyID, 1)
}

func (k fixedKeys) Health(context.Context) error { return nil }

// text is a collector over a fixed reading.
func text(name, source, content string) Collector {
	return Collector{
		Name: name, Source: source,
		Fields:  []Field{{Name: "content", Sensitivity: FieldSensitive}},
		Collect: func(context.Context) ([]byte, error) { return []byte(content), nil },
	}
}

func buildBundle(t *testing.T, collectors ...Collector) ([]byte, Manifest) {
	t.Helper()
	request := Request{
		BundleID: "00000000-0000-0000-0000-000000000001", Panel: "panel.example",
		Tool: "flotestro-control-plane 0.0.0", RequestedBy: "operator",
		Reason: "a ticket was opened", CreatedAt: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC),
	}
	archive, manifest, err := Build(context.Background(), request, collectors)
	if err != nil {
		t.Fatalf("the bundle was not built: %v", err)
	}
	return archive, manifest
}

func TestTheManifestNamesAndDigestsEveryFile(t *testing.T) {
	archive, manifest := buildBundle(t,
		text("panel.json", "the build of this panel", `{"version":"0.56.0"}`),
		text("fleet.json", "the counts of the fleet", `{"hosts":7}`))

	files, err := ReadArchive(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("the archive was not read: %v", err)
	}
	if len(files) != len(manifest.Entries)+1 {
		t.Fatalf("the manifest lists %d files, the archive holds %d", len(manifest.Entries), len(files))
	}
	for _, entry := range manifest.Entries {
		content, present := files[entry.Name]
		if !present {
			t.Fatalf("%s is in the manifest and not in the archive", entry.Name)
		}
		if entry.Bytes != len(content) {
			t.Fatalf("%s: the manifest says %d bytes, the archive holds %d", entry.Name, entry.Bytes, len(content))
		}
		if entry.SHA256 != Digest(content) {
			t.Fatalf("%s: the manifest digest does not describe the file in the archive", entry.Name)
		}
	}

	var written Manifest
	if err := json.Unmarshal(files["manifest.json"], &written); err != nil {
		t.Fatalf("the manifest in the archive is not JSON: %v", err)
	}
	if written.RedactionPolicy != RedactionPolicy || !written.Scanned {
		t.Fatalf("the written manifest states policy %q, scanned %v", written.RedactionPolicy, written.Scanned)
	}
}

func TestASecretInAReadingRefusesTheWholeBundle(t *testing.T) {
	for _, secret := range []struct {
		name, content, code string
	}{
		{"a private key", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n", "bundle_private_key_found"},
		{"a bearer token", "authorization: Bearer abcdefghijklmnop", "bundle_bearer_token_found"},
		{"a password in a URL", "postgres://flotestro:hunter2@db:5432/flotestro", "bundle_password_in_url_found"},
		{"an enrollment token", "token flt_AAAABBBBCCCC", "bundle_enrollment_token_found"},
		{"a panel token", "token flta_AAAABBBBCCCC", "bundle_api_token_found"},
	} {
		request := Request{BundleID: "id", CreatedAt: time.Now()}
		_, _, err := Build(context.Background(), request,
			[]Collector{text("reading.txt", "a reading", secret.content)})
		var leak *LeakError
		if !errors.As(err, &leak) {
			t.Fatalf("%s did not refuse the bundle: %v", secret.name, err)
		}
		if leak.Code() != secret.code {
			t.Fatalf("%s was refused as %s", secret.name, leak.Code())
		}
	}
}

func TestACollectorThatFailedIsSaidSoRatherThanDropped(t *testing.T) {
	failing := Collector{
		Name: "fleet.json", Source: "the counts of the fleet",
		Collect: func(context.Context) ([]byte, error) { return nil, errors.New("the database did not answer") },
	}
	_, manifest := buildBundle(t, failing)
	if len(manifest.Entries) != 1 || manifest.Entries[0].Error == "" {
		t.Fatalf("a reading that failed left no trace in the manifest: %+v", manifest.Entries)
	}
}

func TestASecretFieldIsDeclaredAndNeverCollected(t *testing.T) {
	collector := Collector{
		Name: "settings.json", Source: "the settings of the panel",
		Fields: []Field{
			{Name: "public_url", Sensitivity: FieldSensitive},
			{Name: "oidc_client_secret", Sensitivity: FieldSecret, Why: "whoever reads it can sign in as this panel"},
		},
		Collect: func(context.Context) ([]byte, error) { return []byte(`{"public_url":"https://panel"}`), nil },
	}
	_, manifest := buildBundle(t, collector)
	if len(manifest.Omitted) != 1 || manifest.Omitted[0].Field != "oidc_client_secret" {
		t.Fatalf("the manifest does not say what was left out: %+v", manifest.Omitted)
	}
	if manifest.Omitted[0].Why == "" {
		t.Fatal("a field left out without a reason reads like one that was never there")
	}
}

func TestTheArchiveOpensOnlyForTheBundleItWasSealedFor(t *testing.T) {
	keys := newFixedKeys(t)
	archive, _ := buildBundle(t, text("panel.json", "the build of this panel", `{"version":"0.56.0"}`))

	envelope, err := secrets.Seal(context.Background(), keys, archive, associated("bundle-one"))
	if err != nil {
		t.Fatalf("the archive was not sealed: %v", err)
	}
	opened, err := envelope.Open(context.Background(), keys, associated("bundle-one"))
	if err != nil {
		t.Fatalf("the archive did not open for its own bundle: %v", err)
	}
	if !bytes.Equal(opened, archive) {
		t.Fatal("the archive that came back is not the one that went in")
	}
	if _, err := envelope.Open(context.Background(), keys, associated("bundle-two")); err == nil {
		t.Fatal("the envelope of one bundle opened as another")
	}
}

func TestADownloadTokenLastsItsWindowAndIsSpentOnce(t *testing.T) {
	issued := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(TokenTTL)
	spent := issued.Add(time.Minute)

	for _, check := range []struct {
		name     string
		subject  string
		redeemed *time.Time
		now      time.Time
		want     error
	}{
		{name: "in its window", subject: "operator", now: issued.Add(time.Second)},
		{name: "a second before it ends", subject: "operator", now: expires.Add(-time.Second)},
		{name: "at the moment it ends", subject: "operator", now: expires, want: ErrTokenExpired},
		{name: "after it ended", subject: "operator", now: expires.Add(time.Hour), want: ErrTokenExpired},
		{name: "a second time", subject: "operator", redeemed: &spent, now: spent.Add(time.Second), want: ErrTokenSpent},
		{name: "by somebody else", subject: "another", now: issued.Add(time.Second), want: ErrTokenForeign},
	} {
		err := tokenState("operator", check.subject, expires, check.redeemed, check.now)
		if !errors.Is(err, check.want) {
			t.Fatalf("a token %s: %v, expected %v", check.name, err, check.want)
		}
	}
}

func TestTheRetentionDropsWhatNobodyCameForFirst(t *testing.T) {
	retention := Retention{Age: 7 * 24 * time.Hour, Unfetched: 24 * time.Hour}
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	fetched := now.Add(-2 * time.Hour)

	for _, check := range []struct {
		name     string
		bundle   Bundle
		want     string
		wantDrop bool
	}{
		{name: "made an hour ago and not fetched", bundle: Bundle{RequestedAt: now.Add(-time.Hour)}},
		{name: "fetched and two days old", bundle: Bundle{RequestedAt: now.Add(-48 * time.Hour), DownloadedAt: &fetched}},
		{name: "two days old and never fetched", bundle: Bundle{RequestedAt: now.Add(-48 * time.Hour)},
			want: "never_fetched", wantDrop: true},
		{name: "fetched and older than the retention", want: "age", wantDrop: true,
			bundle: Bundle{RequestedAt: now.Add(-8 * 24 * time.Hour), DownloadedAt: &fetched}},
	} {
		reason, drop := retention.Drop(check.bundle, now)
		if drop != check.wantDrop || reason != check.want {
			t.Fatalf("a bundle %s: dropped %v as %q, expected %v as %q",
				check.name, drop, reason, check.wantDrop, check.want)
		}
	}
}

func TestAnUnfetchedBundleNeverOutlivesAFetchedOne(t *testing.T) {
	filled := Retention{Age: time.Hour, Unfetched: 24 * time.Hour}.WithDefaults()
	if filled.Unfetched != filled.Age {
		t.Fatalf("the unfetched retention stayed at %s against an age of %s", filled.Unfetched, filled.Age)
	}
	defaults := Retention{}.WithDefaults()
	if defaults.Age != DefaultRetention || defaults.Unfetched != DefaultUnfetchedRetention {
		t.Fatalf("the defaults resolved to %s and %s", defaults.Age, defaults.Unfetched)
	}
}
