package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
)

func TestRedactHidesTheValuesOfSecretKeysOnly(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		out   string
		count int
	}{
		{"yaml", "enrollment_url: https://e\napi_token: abc123\n", "enrollment_url: https://e\napi_token: [redacted]\n", 1},
		{"environment", "FLOTESTRO_ENROLLMENT_TOKEN=tok-1\nFLOTESTRO_GATEWAY_URL=https://gw\n", "FLOTESTRO_ENROLLMENT_TOKEN=[redacted]\nFLOTESTRO_GATEWAY_URL=https://gw\n", 1},
		{"json keeps its shape", `{"password": "hunter2", "ok": true}`, `{"password": "[redacted]", "ok": true}`, 1},
		{"journal", "agent[12]: client_secret=s3cr3t sent\n", "agent[12]: client_secret=[redacted] sent\n", 1},
		{"a code that names the token is not a value", `"error_code": "enrollment_token_lingering"`, `"error_code": "enrollment_token_lingering"`, 0},
		{"a sentence is not a value", "the enrollment token is still in /etc/flotestro/agent.env", "the enrollment token is still in /etc/flotestro/agent.env", 0},
		{"an empty value stays empty", "token:\n", "token:\n", 0},
		{"the next line is not the value", "token:\nenrollment_url: https://e\n", "token:\nenrollment_url: https://e\n", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, count := redact([]byte(c.in))
			if string(got) != c.out || count != c.count {
				t.Fatalf("redact(%q) = %q, %d; we want %q, %d", c.in, got, count, c.out, c.count)
			}
		})
	}
}

// testCertificate makes a self-signed certificate of a host for the identity
// metadata; the key is thrown away because the bundle must never need it.
func testCertificate(t *testing.T) (pemBytes []byte, certificate *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd),
		Subject:      pkix.Name{CommonName: "host-0001"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate
}

// fakeBundleSources describes a host that exists only in the test: a valid
// configuration, an environment file with a lingering token, a journal that
// quotes a password, a helper journal that cannot be read, and an identity
func fakeBundleSources(t *testing.T, certPEM []byte) bundleSources {
	t.Helper()
	files := map[string][]byte{}
	files["/etc/flotestro/agent.yaml"] = []byte(goodConfiguration)
	files["/etc/flotestro/agent.env"] = []byte("FLOTESTRO_ENROLLMENT_TOKEN=tok-0123456789\nFLOTESTRO_GATEWAY_URL=https://gw.example.com:8443\n")
	files["/etc/os-release"] = []byte("ID=debian\nVERSION_ID=\"12\"\n")
	files["/var/lib/flotestro-agent/identity/1/agent.crt"] = certPEM
	files["/var/lib/flotestro-agent/identity/1/agent.key"] = []byte("-----BEGIN PRIVATE KEY-----\nMUSTNOTLEAVE\n-----END PRIVATE KEY-----\n")
	return bundleSources{
		ConfigPath:      "/etc/flotestro/agent.yaml",
		EnvironmentPath: "/etc/flotestro/agent.env",
		OSReleasePath:   "/etc/os-release",
		Hostname:        func() (string, error) { return "web-01.example.com", nil },
		Now:             func() time.Time { return time.Date(2026, 9, 15, 10, 30, 0, 0, time.UTC) },
		Diagnose: func(context.Context) ([]byte, error) {
			return []byte(`{"ok": false, "checks": [{"name": "config", "status": "warn", "error_code": "enrollment_token_lingering", "detail": "the enrollment token is still in /etc/flotestro/agent.env"}]}` + "\n"), nil
		},
		Status:    func() ([]byte, error) { return []byte("Identity:     host/host-0001\n"), nil },
		Effective: func() ([]byte, error) { return []byte("Enrollment:   https://enroll.example.com\n"), nil },
		ReadFile: func(path string) ([]byte, error) {
			content, ok := files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return content, nil
		},
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(line, "journalctl -u flotestro-agent.service"):
				return []byte("Sep 15 10:29:58 web-01 flotestro-agent[42]: session opened; proxy_password=hunter2\n"), nil
			case strings.Contains(line, "journalctl -u flotestro-helper.service"):
				return nil, errors.New("journalctl: permission denied")
			case strings.HasPrefix(line, "systemctl status"):
				// systemctl status exits with 3 for an inactive unit and still
				// prints the status; the bundle must keep the text.
				return []byte("* flotestro-agent.service - Flotestro agent\n     Active: inactive (dead)\n"), errors.New("exit status 3")
			}
			return nil, errors.New("unexpected command: " + line)
		},
		Identity: func(stateDir string) agent.StoredIdentity {
			return agent.StoredIdentity{
				Paths: agent.IdentityPaths{
					Key:  filepath.Join(stateDir, "identity/1/agent.key"),
					Cert: filepath.Join(stateDir, "identity/1/agent.crt"),
				},
				Present:  true,
				HostID:   "host-0001",
				NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			}
		},
	}
}

// readBundle unpacks the archive into a map of file name to content, with
// the directory of the bundle stripped.
func readBundle(t *testing.T, archive []byte, name string) map[string][]byte {
	t.Helper()
	uncompressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	reader := tar.NewReader(uncompressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(header.Name, name+"/") {
			t.Fatalf("entry %q is outside the bundle directory %q", header.Name, name)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[strings.TrimPrefix(header.Name, name+"/")] = content
	}
	return files
}

func TestSupportBundleRedactsAndDescribesItself(t *testing.T) {
	certPEM, certificate := testCertificate(t)
	sources := fakeBundleSources(t, certPEM)
	name := bundleName(sources)
	if name != "flotestro-support-web-01.example.com-20260915T103000Z" {
		t.Fatalf("name = %q", name)
	}

	var archive bytes.Buffer
	manifest, err := writeSupportBundle(context.Background(), sources, name, &archive)
	if err != nil {
		t.Fatal(err)
	}
	files := readBundle(t, archive.Bytes(), name)

	// Nothing that was a secret on the host is in the archive in the clear,
	// and the key was never even asked for.
	for fileName, content := range files {
		for _, secret := range []string{"tok-0123456789", "hunter2", "MUSTNOTLEAVE", "PRIVATE KEY"} {
			if bytes.Contains(content, []byte(secret)) {
				t.Fatalf("%s holds %q:\n%s", fileName, secret, content)
			}
		}
	}
	if got := string(files["agent.env"]); got != "FLOTESTRO_ENROLLMENT_TOKEN=[redacted]\nFLOTESTRO_GATEWAY_URL=https://gw.example.com:8443\n" {
		t.Fatalf("agent.env = %q", got)
	}
	if got := string(files["journal-agent.txt"]); !strings.Contains(got, "proxy_password=[redacted]") {
		t.Fatalf("journal-agent.txt = %q", got)
	}
	// A code that names the token is a code, not a value, and the report
	// stays valid JSON after the redaction.
	var report map[string]any
	if err := json.Unmarshal(files["diagnose.json"], &report); err != nil {
		t.Fatalf("diagnose.json is not JSON after the redaction: %v\n%s", err, files["diagnose.json"])
	}
	if !bytes.Contains(files["diagnose.json"], []byte("enrollment_token_lingering")) {
		t.Fatalf("diagnose.json lost its error code:\n%s", files["diagnose.json"])
	}
	if got := string(files["agent.yaml"]); got != goodConfiguration {
		t.Fatalf("agent.yaml changed although it holds no secret: %q", got)
	}
	if got := string(files["systemctl-status.txt"]); !strings.Contains(got, "inactive (dead)") {
		t.Fatalf("systemctl-status.txt = %q", got)
	}

	// The identity is described by the fields the panel searches by.
	var identity identityMetadata
	if err := json.Unmarshal(files["identity.json"], &identity); err != nil {
		t.Fatal(err)
	}
	if !identity.Present || identity.HostID != "host-0001" || identity.Serial != certificate.SerialNumber.Text(16) ||
		len(identity.Fingerprint) != 64 || !identity.NotAfter.Equal(certificate.NotAfter) || identity.Error != "" {
		t.Fatalf("identity = %+v", identity)
	}

	// The manifest lists every file, counts the redactions and names the
	// source that could not be read - the bundle is still made.
	var written bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &written); err != nil {
		t.Fatal(err)
	}
	if written.Hostname != "web-01.example.com" || !written.CreatedAt.Equal(sources.Now()) || !strings.Contains(written.Tool, "flotestro-agentctl") {
		t.Fatalf("manifest = %+v", written)
	}
	if len(written.Entries) != len(manifest.Entries) || len(files) != len(written.Entries)+1 {
		t.Fatalf("manifest lists %d entries, the archive holds %d files: %+v", len(written.Entries), len(files), written.Entries)
	}
	byName := map[string]bundleEntry{}
	for _, entry := range written.Entries {
		if _, present := files[entry.Name]; !present {
			t.Fatalf("the manifest names %s, which is not in the archive", entry.Name)
		}
		if entry.Bytes != len(files[entry.Name]) {
			t.Fatalf("%s: manifest says %d bytes, the archive holds %d", entry.Name, entry.Bytes, len(files[entry.Name]))
		}
		if entry.SHA256 != digestOf(files[entry.Name]) {
			t.Fatalf("%s: the manifest digest does not describe the file in the archive", entry.Name)
		}
		byName[entry.Name] = entry
	}
	if byName["agent.env"].Redactions != 1 || byName["journal-agent.txt"].Redactions != 1 || byName["agent.yaml"].Redactions != 0 {
		t.Fatalf("redactions = env %d, journal %d, yaml %d", byName["agent.env"].Redactions,
			byName["journal-agent.txt"].Redactions, byName["agent.yaml"].Redactions)
	}
	if !strings.Contains(byName["journal-helper.txt"].Error, "permission denied") {
		t.Fatalf("journal-helper.txt error = %q", byName["journal-helper.txt"].Error)
	}
	if byName["systemctl-status.txt"].Error != "" {
		t.Fatalf("an inactive unit was recorded as an error: %q", byName["systemctl-status.txt"].Error)
	}
	if !strings.Contains(written.Redaction, "token") || !strings.Contains(written.Redaction, "never") {
		t.Fatalf("redaction note = %q", written.Redaction)
	}
}

func TestSupportBundleWritesTheArchiveWhereAsked(t *testing.T) {
	certPEM, _ := testCertificate(t)
	real := bundleSourcesFor
	bundleSourcesFor = func(configPath, environmentPath string) bundleSources {
		sources := fakeBundleSources(t, certPEM)
		if configPath != "/etc/flotestro/agent.yaml" || environmentPath != DefaultEnvironmentPath {
			t.Fatalf("sources asked for %s and %s", configPath, environmentPath)
		}
		return sources
	}
	defer func() { bundleSourcesFor = real }()

	output := filepath.Join(t.TempDir(), "bundle.tar.gz")
	var out, errOut bytes.Buffer
	if code := run([]string{"support-bundle", "--output", output}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, the bundle holds the journal and must be private", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), output) || !strings.Contains(out.String(), "Redactions:   2") ||
		!strings.Contains(out.String(), "Partial:      1 file") {
		t.Fatalf("the summary does not say where the bundle went and what was taken out: %q", out.String())
	}
	archive, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if files := readBundle(t, archive, bundleName(fakeBundleSources(t, certPEM))); files["manifest.json"] == nil {
		t.Fatal("the archive on disk has no manifest")
	}

	// An existing file is not overwritten: in a shared directory it may be
	// somebody else's.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"support-bundle", "--output", output}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d on an existing file: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "exist") {
		t.Fatalf("the refusal does not say why: %q", errOut.String())
	}
}

// The archive has a digest of its own. It cannot live inside the archive - the
// manifest is one of the files it would describe - so it lies beside it, and
// the verification reads it.
func TestTheBundleCarriesADigestOfItself(t *testing.T) {
	certPEM, _ := testCertificate(t)
	real := bundleSourcesFor
	bundleSourcesFor = func(string, string) bundleSources { return fakeBundleSources(t, certPEM) }
	defer func() { bundleSourcesFor = real }()

	output := filepath.Join(t.TempDir(), "bundle.tar.gz")
	var out, errOut bytes.Buffer
	if code := run([]string{"support-bundle", "--output", output}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	archive, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestOf(archive)
	if !strings.Contains(out.String(), "sha256:"+digest) {
		t.Fatalf("the summary does not name the digest of the archive: %q", out.String())
	}
	stated, err := os.ReadFile(output + ".sha256")
	if err != nil {
		t.Fatalf("nothing was written beside the bundle: %v", err)
	}
	if string(stated) != digest+"  bundle.tar.gz\n" {
		t.Fatalf("the checksum file reads %q", string(stated))
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"support-bundle", "--verify", output}, &out, &errOut); code != 0 {
		t.Fatalf("the verification refused a bundle that matches its digest: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "matches the digest") {
		t.Fatalf("the verification says nothing about the digest: %q", out.String())
	}

	// A bundle that is not the one the digest describes is refused: a digest
	// nobody compares is decoration.
	other := digestOf([]byte("another bundle"))
	if err := os.WriteFile(output+".sha256", []byte(other+"  bundle.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"support-bundle", "--verify", output}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d for a bundle that does not match its digest", code)
	}
	if !strings.Contains(errOut.String(), "not the one the digest") {
		t.Fatalf("the refusal does not say what is wrong: %q", errOut.String())
	}
}

// Every collector says what it produces before it produces it: no field
// without a sensitivity, and no secret field without a reason for leaving it
// out.
func TestEveryCollectorDeclaresTheSensitivityOfItsFields(t *testing.T) {
	certPEM, _ := testCertificate(t)
	sources := fakeBundleSources(t, certPEM)
	collectors := bundleCollectors(sources)
	if len(collectors) == 0 {
		t.Fatal("the bundle collects nothing")
	}
	names := map[string]bool{}
	for _, source := range collectors {
		if source.Name == "" || source.Source == "" || source.Collect == nil {
			t.Fatalf("collector %+v does not say what it is", source)
		}
		if names[source.Name] {
			t.Fatalf("two collectors write %s", source.Name)
		}
		names[source.Name] = true
		if len(source.Fields) == 0 {
			t.Fatalf("%s declares no field", source.Name)
		}
		for _, declared := range source.Fields {
			switch declared.Sensitivity {
			case fieldPublic, fieldSensitive:
				if declared.Why != "" {
					t.Fatalf("%s: %s travels and still explains itself", source.Name, declared.Name)
				}
			case fieldSecret:
				if declared.Why == "" {
					t.Fatalf("%s: %s is left out without a reason", source.Name, declared.Name)
				}
			default:
				t.Fatalf("%s: %s has the sensitivity %q", source.Name, declared.Name, declared.Sensitivity)
			}
			if declared.Name == "" {
				t.Fatalf("%s declares a field without a name", source.Name)
			}
		}
	}
	// The two things a bundle must never carry are declared where they are
	// known: with the file they would have been in.
	for _, want := range []struct{ file, field string }{
		{"agent.env", "FLOTESTRO_ENROLLMENT_TOKEN"},
		{"identity.json", "private key"},
	} {
		found := false
		for _, source := range collectors {
			if source.Name != want.file {
				continue
			}
			for _, declared := range source.Fields {
				if declared.Name == want.field && declared.Sensitivity == fieldSecret {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("%s does not declare %s as secret", want.file, want.field)
		}
	}
}

// The manifest carries the policy the bundle was made under, the fields of
// every file and what was left out - otherwise a bundle silent about its gaps
// reads like a complete one.
func TestTheManifestSaysWhatWasLeftOutAndUnderWhichPolicy(t *testing.T) {
	certPEM, _ := testCertificate(t)
	sources := fakeBundleSources(t, certPEM)
	name := bundleName(sources)
	var archive bytes.Buffer
	if _, err := writeSupportBundle(context.Background(), sources, name, &archive); err != nil {
		t.Fatal(err)
	}
	files := readBundle(t, archive.Bytes(), name)
	var written bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &written); err != nil {
		t.Fatal(err)
	}
	if written.RedactionPolicy != redactionPolicy || !written.Scanned {
		t.Fatalf("manifest = %+v", written)
	}
	byName := map[string]bundleEntry{}
	for _, entry := range written.Entries {
		if len(entry.Fields) == 0 {
			t.Fatalf("%s is in the bundle without saying what it carries", entry.Name)
		}
		byName[entry.Name] = entry
	}
	if len(written.Omitted) == 0 {
		t.Fatal("the manifest leaves nothing out, although the key and the token are never collected")
	}
	for _, left := range written.Omitted {
		if left.File == "" || left.Field == "" || left.Why == "" {
			t.Fatalf("omission = %+v", left)
		}
		if _, present := byName[left.File]; !present {
			t.Fatalf("the manifest leaves out %s of %s, which is not in the bundle", left.Field, left.File)
		}
	}
	// What is declared secret is not in the file it was declared for.
	if bytes.Contains(files["identity.json"], []byte("PRIVATE KEY")) {
		t.Fatalf("identity.json holds the key:\n%s", files["identity.json"])
	}
	if bytes.Contains(files["agent.env"], []byte("tok-0123456789")) {
		t.Fatalf("agent.env holds the token:\n%s", files["agent.env"])
	}
}

// leakyBundleSources is a host whose journal quotes something no key names -
// the case the redaction cannot catch and the scanner must.
func leakyBundleSources(t *testing.T, certPEM []byte, leak string) bundleSources {
	t.Helper()
	sources := fakeBundleSources(t, certPEM)
	command := sources.Command
	sources.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, "journalctl -u flotestro-agent.service") {
			return []byte(leak), nil
		}
		return command(ctx, name, args...)
	}
	return sources
}

// The private key of the host in a journal line: the redaction has no key
// name to go by, so the bundle is refused rather than sent.
func TestABundleCarryingAKeyFailsWithItsCode(t *testing.T) {
	certPEM, _ := testCertificate(t)
	leak := "Sep 15 10:29:58 web-01 flotestro-agent[42]: -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n-----END EC PRIVATE KEY-----\n"
	real := bundleSourcesFor
	bundleSourcesFor = func(string, string) bundleSources { return leakyBundleSources(t, certPEM, leak) }
	defer func() { bundleSourcesFor = real }()

	output := filepath.Join(t.TempDir(), "bundle.tar.gz")
	var out, errOut bytes.Buffer
	if code := run([]string{"support-bundle", "--output", output}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "bundle_private_key_found") ||
		!strings.Contains(errOut.String(), "journal-agent.txt") {
		t.Fatalf("the refusal does not name the file and the code: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "MHcCAQEEIA") {
		t.Fatalf("the refusal quotes the finding: %q", errOut.String())
	}
	// A bundle that would leak does not stay on the disk for somebody to
	// find and send.
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("the incomplete bundle is still there: %v", err)
	}
}

// The other kinds the scanner refuses a bundle for, each with its own code.
func TestTheScannerNamesEveryKindItRefuses(t *testing.T) {
	cases := []struct {
		name, content, code string
	}{
		{"private key", "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----", "bundle_private_key_found"},
		{"bearer token", `curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"`, "bundle_bearer_token_found"},
		{"password in a URL", "proxy https://operator:hunter2@proxy.example.com:3128 refused", "bundle_password_in_url_found"},
		{"enrollment token", "enrolling with flt_9f8e7d6c5b4a3210 now", "bundle_enrollment_token_found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := scanContent("journal-agent.txt", []byte(c.content))
			if len(findings) != 1 || findings[0].Code != c.code || findings[0].File != "journal-agent.txt" {
				t.Fatalf("findings = %+v", findings)
			}
			if findings[0].Kind == "" {
				t.Fatalf("finding without a kind: %+v", findings[0])
			}
		})
	}
	// What the redaction already took out is a shape, not a secret: a bundle
	// is not refused for the trace of its own redaction.
	if findings := scanContent("agent.env", []byte("https://operator:[redacted]@proxy.example.com:3128")); len(findings) != 0 {
		t.Fatalf("a redacted value was taken for a finding: %+v", findings)
	}
	if findings := scanContent("agent.yaml", []byte(goodConfiguration)); len(findings) != 0 {
		t.Fatalf("a configuration with no secret was refused: %+v", findings)
	}
}

// --verify holds a bundle somebody already has against the same scanner, and
// says which file and what kind of thing - never the thing itself.
func TestVerifyNamesTheFileAndTheKindOfFinding(t *testing.T) {
	certPEM, _ := testCertificate(t)
	leak := "Sep 15 10:29:58 web-01 flotestro-agent[42]: -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n-----END EC PRIVATE KEY-----\n"
	sources := leakyBundleSources(t, certPEM, leak)
	name := bundleName(sources)
	// The archive is written past the generation on purpose: --verify exists
	// for bundles that are already out there, however they were made.
	var archive bytes.Buffer
	if _, err := writeSupportBundle(context.Background(), sources, name, &archive); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "old-bundle.tar.gz")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := run([]string{"support-bundle", "--verify", path}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "journal-agent.txt") ||
		!strings.Contains(errOut.String(), "bundle_private_key_found") {
		t.Fatalf("the report does not name the file and the kind: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "MHcCAQEEIA") || strings.Contains(out.String(), "MHcCAQEEIA") {
		t.Fatalf("the report quotes the finding: %q%q", out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Policy:       "+redactionPolicy) {
		t.Fatalf("the report does not say under which policy the bundle was made: %q", out.String())
	}
}

// A bundle that holds nothing it should not is said to be clean, so that an
// operator can prove what they are about to send.
func TestVerifyPassesACleanBundle(t *testing.T) {
	certPEM, _ := testCertificate(t)
	real := bundleSourcesFor
	bundleSourcesFor = func(string, string) bundleSources { return fakeBundleSources(t, certPEM) }
	defer func() { bundleSourcesFor = real }()

	output := filepath.Join(t.TempDir(), "bundle.tar.gz")
	var out, errOut bytes.Buffer
	if code := run([]string{"support-bundle", "--output", output}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Scanner:      no finding") || !strings.Contains(out.String(), "Left out:") {
		t.Fatalf("the summary says nothing about the scan: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"support-bundle", "--verify", output}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d: %s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Findings:     none") || errOut.Len() != 0 {
		t.Fatalf("out = %q, err = %q", out.String(), errOut.String())
	}
}
