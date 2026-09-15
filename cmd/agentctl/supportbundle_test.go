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
// whose key lies next to the certificate.
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
