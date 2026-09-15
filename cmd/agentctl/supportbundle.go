package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// The units the bundle reads the journal and the status of. The socket goes
// with the helper: a helper that never starts is usually a socket that never
// listens, and the journal of the service alone does not show that.
var bundleUnits = []string{"flotestro-agent.service", "flotestro-helper.service", "flotestro-helper.socket"}

// journalLines bounds what the bundle takes from the journal: enough to see
// the last hours of a failing agent, not the history of the host.
const journalLines = "500"

// redactedValue replaces every value the redaction takes out.
const redactedValue = "[redacted]"

// secretPattern finds a "key: value" or "key=value" line whose key names a
// token, a password or a secret, in YAML, in an environment file, in JSON
// and in a journal line alike.
//
// The configuration carries no secrets by design, but the environment file
// used to carry the enrollment token, and a journal line may quote a
// variable. The pattern is broad on purpose: a value redacted for nothing
// costs a question to the operator; a value that slips through costs a
// secret. Group 1 is the key with its separator, 2 and 4 the quotes of the
// value, 3 the value itself.
//
// Only blanks may stand around the separator: a newline there would make
// the value the whole next line, and "token:" with nothing after it would
// swallow the entry below.
var secretPattern = regexp.MustCompile(`(?i)("?[\w.-]*(?:token|password|secret)[\w.-]*"?[ \t]*[:=][ \t]*)("?)([^"\s,]*)("?)`)

// redact hides the values of the keys that name a secret and counts what it
// hid.
func redact(content []byte) ([]byte, int) {
	count := 0
	redacted := secretPattern.ReplaceAllFunc(content, func(match []byte) []byte {
		groups := secretPattern.FindSubmatch(match)
		if groups == nil || len(groups[3]) == 0 {
			// An empty value hides nothing; leaving it alone keeps the
			// count honest.
			return match
		}
		count++
		return append(append(append(append([]byte{}, groups[1]...), groups[2]...), redactedValue...), groups[4]...)
	})
	return redacted, count
}

// bundleSources gathers everything a support bundle reads outside the
// process.
//
// Every source is a field rather than a call, so that a test can build a
// bundle of a host that does not exist and check what ended up inside it.
type bundleSources struct {
	ConfigPath      string
	EnvironmentPath string
	OSReleasePath   string

	Hostname func() (string, error)
	Now      func() time.Time
	// Diagnose returns the report of "diagnose --json".
	Diagnose func(ctx context.Context) ([]byte, error)
	// Status returns the text of "status".
	Status func() ([]byte, error)
	// Effective returns the text of "config show": the settings with the
	// defaults filled in.
	Effective func() ([]byte, error)
	ReadFile  func(path string) ([]byte, error)
	// Command runs a program and returns what it printed; the output is
	// returned also when the program failed, with the error next to it.
	Command  func(ctx context.Context, name string, args ...string) ([]byte, error)
	Identity func(stateDir string) agent.StoredIdentity
}

// bundleSourcesFor makes the sources of a bundle; a test swaps it for a
// host that does not exist.
var bundleSourcesFor = newBundleSources

// newBundleSources wires the bundle to the real host.
func newBundleSources(configPath, environmentPath string) bundleSources {
	return bundleSources{
		ConfigPath:      configPath,
		EnvironmentPath: environmentPath,
		OSReleasePath:   "/etc/os-release",
		Hostname:        os.Hostname,
		Now:             time.Now,
		Diagnose: func(ctx context.Context) ([]byte, error) {
			d := newDiagnostics(configPath)
			d.EnvironmentPath = environmentPath
			var out bytes.Buffer
			err := renderJSON(&out, d.run(ctx))
			return out.Bytes(), err
		},
		Status: func() ([]byte, error) {
			// The exit code of the status is not an error of the bundle: a
			// host with a problem is exactly the host a bundle is made of.
			var out bytes.Buffer
			statusCommand([]string{"--config", configPath}, &out, &out)
			return out.Bytes(), nil
		},
		Effective: func() ([]byte, error) {
			var out bytes.Buffer
			checkConfiguration([]string{"--config", configPath}, &out, &out, true)
			return out.Bytes(), nil
		},
		ReadFile: os.ReadFile,
		Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			command := exec.CommandContext(ctx, name, args...)
			// The tools of the host answer in the language of the locale;
			// the person reading the bundle is not necessarily on that host.
			command.Env = append(os.Environ(), "LC_ALL=C")
			return command.CombinedOutput()
		},
		Identity: agent.ReadIdentity,
	}
}

// bundleEntry describes one file of the bundle in the manifest.
type bundleEntry struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Bytes  int    `json:"bytes"`
	// Redactions counts the values hidden in this file.
	Redactions int `json:"redactions,omitempty"`
	// Error says why the file is empty or partial; the bundle is still
	// written, because a host whose journal cannot be read is still a host
	// that needs help.
	Error string `json:"error,omitempty"`
}

// bundleManifest is the first file to read: what is inside and what was
// taken out.
type bundleManifest struct {
	Tool      string        `json:"tool"`
	Hostname  string        `json:"hostname"`
	CreatedAt time.Time     `json:"created_at"`
	Redaction string        `json:"redaction"`
	Entries   []bundleEntry `json:"entries"`
}

// identityMetadata is what the bundle says about the certificate of the
// host: enough to find it in the panel, never the key.
type identityMetadata struct {
	Present     bool      `json:"present"`
	HostID      string    `json:"host_id,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Expired     bool      `json:"expired"`
	Fingerprint string    `json:"fingerprint_sha256,omitempty"`
	Certificate string    `json:"certificate_path,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// supportBundleCommand writes everything a support engineer asks for first
// into one archive.
//
// The bundle is made only on an explicit command and the operator sees the
// path it went to: nothing of the host leaves it by itself. Secrets are
// redacted before they are written, not after, so a bundle interrupted
// half-way holds nothing more than a finished one.
func supportBundleCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("support-bundle", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	environment := flags.String("env-file", DefaultEnvironmentPath, "the environment file of the service")
	output := flags.String("output", "", "where to write the archive (default /tmp/flotestro-support-<hostname>-<timestamp>.tar.gz)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sources := bundleSourcesFor(*path, *environment)
	name := bundleName(sources)
	target := *output
	if target == "" {
		target = filepath.Join(os.TempDir(), name+".tar.gz")
	}
	// O_EXCL and 0600: the default lands in a shared directory, where a
	// file that already exists may be somebody else's link, and the bundle
	// holds the journal of a service.
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(errOut, "the bundle was not written: %v\n", err)
		return 1
	}
	manifest, err := writeSupportBundle(ctx, sources, name, file)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(target)
		fmt.Fprintf(errOut, "the bundle was not written: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Bundle:       %s\n", target)
	fmt.Fprintf(out, "Files:        %d\n", len(manifest.Entries))
	redactions, partial := 0, 0
	for _, entry := range manifest.Entries {
		redactions += entry.Redactions
		if entry.Error != "" {
			partial++
		}
	}
	fmt.Fprintf(out, "Redactions:   %d\n", redactions)
	if partial > 0 {
		fmt.Fprintf(out, "Partial:      %d file(s) could not be read fully; see manifest.json\n", partial)
	}
	return 0
}

// unsafeInName matches what a host name must not put into a file name:
// anything a shell or a file system could trip over.
var unsafeInName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// bundleName names the archive and the directory inside it after the host
// and the moment, so that bundles of many hosts do not overwrite each other
// on the desk of the person who reads them.
func bundleName(sources bundleSources) string {
	host, err := sources.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	host = unsafeInName.ReplaceAllString(host, "_")
	return "flotestro-support-" + host + "-" + sources.Now().UTC().Format("20060102T150405Z")
}

// writeSupportBundle gathers the files and writes the archive.
//
// Every file lands in the archive whether its source answered or not; the
// manifest says which did not and why. The manifest goes in last, because
// it describes what was written, and stands first in the listing of the
// archive only by name.
func writeSupportBundle(ctx context.Context, sources bundleSources, name string, w io.Writer) (bundleManifest, error) {
	host, _ := sources.Hostname()
	manifest := bundleManifest{
		Tool:      "flotestro-agentctl " + version,
		Hostname:  host,
		CreatedAt: sources.Now().UTC(),
		Redaction: "values of keys matching token, password or secret are replaced with " + redactedValue + "; the private key is never read",
	}

	compressed := gzip.NewWriter(w)
	archive := tar.NewWriter(compressed)
	add := func(entry bundleEntry, content []byte) error {
		entry.Bytes = len(content)
		manifest.Entries = append(manifest.Entries, entry)
		header := &tar.Header{
			Name:    name + "/" + entry.Name,
			Mode:    0o600,
			Size:    int64(len(content)),
			ModTime: manifest.CreatedAt,
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		_, err := archive.Write(content)
		return err
	}
	// text adds a file after the redaction; the error of the source is
	// recorded, not returned, so that the rest of the bundle is still made.
	text := func(fileName, source string, content []byte, err error) error {
		redacted, count := redact(content)
		entry := bundleEntry{Name: fileName, Source: source, Redactions: count}
		if err != nil {
			entry.Error = err.Error()
		}
		return add(entry, redacted)
	}

	content, err := sources.Diagnose(ctx)
	if err := text("diagnose.json", "flotestro-agentctl diagnose --json", content, err); err != nil {
		return manifest, err
	}
	content, err = sources.Status()
	if err := text("status.txt", "flotestro-agentctl status", content, err); err != nil {
		return manifest, err
	}
	content, err = sources.Effective()
	if err := text("config-effective.txt", "flotestro-agentctl config show", content, err); err != nil {
		return manifest, err
	}
	content, err = sources.ReadFile(sources.ConfigPath)
	if err := text("agent.yaml", sources.ConfigPath, content, err); err != nil {
		return manifest, err
	}
	content, err = sources.ReadFile(sources.EnvironmentPath)
	if os.IsNotExist(err) {
		// The Arch package carries no environment file; its absence is a
		// fact of the host, not a failure of the bundle.
		content, err = []byte("(no environment file)\n"), nil
	}
	if err := text("agent.env", sources.EnvironmentPath, content, err); err != nil {
		return manifest, err
	}
	for _, unit := range bundleUnits {
		if strings.HasSuffix(unit, ".socket") {
			// A socket unit writes nothing of its own to the journal; its
			// state shows in the status below.
			continue
		}
		short := strings.TrimSuffix(strings.TrimPrefix(unit, "flotestro-"), ".service")
		content, err = sources.Command(ctx, "journalctl", "-u", unit, "--no-pager", "-n", journalLines)
		if err := text("journal-"+short+".txt", "journalctl -u "+unit+" --no-pager -n "+journalLines, content, err); err != nil {
			return manifest, err
		}
	}
	statusArgs := append([]string{"status", "--no-pager", "--full"}, bundleUnits...)
	content, err = sources.Command(ctx, "systemctl", statusArgs...)
	// systemctl status exits non-zero for a unit that is not running, which
	// is not a failure to read it; only an empty answer is.
	if err != nil && len(content) > 0 {
		err = nil
	}
	if err := text("systemctl-status.txt", "systemctl "+strings.Join(statusArgs, " "), content, err); err != nil {
		return manifest, err
	}
	content, err = sources.ReadFile(sources.OSReleasePath)
	if err := text("os-release", sources.OSReleasePath, content, err); err != nil {
		return manifest, err
	}

	identity, identityErr := describeIdentity(sources)
	content, err = json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return manifest, err
	}
	entry := bundleEntry{Name: "identity.json", Source: "the certificate of the identity"}
	if identityErr != nil {
		entry.Error = identityErr.Error()
	}
	if err := add(entry, append(content, '\n')); err != nil {
		return manifest, err
	}

	content, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	// The manifest describes every other file, so it is not its own entry.
	header := &tar.Header{Name: name + "/manifest.json", Mode: 0o600, Size: int64(len(content) + 1), ModTime: manifest.CreatedAt}
	if err := archive.WriteHeader(header); err != nil {
		return manifest, err
	}
	if _, err := archive.Write(append(content, '\n')); err != nil {
		return manifest, err
	}
	if err := archive.Close(); err != nil {
		return manifest, err
	}
	return manifest, compressed.Close()
}

// describeIdentity reads the certificate of the host and nothing else.
//
// The key lies next to the certificate and is never opened: a bundle goes
// to people who must not be able to impersonate the host.
func describeIdentity(sources bundleSources) (identityMetadata, error) {
	cfg, err := agentconfig.Read(bytes.NewReader(readOrEmpty(sources, sources.ConfigPath)))
	if err != nil {
		return identityMetadata{Error: "the configuration did not load: " + err.Error()}, err
	}
	stored := sources.Identity(cfg.Agent.StateDir)
	metadata := identityMetadata{
		Present:     stored.Present,
		HostID:      stored.HostID,
		NotAfter:    stored.NotAfter,
		Expired:     stored.Expired,
		Certificate: stored.Paths.Cert,
		Error:       stored.Err,
	}
	if !stored.Present {
		return metadata, nil
	}
	content, err := sources.ReadFile(stored.Paths.Cert)
	if err != nil {
		metadata.Error = err.Error()
		return metadata, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		err := fmt.Errorf("%s is not valid PEM", stored.Paths.Cert)
		metadata.Error = err.Error()
		return metadata, err
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		metadata.Error = err.Error()
		return metadata, err
	}
	sum := sha256.Sum256(certificate.Raw)
	metadata.Serial = certificate.SerialNumber.Text(16)
	metadata.Subject = certificate.Subject.String()
	metadata.Issuer = certificate.Issuer.String()
	metadata.NotBefore = certificate.NotBefore
	metadata.NotAfter = certificate.NotAfter
	metadata.Fingerprint = hex.EncodeToString(sum[:])
	return metadata, nil
}

// readOrEmpty reads a file for a step that treats a missing file like an
// empty one: the step reports its own error on what it finds.
func readOrEmpty(sources bundleSources, path string) []byte {
	content, err := sources.ReadFile(path)
	if err != nil {
		return nil
	}
	return content
}
