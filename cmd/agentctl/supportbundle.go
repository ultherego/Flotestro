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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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

// sensitivity says how a thing a collector produces may travel.
//
// The three answers are the whole policy of the bundle: what is public
// travels, what is sensitive travels in a file nobody but the operator can
// read, and what is secret does not travel at all. A collector says which of
// the three every field of it is before it collects anything, so that the
// decision is made where the field is known and not by a pattern looking at
// the text afterwards.
type sensitivity string

const (
	// fieldPublic: it says nothing about this host that is not already known
	// to whoever asked for the bundle - a version, the name of a unit, the
	// code of a check.
	fieldPublic sensitivity = "public"
	// fieldSensitive: it describes this host - its addresses, its paths, its
	// journal. It travels, and it is why the bundle is written 0600 and goes
	// nowhere on its own.
	fieldSensitive sensitivity = "sensitive"
	// fieldSecret: whoever reads it can act as this host. It never travels:
	// the collector does not even read it, and the manifest says what was
	// left out and why.
	fieldSecret sensitivity = "secret"
)

// field is one thing a collector produces.
type field struct {
	Name        string      `json:"name"`
	Sensitivity sensitivity `json:"sensitivity"`
	// Why says why a secret field is left out. It is empty for a field that
	// travels: a thing that is in the bundle needs no excuse.
	Why string `json:"why,omitempty"`
}

// collector produces one file of the bundle and declares beforehand what is
// in it and how sensitive every part of it is.
type collector struct {
	// Name is the file in the bundle; Source is where its content came from,
	// in the words the operator would use to fetch it by hand.
	Name   string
	Source string
	Fields []field
	// Collect returns the content. An error is recorded in the manifest
	// rather than returned: a host whose journal cannot be read is exactly
	// the host somebody needs a bundle of.
	Collect func(ctx context.Context, sources bundleSources) ([]byte, error)
}

// omitted lists the secret fields of a collector - what was left out of this
// file, and why.
func (c collector) omitted() []omission {
	var left []omission
	for _, f := range c.Fields {
		if f.Sensitivity == fieldSecret {
			left = append(left, omission{File: c.Name, Field: f.Name, Why: f.Why})
		}
	}
	return left
}

// omission is one thing the bundle does not carry.
type omission struct {
	File  string `json:"file"`
	Field string `json:"field"`
	Why   string `json:"why"`
}

// bundleEntry describes one file of the bundle in the manifest.
type bundleEntry struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Bytes  int    `json:"bytes"`
	// Fields is what the collector declared this file carries.
	Fields []field `json:"fields,omitempty"`
	// Redactions counts the values hidden in this file.
	Redactions int `json:"redactions,omitempty"`
	// Error says why the file is empty or partial; the bundle is still
	// written, because a host whose journal cannot be read is still a host
	// that needs help.
	Error string `json:"error,omitempty"`
}

// redactionPolicy is the version of what the bundle takes out and leaves out.
// A bundle read months later is read against the policy it was made under,
// not the one in the reader's head.
const redactionPolicy = "2"

// bundleManifest is the first file to read: what is inside, what was taken
// out, and what was never collected.
type bundleManifest struct {
	Tool      string    `json:"tool"`
	Hostname  string    `json:"hostname"`
	CreatedAt time.Time `json:"created_at"`
	// RedactionPolicy names the version of the policy this bundle was made
	// under; Redaction says in one sentence what that policy is.
	RedactionPolicy string        `json:"redaction_policy"`
	Redaction       string        `json:"redaction"`
	Entries         []bundleEntry `json:"entries"`
	// Omitted names what the collectors refused to put in and why. A bundle
	// that is silent about what it left out reads like a complete one.
	Omitted []omission `json:"omitted,omitempty"`
	// Scanned says the assembled bundle was held against the scanner before
	// it was written. A bundle that failed the scan was not written at all,
	// so the field is true in every bundle that exists - and a reader can
	// check it with --verify rather than take its word.
	Scanned bool `json:"scanned"`
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
// path it went to: nothing of the host leaves it by itself. Every collector
// says beforehand what it produces and how sensitive it is, the secret parts
// are never read, and the assembled archive is held against the scanner
// before it is written: a bundle that leaks is worse than no bundle.
func supportBundleCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("support-bundle", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", agentconfig.DefaultPath, "the configuration file of the agent")
	environment := flags.String("env-file", DefaultEnvironmentPath, "the environment file of the service")
	output := flags.String("output", "", "where to write the archive (default /tmp/flotestro-support-<hostname>-<timestamp>.tar.gz)")
	verify := flags.String("verify", "", "check an existing bundle with the same scanner instead of making one")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *verify != "" {
		return verifyBundle(*verify, out, errOut)
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
	// holds the journal of a service. The name is taken now, before the
	// archive is assembled, so that two bundles started at once do not write
	// over each other.
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(errOut, "the bundle was not written: %v\n", err)
		return 1
	}
	// The archive is assembled in memory and only then written: an archive
	// that turns out to hold a secret must not exist on disk even for the
	// moment it takes to notice.
	var assembled bytes.Buffer
	manifest, err := writeSupportBundle(ctx, sources, name, &assembled)
	if err == nil {
		err = scanAssembled(assembled.Bytes())
	}
	if err == nil {
		_, err = file.Write(assembled.Bytes())
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		// The reserved name goes away with the archive: an incomplete bundle
		// left behind is one somebody sends.
		os.Remove(target)
		fmt.Fprintf(errOut, "the bundle was not written: %v\n", err)
		var leak *leakError
		if errors.As(err, &leak) {
			fmt.Fprintln(errOut, leak.advice())
		}
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
	fmt.Fprintf(out, "Left out:     %d field(s) declared secret; see manifest.json\n", len(manifest.Omitted))
	fmt.Fprintf(out, "Scanner:      no finding under redaction policy %s\n", manifest.RedactionPolicy)
	if partial > 0 {
		fmt.Fprintf(out, "Partial:      %d file(s) could not be read fully; see manifest.json\n", partial)
	}
	return 0
}

// verifyBundle holds an existing bundle against the same scanner the
// generation uses, so that an operator can prove what they are about to send.
//
// It names the file and the kind of the finding and never the finding itself:
// a report of a leak that quotes the secret is one more copy of it.
func verifyBundle(path string, out, errOut io.Writer) int {
	content, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "the bundle was not read: %v\n", err)
		return 1
	}
	files, err := readArchive(bytes.NewReader(content))
	if err != nil {
		fmt.Fprintf(errOut, "the bundle was not read: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Bundle:       %s\n", path)
	fmt.Fprintf(out, "Files:        %d\n", len(files))
	if manifest, ok := manifestOf(files); ok {
		policy := manifest.RedactionPolicy
		if policy == "" {
			// A bundle from before the policy was versioned says nothing about
			// the rules it was made under, and that is itself worth knowing.
			policy = "not stated"
		}
		fmt.Fprintf(out, "Policy:       %s\n", policy)
		fmt.Fprintf(out, "Left out:     %d field(s) declared secret\n", len(manifest.Omitted))
	} else {
		fmt.Fprint(out, "Policy:       no manifest in the bundle\n")
	}
	findings := scanFiles(files)
	if len(findings) == 0 {
		fmt.Fprint(out, "Findings:     none\n")
		return 0
	}
	fmt.Fprintf(out, "Findings:     %d\n", len(findings))
	for _, found := range findings {
		fmt.Fprintf(errOut, "%s: %s (%s)\n", found.File, found.Kind, found.Code)
	}
	fmt.Fprint(errOut, "do not send this bundle; make a new one and report the finding\n")
	return 1
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

// bundleCollectors lists what a bundle is made of, in the order it is read.
//
// Every collector declares its fields. What is declared secret is not
// collected at all - the private key is never opened, the value of an
// enrollment token never reaches the archive - and the manifest says so under
// "omitted": a bundle silent about what it left out reads like a complete
// one.
func bundleCollectors(sources bundleSources) []collector {
	collectors := []collector{
		{
			Name: "diagnose.json", Source: "flotestro-agentctl diagnose --json",
			Fields: []field{
				{Name: "checks[].name", Sensitivity: fieldPublic},
				{Name: "checks[].error_code", Sensitivity: fieldPublic},
				{Name: "checks[].detail", Sensitivity: fieldSensitive},
			},
			Collect: func(ctx context.Context, sources bundleSources) ([]byte, error) {
				return sources.Diagnose(ctx)
			},
		},
		{
			Name: "status.txt", Source: "flotestro-agentctl status",
			Fields: []field{
				{Name: "agent version", Sensitivity: fieldPublic},
				{Name: "identity and connection", Sensitivity: fieldSensitive},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.Status()
			},
		},
		{
			Name: "config-effective.txt", Source: "flotestro-agentctl config show",
			Fields: []field{
				{Name: "settings with the defaults filled in", Sensitivity: fieldSensitive},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.Effective()
			},
		},
		{
			Name: "agent.yaml", Source: sources.ConfigPath,
			Fields: []field{
				{Name: "connection and agent settings", Sensitivity: fieldSensitive},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.ReadFile(sources.ConfigPath)
			},
		},
		{
			Name: "agent.env", Source: sources.EnvironmentPath,
			Fields: []field{
				{Name: "FLOTESTRO_GATEWAY_URL", Sensitivity: fieldSensitive},
				{Name: "FLOTESTRO_ENROLLMENT_TOKEN", Sensitivity: fieldSecret,
					Why: "a token left in the file would let whoever reads the bundle enroll a machine as this host"},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				content, err := sources.ReadFile(sources.EnvironmentPath)
				if os.IsNotExist(err) {
					// The Arch package carries no environment file; its absence
					// is a fact of the host, not a failure of the bundle.
					return []byte("(no environment file)\n"), nil
				}
				return content, err
			},
		},
	}

	for _, unit := range bundleUnits {
		if strings.HasSuffix(unit, ".socket") {
			// A socket unit writes nothing of its own to the journal; its
			// state shows in the status below.
			continue
		}
		short := strings.TrimSuffix(strings.TrimPrefix(unit, "flotestro-"), ".service")
		collectors = append(collectors, collector{
			Name:   "journal-" + short + ".txt",
			Source: "journalctl -u " + unit + " --no-pager -n " + journalLines,
			Fields: []field{
				{Name: "the last " + journalLines + " lines of the unit", Sensitivity: fieldSensitive},
				{Name: "values of keys naming a token, a password or a secret", Sensitivity: fieldSecret,
					Why: "a journal line may quote a variable, and the quoted value is replaced with " + redactedValue},
			},
			Collect: func(ctx context.Context, sources bundleSources) ([]byte, error) {
				return sources.Command(ctx, "journalctl", "-u", unit, "--no-pager", "-n", journalLines)
			},
		})
	}

	statusArgs := append([]string{"status", "--no-pager", "--full"}, bundleUnits...)
	collectors = append(collectors,
		collector{
			Name: "systemctl-status.txt", Source: "systemctl " + strings.Join(statusArgs, " "),
			Fields: []field{
				{Name: "unit state", Sensitivity: fieldPublic},
				{Name: "command lines and recent log lines", Sensitivity: fieldSensitive},
			},
			Collect: func(ctx context.Context, sources bundleSources) ([]byte, error) {
				content, err := sources.Command(ctx, "systemctl", statusArgs...)
				// systemctl status exits non-zero for a unit that is not
				// running, which is not a failure to read it; only an empty
				// answer is.
				if err != nil && len(content) > 0 {
					err = nil
				}
				return content, err
			},
		},
		collector{
			Name: "os-release", Source: sources.OSReleasePath,
			Fields: []field{{Name: "distribution and version", Sensitivity: fieldPublic}},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.ReadFile(sources.OSReleasePath)
			},
		},
		collector{
			Name: "identity.json", Source: "the certificate of the identity",
			Fields: []field{
				{Name: "host_id", Sensitivity: fieldSensitive},
				{Name: "serial, subject, issuer, validity, fingerprint", Sensitivity: fieldSensitive},
				{Name: "private key", Sensitivity: fieldSecret,
					Why: "a bundle goes to people who must not be able to act as this host, so the key is never read"},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				identity, identityErr := describeIdentity(sources)
				content, err := json.MarshalIndent(identity, "", "  ")
				if err != nil {
					return nil, err
				}
				return append(content, '\n'), identityErr
			},
		},
	)
	return collectors
}

// writeSupportBundle gathers the files and writes the archive.
//
// Every file lands in the archive whether its source answered or not; the
// manifest says which did not and why. The manifest goes in last, because it
// describes what was written, and stands first in the listing of the archive
// only by name.
func writeSupportBundle(ctx context.Context, sources bundleSources, name string, w io.Writer) (bundleManifest, error) {
	host, _ := sources.Hostname()
	manifest := bundleManifest{
		Tool:            "flotestro-agentctl " + version,
		Hostname:        host,
		CreatedAt:       sources.Now().UTC(),
		RedactionPolicy: redactionPolicy,
		Redaction: "values of keys matching token, password or secret are replaced with " + redactedValue +
			"; the fields declared secret are never collected; the private key is never read",
		Scanned: true,
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

	for _, source := range bundleCollectors(sources) {
		content, collectErr := source.Collect(ctx, sources)
		// The redaction runs before the file is written, not after, so that a
		// bundle interrupted half-way holds nothing more than a finished one.
		redacted, count := redact(content)
		entry := bundleEntry{Name: source.Name, Source: source.Source,
			Fields: source.Fields, Redactions: count}
		if collectErr != nil {
			entry.Error = collectErr.Error()
		}
		manifest.Omitted = append(manifest.Omitted, source.omitted()...)
		if err := add(entry, redacted); err != nil {
			return manifest, err
		}
	}

	content, err := json.MarshalIndent(manifest, "", "  ")
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

// enrollmentTokenPrefix is what the panel puts in front of an enrollment
// token. It is written out here rather than taken from the package of the
// control plane: that package carries a database driver with it, and the tool
// that runs on every host stays small.
const enrollmentTokenPrefix = "flt_"

// The kinds of secret that fail the generation of a bundle.
//
// The redaction hides the values of keys that name a secret. These are the
// things no key names: a key block pasted into a journal line, a token in a
// header, a password written into a URL. A bundle carrying one of them is not
// redacted and made safe - it is refused, because a bundle that leaks is
// worse than no bundle at all.
type secretKind struct {
	// Kind names what was found, for the person reading the refusal.
	Kind string
	// Code is the stable name of the refusal, for everything else.
	Code    string
	Pattern *regexp.Regexp
}

var bundleSecretKinds = []secretKind{
	{Kind: "private key block", Code: "bundle_private_key_found",
		Pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)},
	{Kind: "bearer token", Code: "bundle_bearer_token_found",
		Pattern: regexp.MustCompile(`(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}`)},
	{Kind: "password in a URL", Code: "bundle_password_in_url_found",
		Pattern: regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:]+:[^\s/@]+@`)},
	{Kind: "enrollment token", Code: "bundle_enrollment_token_found",
		Pattern: regexp.MustCompile(`\b` + enrollmentTokenPrefix + `[A-Za-z0-9_+/=-]{8,}`)},
}

// finding is what the scanner found: which file and what kind of thing. The
// value itself is deliberately absent - a report of a leak that quotes the
// secret is one more copy of it.
type finding struct {
	File string
	Kind string
	Code string
}

// leakError fails the generation of a bundle that would carry a secret.
type leakError struct{ findings []finding }

func (e *leakError) Error() string {
	first := e.findings[0]
	message := fmt.Sprintf("%s holds a %s (%s)", first.File, first.Kind, first.Code)
	if len(e.findings) > 1 {
		message += fmt.Sprintf(" and %d more finding(s)", len(e.findings)-1)
	}
	return message
}

// advice says what to do with a host whose bundle would leak.
func (e *leakError) advice() string {
	return "nothing was left on disk; take the named secret off the host or out of its journal, then make the bundle again"
}

// scanAssembled holds the finished archive against the scanner.
//
// The scan is over the assembled bundle rather than over each file as it is
// made: what matters is what would be sent, and that is the archive.
func scanAssembled(archive []byte) error {
	files, err := readArchive(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	if findings := scanFiles(files); len(findings) > 0 {
		return &leakError{findings: findings}
	}
	return nil
}

// readArchive unpacks a bundle into its files, named as the bundle names
// them without its own directory.
func readArchive(r io.Reader) (map[string][]byte, error) {
	uncompressed, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer uncompressed.Close()
	files := map[string][]byte{}
	reader := tar.NewReader(uncompressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		name := header.Name
		if _, rest, found := strings.Cut(name, "/"); found {
			name = rest
		}
		files[name] = content
	}
}

// scanFiles runs the scanner over every file of a bundle. The findings come
// out in a fixed order, so that two runs over the same bundle read the same.
func scanFiles(files map[string][]byte) []finding {
	var findings []finding
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		findings = append(findings, scanContent(name, files[name])...)
	}
	return findings
}

// scanContent looks for the kinds of secret no key names.
func scanContent(name string, content []byte) []finding {
	var findings []finding
	for _, kind := range bundleSecretKinds {
		found := false
		for _, match := range kind.Pattern.FindAll(content, -1) {
			if bytes.Contains(match, []byte(redactedValue)) {
				// The redaction already took this value out; what is left is
				// the shape of the line, not a secret.
				continue
			}
			found = true
			break
		}
		if found {
			findings = append(findings, finding{File: name, Kind: kind.Kind, Code: kind.Code})
		}
	}
	return findings
}

// manifestOf reads the manifest of an unpacked bundle. A bundle without one
// is not an error here: saying it has none is the answer.
func manifestOf(files map[string][]byte) (bundleManifest, bool) {
	content, present := files["manifest.json"]
	if !present {
		return bundleManifest{}, false
	}
	var manifest bundleManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return bundleManifest{}, false
	}
	return manifest, true
}
