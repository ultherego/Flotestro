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

	"gopkg.in/yaml.v3"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// The units the bundle reads the journal and the status of.
var bundleUnits = []string{"flotestro-agent.service", "flotestro-helper.service", "flotestro-helper.socket"}

// journalLines bounds what the bundle takes from the journal: enough to see
// the last hours of a failing agent, not the history of the host.
const journalLines = "500"

// redactedValue replaces every value the redaction takes out.
const redactedValue = "[redacted]"

// secretPattern finds a "key: value" or "key=value" line whose key names a
// token, a password or a secret, in YAML, in an environment file, in JSON and
// in a journal line alike.
var secretPattern = regexp.MustCompile(`(?i)("?[\w.-]*(?:token|password|secret)[\w.-]*"?[ \t]*[:=][ \t]*)("?)([^"\s,]*)("?)`)

// redact is the last layer over what the structural redaction has already
// been over: it hides the values of the keys that name a secret and counts
// what it hid.
func redact(content []byte) ([]byte, int) {
	count := 0
	redacted := secretPattern.ReplaceAllFunc(content, func(match []byte) []byte {
		groups := secretPattern.FindSubmatch(match)
		if groups == nil || len(groups[3]) == 0 ||
			string(bytes.Trim(groups[3], `"'`)) == redactedValue {
			// An empty value hides nothing, and a value the structural pass
			// already dropped is not hidden twice - however the writer of the
			// file quoted it; both keep the count honest.
			return match
		}
		count++
		return append(append(append(append([]byte{}, groups[1]...), groups[2]...), redactedValue...), groups[4]...)
	})
	return redacted, count
}

// bundleSources gathers everything a support bundle reads outside the process.
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
type sensitivity string

const (
	// fieldPublic: it says nothing about this host that is not already known to
	// whoever asked for the bundle - a version, the name of a unit, the code of a
	// check.
	fieldPublic sensitivity = "public"
	// fieldSensitive: it describes this host - its addresses, its paths, its
	// journal.
	fieldSensitive sensitivity = "sensitive"
	// fieldSecret: whoever reads it can act as this host.
	fieldSecret sensitivity = "secret"
)

// bundleFormat is the shape of what a collector produces, so that the
// redaction parses the file instead of guessing at its text.
type bundleFormat string

const (
	formatJSON        bundleFormat = "json"
	formatYAML        bundleFormat = "yaml"
	formatEnvironment bundleFormat = "environment"
	// formatText is free text - a journal, a status, a report written for a
	// person - which has no structure to walk.
	formatText bundleFormat = "text"
)

// dropKind says how a field declared secret is kept out of the bundle.
type dropKind string

const (
	// dropNotCollected: the source is never read, so nothing can slip out of it.
	dropNotCollected dropKind = "not_collected"
	// dropStructural: the file is parsed and the value at the declared key is
	// replaced, whatever that key happens to be called.
	dropStructural dropKind = "structural"
	// dropPattern: free text names no key to walk to, so the pattern is all
	// there is for it.
	dropPattern dropKind = "pattern"
)

// field is one thing a collector produces.
type field struct {
	Name        string      `json:"name"`
	Sensitivity sensitivity `json:"sensitivity"`
	// Why says why a secret field is left out. It is empty for a field that
	// travels: a thing that is in the bundle needs no excuse.
	Why string `json:"why,omitempty"`
	// Drop says how a secret field is kept out; Key locates it for a structural
	// drop - the name of a variable in an environment listing, or a dotted path
	// in YAML and JSON where a segment ending in "[]" is a list.
	Drop dropKind `json:"drop,omitempty"`
	Key  string   `json:"key,omitempty"`
}

// collector produces one file of the bundle and declares beforehand what is
// in it and how sensitive every part of it is.
type collector struct {
	// Name is the file in the bundle; Source is where its content came from,
	// in the words the operator would use to fetch it by hand.
	Name   string
	Source string
	// Format is the shape of the content; the structural redaction parses it
	// before the file is written.
	Format bundleFormat
	Fields []field
	// Collect returns the content.
	Collect func(ctx context.Context, sources bundleSources) ([]byte, error)
}

// The typed reasons the manifest gives for what a bundle does not carry.
const (
	codeFieldNotCollected = "bundle_field_not_collected"
	codeFieldRedacted     = "bundle_field_redacted"
	codeFieldPatternOnly  = "bundle_field_pattern_only"
	codeFileUnparsable    = "bundle_file_unparsable"
)

// omitted lists the secret fields of a collector - what was left out of this
// file, and why. dropped names the declared keys the structural pass found, so
// that a key the file never held is not reported as taken out of it.
func (c collector) omitted(dropped map[string]int) []omission {
	var left []omission
	for _, f := range c.Fields {
		if f.Sensitivity != fieldSecret {
			continue
		}
		code := ""
		switch f.Drop {
		case dropNotCollected:
			code = codeFieldNotCollected
		case dropPattern:
			code = codeFieldPatternOnly
		case dropStructural:
			if dropped[f.Key] == 0 {
				continue
			}
			code = codeFieldRedacted
		}
		left = append(left, omission{File: c.Name, Field: f.Name, Why: f.Why, Code: code})
	}
	return left
}

// omission is one thing the bundle does not carry.
type omission struct {
	File  string `json:"file"`
	Field string `json:"field"`
	Why   string `json:"why"`
	// Code is the stable name of the reason, for everything that reads the
	// manifest rather than reads it aloud.
	Code string `json:"code,omitempty"`
}

// secretKeys lists the keys the collector declared secret and asked the
// structural redaction to drop.
func (c collector) secretKeys() []string {
	var keys []string
	for _, f := range c.Fields {
		if f.Sensitivity == fieldSecret && f.Drop == dropStructural && f.Key != "" {
			keys = append(keys, f.Key)
		}
	}
	return keys
}

// redactStructurally parses a collected file and replaces the values the
// collector declared secret - because they were declared, not because a
// pattern recognised them. A file whose shape does not parse comes back as an
// error: what cannot be walked cannot be shown to hold no secret, so the
// caller declares it instead of shipping it.
func redactStructurally(c collector, content []byte) ([]byte, map[string]int, error) {
	dropped := map[string]int{}
	keys := c.secretKeys()
	switch c.Format {
	case formatText:
		if len(keys) > 0 {
			return nil, dropped, errors.New("a key was declared for a file that has no structure to walk")
		}
		return content, dropped, nil
	case formatEnvironment:
		out, err := redactEnvironment(content, keys, dropped)
		return out, dropped, err
	case formatJSON:
		out, err := redactDocument(content, keys, dropped, parseJSON, writeJSON)
		if err != nil {
			return nil, dropped, fmt.Errorf("the content did not parse as %s", c.Format)
		}
		return out, dropped, nil
	case formatYAML:
		out, err := redactDocument(content, keys, dropped, parseYAML, writeYAML)
		if err != nil {
			return nil, dropped, fmt.Errorf("the content did not parse as %s", c.Format)
		}
		return out, dropped, nil
	}
	return nil, dropped, errors.New("the collector declares no format for its content")
}

// environmentAssignment matches a line of an environment listing: an optional
// export, the name of a variable, and the "=" the value follows.
var environmentAssignment = regexp.MustCompile(`^(export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=`)

// redactEnvironment replaces the values of the declared variables. A line that
// is neither blank, a comment nor an assignment leaves the shape of the file
// unknown, and an unknown shape is not shipped.
func redactEnvironment(content []byte, keys []string, dropped map[string]int) ([]byte, error) {
	secret := map[string]bool{}
	for _, key := range keys {
		secret[key] = true
	}
	lines := strings.Split(string(content), "\n")
	for number, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		match := environmentAssignment.FindStringSubmatch(trimmed)
		if match == nil {
			// The line is counted, never quoted: the reason travels in the
			// manifest, where the value of the line must not.
			return nil, fmt.Errorf("line %d is neither an assignment, a comment nor blank", number+1)
		}
		if secret[match[2]] {
			lines[number] = match[1] + match[2] + "=" + redactedValue
			dropped[match[2]]++
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

// redactDocument parses a structured file, drops the declared keys and writes
// it back. A file nothing was dropped from keeps the bytes it was collected
// with, so that the bundle shows what the host holds and not what a marshaller
// would rather write.
func redactDocument(content []byte, keys []string, dropped map[string]int,
	parse func([]byte) (any, error), write func(any) ([]byte, error)) ([]byte, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return content, nil
	}
	document, err := parse(content)
	if err != nil {
		return nil, err
	}
	changed := false
	for _, key := range keys {
		if count := dropPath(document, strings.Split(key, ".")); count > 0 {
			dropped[key] += count
			changed = true
		}
	}
	if !changed {
		return content, nil
	}
	return write(document)
}

// dropPath replaces the value at a declared path and returns how many values
// it replaced. A segment ending in "[]" is a list, every element of which
// carries the rest of the path.
func dropPath(node any, path []string) int {
	if len(path) == 0 {
		return 0
	}
	name, list := strings.CutSuffix(path[0], "[]")
	entry, present := mappingValue(node, name)
	if !present {
		return 0
	}
	if list {
		items, ok := entry.([]any)
		if !ok {
			return 0
		}
		if len(path) == 1 {
			for index := range items {
				items[index] = redactedValue
			}
			return len(items)
		}
		count := 0
		for _, item := range items {
			count += dropPath(item, path[1:])
		}
		return count
	}
	if len(path) == 1 {
		return setMappingValue(node, name, redactedValue)
	}
	return dropPath(entry, path[1:])
}

// mappingValue reads a key of a mapping whichever shape the parser gave it:
// JSON and YAML with string keys give map[string]any, YAML otherwise
// map[any]any.
func mappingValue(node any, name string) (any, bool) {
	switch mapping := node.(type) {
	case map[string]any:
		value, present := mapping[name]
		return value, present
	case map[any]any:
		value, present := mapping[name]
		return value, present
	}
	return nil, false
}

// setMappingValue replaces a key that is there and says how many it replaced.
func setMappingValue(node any, name string, value any) int {
	switch mapping := node.(type) {
	case map[string]any:
		if _, present := mapping[name]; !present {
			return 0
		}
		mapping[name] = value
		return 1
	case map[any]any:
		if _, present := mapping[name]; !present {
			return 0
		}
		mapping[name] = value
		return 1
	}
	return 0
}

// parseJSON reads exactly one JSON document; a number keeps the text it was
// written with, so a file written back is the file that was read.
func parseJSON(content []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("more than one document")
	}
	return document, nil
}

// writeJSON writes a document back the way the bundle writes JSON.
func writeJSON(document any) ([]byte, error) {
	content, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

// parseYAML reads one YAML document. A file of nothing but comments parses to
// nothing, which drops nothing and is not an error.
func parseYAML(content []byte) (any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var document any
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	var next any
	err := decoder.Decode(&next)
	if err == nil {
		return nil, errors.New("more than one document")
	}
	if !errors.Is(err, io.EOF) {
		return nil, err
	}
	return document, nil
}

// writeYAML writes a document back the way the bundle writes YAML.
func writeYAML(document any) ([]byte, error) {
	return yaml.Marshal(document)
}

// withheldNote stands in the bundle in place of a file the structural
// redaction could not parse.
func withheldNote(reason error) []byte {
	return []byte("(withheld: " + codeFileUnparsable + "; " + reason.Error() + ")\n")
}

// bundleEntry describes one file of the bundle in the manifest.
type bundleEntry struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Bytes  int    `json:"bytes"`
	// SHA256 is the digest of this file as it was written, so a file taken
	// out of the archive can be held against the manifest.
	SHA256 string `json:"sha256"`
	// Format is the shape the structural redaction parsed this file as.
	Format bundleFormat `json:"format,omitempty"`
	// Fields is what the collector declared this file carries.
	Fields []field `json:"fields,omitempty"`
	// Withheld names the typed reason the content was not shipped; the file is
	// in the bundle as a note, so that its absence is not silent.
	Withheld string `json:"withheld,omitempty"`
	// Redactions counts the values hidden in this file.
	Redactions int `json:"redactions,omitempty"`
	// Error says why the file is empty or partial; the bundle is still written,
	// because a host whose journal cannot be read is still a host that needs
	// help.
	Error string `json:"error,omitempty"`
}

// redactionPolicy is the version of what the bundle takes out and leaves out.
const redactionPolicy = "3"

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
	// Scanned says the assembled bundle was held against the scanner before it
	// was written.
	Scanned bool `json:"scanned"`
}

// fieldsLeftOut counts the declared fields the bundle does not carry, apart
// from the files it withheld whole.
func (m bundleManifest) fieldsLeftOut() int {
	count := 0
	for _, left := range m.Omitted {
		if left.Code != codeFileUnparsable {
			count++
		}
	}
	return count
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
	// O_EXCL and 0600: the default lands in a shared directory, where a file that
	// already exists may be somebody else's link, and the bundle holds the
	// journal of a service.
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(errOut, "the bundle was not written: %v\n", err)
		return 1
	}
	// The archive is assembled in memory and only then written: an archive that
	// turns out to hold a secret must not exist on disk even for the moment it
	// takes to notice.
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
	digest := digestOf(assembled.Bytes())
	// The digest of the archive cannot live inside it - the manifest is one of
	// the files it would describe - so it lies beside it, in the form
	// "sha256sum -c" reads.
	checksum := target + ".sha256"
	if err := os.WriteFile(checksum, []byte(digest+"  "+filepath.Base(target)+"\n"), 0o600); err != nil {
		fmt.Fprintf(errOut, "the digest was not written next to the bundle: %v\n", err)
		checksum = ""
	}
	fmt.Fprintf(out, "Bundle:       %s\n", target)
	fmt.Fprintf(out, "Digest:       sha256:%s\n", digest)
	if checksum != "" {
		fmt.Fprintf(out, "Checksum:     %s\n", checksum)
	}
	fmt.Fprintf(out, "Files:        %d\n", len(manifest.Entries))
	redactions, partial, withheld := 0, 0, 0
	for _, entry := range manifest.Entries {
		redactions += entry.Redactions
		if entry.Error != "" {
			partial++
		}
		if entry.Withheld != "" {
			withheld++
		}
	}
	fmt.Fprintf(out, "Redactions:   %d\n", redactions)
	fmt.Fprintf(out, "Left out:     %d field(s) declared secret; see manifest.json\n", manifest.fieldsLeftOut())
	fmt.Fprintf(out, "Scanner:      no finding under redaction policy %s\n", manifest.RedactionPolicy)
	if partial > 0 {
		fmt.Fprintf(out, "Partial:      %d file(s) could not be read fully; see manifest.json\n", partial)
	}
	if withheld > 0 {
		fmt.Fprintf(out, "Withheld:     %d file(s) did not parse and were not shipped; see manifest.json\n", withheld)
	}
	return 0
}

// verifyBundle holds an existing bundle against the same scanner the
// generation uses, so that an operator can prove what they are about to send.
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
	fmt.Fprintf(out, "Digest:       sha256:%s\n", digestOf(content))
	if stated, present := statedDigest(path); present {
		if stated == digestOf(content) {
			fmt.Fprint(out, "Checksum:     matches the digest written beside the bundle\n")
		} else {
			fmt.Fprint(errOut, "the bundle is not the one the digest beside it describes\n")
			return 1
		}
	}
	fmt.Fprintf(out, "Files:        %d\n", len(files))
	if manifest, ok := manifestOf(files); ok {
		policy := manifest.RedactionPolicy
		if policy == "" {
			// A bundle from before the policy was versioned says nothing about
			// the rules it was made under, and that is itself worth knowing.
			policy = "not stated"
		}
		fmt.Fprintf(out, "Policy:       %s\n", policy)
		fmt.Fprintf(out, "Left out:     %d field(s) declared secret\n", manifest.fieldsLeftOut())
		if withheld := len(manifest.Omitted) - manifest.fieldsLeftOut(); withheld > 0 {
			fmt.Fprintf(out, "Withheld:     %d file(s) did not parse and were not shipped\n", withheld)
		}
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

// digestOf is the SHA-256 of a file of the bundle, in the form the manifest
// and the checksum beside the archive write it.
func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// statedDigest reads the digest written beside a bundle. A bundle without one
// is not an error: saying nothing was written beside it is the answer.
func statedDigest(path string) (string, bool) {
	content, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return "", false
	}
	digest, _, _ := strings.Cut(strings.TrimSpace(string(content)), " ")
	if len(digest) != sha256.Size*2 {
		return "", false
	}
	return digest, true
}

// unsafeInName matches what a host name must not put into a file name:
// anything a shell or a file system could trip over.
var unsafeInName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// bundleName names the archive and the directory inside it after the host and
// the moment, so that bundles of many hosts do not overwrite each other on the
// desk of the person who reads them.
func bundleName(sources bundleSources) string {
	host, err := sources.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	host = unsafeInName.ReplaceAllString(host, "_")
	return "flotestro-support-" + host + "-" + sources.Now().UTC().Format("20060102T150405Z")
}

// environmentFields declares what the environment listing of the service
// carries. The variables marked secret in environmentSettings are declared
// secret here and dropped by the key they are declared under, so that marking
// one there is enough to keep its value out of a bundle.
func environmentFields() []field {
	fields := make([]field, 0, len(environmentSettings))
	for _, setting := range environmentSettings {
		declared := field{Name: setting.Variable, Sensitivity: fieldSensitive}
		if setting.Secret {
			declared.Sensitivity = fieldSecret
			declared.Drop = dropStructural
			declared.Key = setting.Variable
			declared.Why = "the service marks " + setting.Variable + " secret, so the listing is parsed and " +
				"its value replaced before the bundle is written; whoever read it could act as this host"
		}
		fields = append(fields, declared)
	}
	return fields
}

// bundleCollectors lists what a bundle is made of, in the order it is read.
// Every collector declares its fields.
func bundleCollectors(sources bundleSources) []collector {
	collectors := []collector{
		{
			Name: "diagnose.json", Source: "flotestro-agentctl diagnose --json",
			Format: formatJSON,
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
			Format: formatText,
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
			Format: formatText,
			Fields: []field{
				{Name: "settings with the defaults filled in", Sensitivity: fieldSensitive},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.Effective()
			},
		},
		{
			Name: "agent.yaml", Source: sources.ConfigPath,
			Format: formatYAML,
			Fields: []field{
				{Name: "connection and agent settings", Sensitivity: fieldSensitive},
			},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.ReadFile(sources.ConfigPath)
			},
		},
		{
			Name: "agent.env", Source: sources.EnvironmentPath,
			Format: formatEnvironment,
			Fields: environmentFields(),
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				content, err := sources.ReadFile(sources.EnvironmentPath)
				if os.IsNotExist(err) {
					// The Arch package carries no environment file; its absence
					// is a fact of the host, not a failure of the bundle. The
					// note is a comment, so the listing still parses.
					return []byte("# no environment file\n"), nil
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
			Format: formatText,
			Fields: []field{
				{Name: "the last " + journalLines + " lines of the unit", Sensitivity: fieldSensitive},
				{Name: "values of keys naming a token, a password or a secret", Sensitivity: fieldSecret, Drop: dropPattern,
					Why: "a journal line is written by whoever logged it, so it names no key to walk to; " +
						"a line quoting a variable has the quoted value replaced with " + redactedValue},
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
			Format: formatText,
			Fields: []field{
				{Name: "unit state", Sensitivity: fieldPublic},
				{Name: "command lines and recent log lines", Sensitivity: fieldSensitive},
			},
			Collect: func(ctx context.Context, sources bundleSources) ([]byte, error) {
				content, err := sources.Command(ctx, "systemctl", statusArgs...)
				// systemctl status exits non-zero for a unit that is not running, which is
				// not a failure to read it; only an empty answer is.
				if err != nil && len(content) > 0 {
					err = nil
				}
				return content, err
			},
		},
		collector{
			Name: "os-release", Source: sources.OSReleasePath,
			Format: formatEnvironment,
			Fields: []field{{Name: "distribution and version", Sensitivity: fieldPublic}},
			Collect: func(_ context.Context, sources bundleSources) ([]byte, error) {
				return sources.ReadFile(sources.OSReleasePath)
			},
		},
		collector{
			Name: "identity.json", Source: "the certificate of the identity",
			Format: formatJSON,
			Fields: []field{
				{Name: "host_id", Sensitivity: fieldSensitive},
				{Name: "serial, subject, issuer, validity, fingerprint", Sensitivity: fieldSensitive},
				{Name: "private key", Sensitivity: fieldSecret, Drop: dropNotCollected,
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
func writeSupportBundle(ctx context.Context, sources bundleSources, name string, w io.Writer) (bundleManifest, error) {
	host, _ := sources.Hostname()
	manifest := bundleManifest{
		Tool:            "flotestro-agentctl " + version,
		Hostname:        host,
		CreatedAt:       sources.Now().UTC(),
		RedactionPolicy: redactionPolicy,
		Redaction: "every collected file is parsed and the values of the fields declared secret are replaced with " +
			redactedValue + "; the pattern for keys naming a token, a password or a secret runs after that, " +
			"as the last layer and not the only one; a file whose shape does not parse is declared, not shipped; " +
			"the private key is never read",
		Scanned: true,
	}

	compressed := gzip.NewWriter(w)
	archive := tar.NewWriter(compressed)
	add := func(entry bundleEntry, content []byte) error {
		entry.Bytes = len(content)
		entry.SHA256 = digestOf(content)
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
		entry := bundleEntry{Name: source.Name, Source: source.Source,
			Format: source.Format, Fields: source.Fields}
		if collectErr != nil {
			entry.Error = collectErr.Error()
		}
		// The structural pass drops what the collector declared; the pattern
		// runs after it over what is left, as the backstop for a secret nobody
		// declared. Both run before the file is written, not after, so that a
		// bundle interrupted half-way holds nothing more than a finished one.
		structured, dropped, parseErr := redactStructurally(source, content)
		if parseErr != nil {
			structured = withheldNote(parseErr)
			entry.Withheld = codeFileUnparsable
			manifest.Omitted = append(manifest.Omitted, omission{
				File:  source.Name,
				Field: "the whole file",
				Code:  codeFileUnparsable,
				Why:   parseErr.Error() + "; a shape the redaction cannot walk cannot be shown to hold no secret",
			})
		}
		redacted, count := redact(structured)
		for _, times := range dropped {
			count += times
		}
		entry.Redactions = count
		manifest.Omitted = append(manifest.Omitted, source.omitted(dropped)...)
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
// token.
const enrollmentTokenPrefix = "flt_"

// The kinds of secret that fail the generation of a bundle. The redaction
// hides the values of keys that name a secret.
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

// finding is what the scanner found: which file and what kind of thing.
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
