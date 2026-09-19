// Package support assembles the support bundle of the panel: a typed set of
// readings, scanned before it is sealed and handed over.
package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Sensitivity says how a thing a collector produces may travel. The scale is
// the one the agent's bundle uses, so a reader of either reads the same words.
type Sensitivity string

const (
	// FieldPublic says nothing about this installation that whoever asked for
	// the bundle does not already know: a version, the name of a check.
	FieldPublic Sensitivity = "public"
	// FieldSensitive describes this installation: its addresses, its counts,
	// its settings.
	FieldSensitive Sensitivity = "sensitive"
	// FieldSecret: whoever reads it can act as this panel. It is never
	// collected, only declared.
	FieldSecret Sensitivity = "secret"
)

// RedactionPolicy is the version of what the bundle collects and leaves out.
const RedactionPolicy = "1"

// redactionSentence says in one line what that policy is.
const redactionSentence = "the fields declared secret are never collected; " +
	"no credential, key or token of the panel is read, and the assembled archive is held against the scanner"

// Field is one thing a collector produces.
type Field struct {
	Name        string      `json:"name"`
	Sensitivity Sensitivity `json:"sensitivity"`
	// Why says why a secret field is left out; empty for a field that travels.
	Why string `json:"why,omitempty"`
}

// Collector produces one file of the bundle and declares beforehand what is in
// it and how sensitive every part of it is.
type Collector struct {
	// Name is the file in the bundle, Source where its content came from in
	// the words an operator would use to fetch it by hand.
	Name    string
	Source  string
	Fields  []Field
	Collect func(ctx context.Context) ([]byte, error)
}

// omitted lists the secret fields of a collector: what this file does not
// carry, and why.
func (c Collector) omitted() []Omission {
	var left []Omission
	for _, field := range c.Fields {
		if field.Sensitivity == FieldSecret {
			left = append(left, Omission{File: c.Name, Field: field.Name, Why: field.Why})
		}
	}
	return left
}

// Omission is one thing the bundle does not carry.
type Omission struct {
	File  string `json:"file"`
	Field string `json:"field"`
	Why   string `json:"why"`
}

// Entry describes one file of the bundle in the manifest.
type Entry struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Bytes  int    `json:"bytes"`
	// SHA256 is the digest of this file as it was written, so a file taken
	// out of the archive can be held against the manifest.
	SHA256 string  `json:"sha256"`
	Fields []Field `json:"fields,omitempty"`
	// Error says why the file is empty or partial. The bundle is still made:
	// a panel whose database does not answer is exactly the panel a bundle is
	// asked for.
	Error string `json:"error,omitempty"`
}

// Manifest is the first file to read: what is inside, what was left out, and
// under which policy.
type Manifest struct {
	Tool      string    `json:"tool"`
	BundleID  string    `json:"bundle_id"`
	Panel     string    `json:"panel"`
	CreatedAt time.Time `json:"created_at"`
	// RequestedBy and Reason say who asked for this bundle and why; the
	// archive is handed on, and it says on its face what it was made for.
	RequestedBy     string     `json:"requested_by"`
	Reason          string     `json:"reason"`
	RedactionPolicy string     `json:"redaction_policy"`
	Redaction       string     `json:"redaction"`
	Entries         []Entry    `json:"entries"`
	Omitted         []Omission `json:"omitted,omitempty"`
	// Scanned says the assembled archive was held against the scanner before
	// it was sealed.
	Scanned bool `json:"scanned"`
}

// Request is what a bundle is made of and for.
type Request struct {
	BundleID    string
	Panel       string
	Tool        string
	RequestedBy string
	Reason      string
	CreatedAt   time.Time
}

// Build assembles the archive and returns it with its manifest. A bundle the
// scanner finds something in is not written at all.
func Build(ctx context.Context, request Request, collectors []Collector) ([]byte, Manifest, error) {
	manifest := Manifest{
		Tool: request.Tool, BundleID: request.BundleID, Panel: request.Panel,
		CreatedAt: request.CreatedAt.UTC(), RequestedBy: request.RequestedBy, Reason: request.Reason,
		RedactionPolicy: RedactionPolicy, Redaction: redactionSentence, Scanned: true,
	}
	directory := "flotestro-support-" + request.BundleID

	var assembled bytes.Buffer
	compressed := gzip.NewWriter(&assembled)
	archive := tar.NewWriter(compressed)
	add := func(name string, content []byte) error {
		header := &tar.Header{
			Name: directory + "/" + name, Mode: 0o600,
			Size: int64(len(content)), ModTime: manifest.CreatedAt,
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		_, err := archive.Write(content)
		return err
	}

	for _, collector := range collectors {
		content, collectErr := collector.Collect(ctx)
		entry := Entry{Name: collector.Name, Source: collector.Source, Fields: collector.Fields,
			Bytes: len(content), SHA256: Digest(content)}
		if collectErr != nil {
			entry.Error = collectErr.Error()
		}
		manifest.Entries = append(manifest.Entries, entry)
		manifest.Omitted = append(manifest.Omitted, collector.omitted()...)
		if err := add(collector.Name, content); err != nil {
			return nil, manifest, err
		}
	}

	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, manifest, err
	}
	// The manifest describes every other file, so it is not its own entry.
	if err := add("manifest.json", append(document, '\n')); err != nil {
		return nil, manifest, err
	}
	if err := archive.Close(); err != nil {
		return nil, manifest, err
	}
	if err := compressed.Close(); err != nil {
		return nil, manifest, err
	}
	if err := Scan(assembled.Bytes()); err != nil {
		return nil, manifest, err
	}
	return assembled.Bytes(), manifest, nil
}

// Digest is the SHA-256 of a file of the bundle, in the form the manifest
// writes it.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// enrollmentTokenPrefix is what the panel puts in front of an enrollment
// token; apiTokenPrefix in front of a token of the API.
const (
	enrollmentTokenPrefix = "flt_"
	apiTokenPrefix        = "flta_"
)

// secretKind is a kind of secret that fails the generation of a bundle. It is
// the last layer: the collectors never read one in the first place.
type secretKind struct {
	// Kind names what was found, for the person reading the refusal; Code is
	// the stable name of the refusal for everything else.
	Kind    string
	Code    string
	Pattern *regexp.Regexp
}

var secretKinds = []secretKind{
	{Kind: "private key block", Code: "bundle_private_key_found",
		Pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)},
	{Kind: "bearer token", Code: "bundle_bearer_token_found",
		Pattern: regexp.MustCompile(`(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}`)},
	{Kind: "password in a URL", Code: "bundle_password_in_url_found",
		Pattern: regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:]+:[^\s/@]+@`)},
	{Kind: "enrollment token", Code: "bundle_enrollment_token_found",
		Pattern: regexp.MustCompile(`\b` + enrollmentTokenPrefix + `[A-Za-z0-9_+/=-]{8,}`)},
	{Kind: "panel API token", Code: "bundle_api_token_found",
		Pattern: regexp.MustCompile(`\b` + apiTokenPrefix + `[A-Za-z0-9_+/=-]{8,}`)},
}

// Finding is what the scanner found: which file and what kind of thing.
type Finding struct {
	File string `json:"file"`
	Kind string `json:"kind"`
	Code string `json:"code"`
}

// LeakError fails the generation of a bundle that would carry a secret.
type LeakError struct{ Findings []Finding }

func (e *LeakError) Error() string {
	first := e.Findings[0]
	message := fmt.Sprintf("%s holds a %s (%s)", first.File, first.Kind, first.Code)
	if len(e.Findings) > 1 {
		message += fmt.Sprintf(" and %d more finding(s)", len(e.Findings)-1)
	}
	return message
}

// Code is the stable name of the first finding, for the row and the trail.
func (e *LeakError) Code() string { return e.Findings[0].Code }

// Scan holds an assembled archive against the scanner.
func Scan(archive []byte) error {
	files, err := ReadArchive(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	var findings []Finding
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	// A fixed order, so that two runs over the same bundle read the same.
	sort.Strings(names)
	for _, name := range names {
		for _, kind := range secretKinds {
			if kind.Pattern.Find(files[name]) != nil {
				findings = append(findings, Finding{File: name, Kind: kind.Kind, Code: kind.Code})
			}
		}
	}
	if len(findings) > 0 {
		return &LeakError{Findings: findings}
	}
	return nil
}

// ReadArchive unpacks a bundle into its files, named as the bundle names them
// without its own directory.
func ReadArchive(r io.Reader) (map[string][]byte, error) {
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

// JSONCollector wraps a reading that is a document rather than text.
func JSONCollector(name, source string, fields []Field, read func(ctx context.Context) (any, error)) Collector {
	return Collector{Name: name, Source: source, Fields: fields,
		Collect: func(ctx context.Context) ([]byte, error) {
			value, err := read(ctx)
			if value == nil {
				return nil, err
			}
			document, marshalErr := json.MarshalIndent(value, "", "  ")
			if marshalErr != nil {
				return nil, marshalErr
			}
			return append(document, '\n'), err
		},
	}
}
