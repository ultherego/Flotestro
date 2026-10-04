package release

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// The layout of the evidence bundle. The laboratory writes the report it
// produced and the bytes of everything that report names a digest of.
const (
	evidenceReport    = "result.json"
	evidenceLogs      = "logs/"
	evidenceArtifacts = "artifacts/"
)

// evidenceLimit caps what one bundle may expand to. A bundle is supplied to the
// checker, so it is untrusted input: without a cap a small archive can ask the
// checker for all the memory on the runner.
const evidenceLimit = 512 << 20

// Evidence is what a verified bundle came to: the report the laboratory wrote
// and the account of the bytes that back it.
type Evidence struct {
	Report GateReport
	// ReportBytes is result.json exactly as the bundle carried it. The caller
	// that wants to show the report takes it from here: a second reader of the
	// archive is a second answer to "which member is the report", and the two
	// disagreed - this checker accepts ./result.json and the workflow's tar
	// asked for result.json, which exits 2.
	ReportBytes []byte
	// Digest is the bundle itself, so the commit status can name the file the
	// verdict was computed over.
	Digest string
	// Verified counts the files whose bytes matched the digest the report
	// claimed for them.
	Verified int
	Bytes    int64
}

// VerifyEvidence reads a gate bundle and refuses one that does not back its own
// report. It never trusts a field of the report about the bundle: every digest
// is recomputed from the bytes, and the tree hash is compared with the one the
// caller read out of git rather than with the one the report carries about
// itself.
//
// The refusals it exists for: a log replaced after the run, an artefact the
// report does not account for, a report about another commit, and a report
// whose tree is not the tree of the commit git holds.
func VerifyEvidence(bundle io.Reader, sha, treeFromGit string) (Evidence, error) {
	digester := sha256.New()
	// Everything the gzip reader consumes passes through the digester, so the
	// digest is of the bundle as supplied and not of what the tar happened to
	// describe.
	counted := io.TeeReader(bundle, digester)
	stream, err := gzip.NewReader(counted)
	if err != nil {
		return Evidence{}, fmt.Errorf("the evidence bundle is not gzip: %w", err)
	}
	defer stream.Close()

	files := map[string][]byte{}
	var total int64
	reader := tar.NewReader(stream)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Evidence{}, fmt.Errorf("the evidence bundle is not a readable tar: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return Evidence{}, fmt.Errorf("the evidence bundle carries %q, which is not a regular file", header.Name)
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if path.IsAbs(name) || strings.HasPrefix(name, "..") {
			return Evidence{}, fmt.Errorf("the evidence bundle names the path %q, which leaves the bundle", header.Name)
		}
		if _, twice := files[name]; twice {
			return Evidence{}, fmt.Errorf("the evidence bundle carries %q twice; which of the two backs the report is not a question it can answer", name)
		}
		total += header.Size
		if total > evidenceLimit {
			return Evidence{}, fmt.Errorf("the evidence bundle expands past %d bytes", int64(evidenceLimit))
		}
		content, err := io.ReadAll(io.LimitReader(reader, evidenceLimit))
		if err != nil {
			return Evidence{}, fmt.Errorf("reading %q out of the evidence bundle: %w", name, err)
		}
		files[name] = content
	}

	raw, present := files[evidenceReport]
	if !present {
		return Evidence{}, fmt.Errorf("the evidence bundle carries no %s; the report has to come from the bundle, not from a field somebody filled in", evidenceReport)
	}
	report, err := ParseGateReport(raw)
	if err != nil {
		return Evidence{}, err
	}
	if sha != "" && report.SHA != sha {
		return Evidence{}, fmt.Errorf("the bundle reports the commit %s; the verdict was asked for %s", report.SHA, sha)
	}
	// The tree of a commit is git's answer, not the report's. A run of the right
	// commit over the wrong tree is exactly what a pasted report cannot rule out.
	if treeFromGit != "" && report.TreeHash != treeFromGit {
		return Evidence{}, fmt.Errorf(
			"the bundle reports the tree %s; git holds %s for that commit",
			report.TreeHash, treeFromGit)
	}

	accounted := map[string]bool{evidenceReport: true}
	verified := 0
	for _, claimed := range []struct {
		prefix  string
		kind    string
		digests map[string]string
	}{
		{evidenceLogs, "log", report.Logs},
		{evidenceArtifacts, "artefact", report.Artifacts},
	} {
		names := make([]string, 0, len(claimed.digests))
		for name := range claimed.digests {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			at := claimed.prefix + name
			content, carried := files[at]
			if !carried {
				return Evidence{}, fmt.Errorf(
					"the report claims the %s %s and the bundle does not carry %s; a digest without its bytes is a claim, not evidence",
					claimed.kind, name, at)
			}
			got := "sha256:" + hex.EncodeToString(sha256Of(content))
			if got != claimed.digests[name] {
				return Evidence{}, fmt.Errorf(
					"the %s %s in the bundle is %s and the report claims %s",
					claimed.kind, name, got, claimed.digests[name])
			}
			accounted[at] = true
			verified++
		}
	}
	// A file nobody claimed is not harmless: it is evidence the report does not
	// stand behind, and the next reader has no way to tell which of the two the
	// run produced.
	unaccounted := make([]string, 0)
	for name := range files {
		if !accounted[name] {
			unaccounted = append(unaccounted, name)
		}
	}
	if len(unaccounted) > 0 {
		sort.Strings(unaccounted)
		return Evidence{}, fmt.Errorf(
			"the evidence bundle carries %s, which the report does not account for",
			strings.Join(unaccounted, ", "))
	}

	// The digest of the bundle is only complete once the whole stream has been
	// read; the tar reader stops at the end of the last entry.
	if _, err := io.Copy(io.Discard, counted); err != nil {
		return Evidence{}, fmt.Errorf("reading the end of the evidence bundle: %w", err)
	}
	return Evidence{
		Report:      report,
		ReportBytes: raw,
		Digest:      "sha256:" + hex.EncodeToString(digester.Sum(nil)),
		Verified:    verified,
		Bytes:       total,
	}, nil
}

func sha256Of(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}
