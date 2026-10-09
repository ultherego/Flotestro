package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// publishedStep runs the one step of the release workflow's "published" job
// with curl and gh stubbed, and returns what it printed and whether it passed.
//
// The step is shell in a workflow file, which nothing ever executes until a tag
// is pushed - and a workflow is validated only when something runs it, which is
// how the 0.62.0 tag ended in a startup_failure with no job and no log. This
// runs it here instead, over a served directory the test lays out.
func publishedStep(t *testing.T, served map[string]string, pagesStatus string) (string, bool) {
	t.Helper()
	parsed := parsedWorkflow(t, "release.yml")
	job, found := parsed.Jobs["published"]
	if !found {
		t.Fatal("release.yml declares no job \"published\": the release no longer asks the " +
			"address whether it serves what was just published")
	}
	if len(job.Steps) != 1 {
		t.Fatalf("the published job has %d steps; this test runs one", len(job.Steps))
	}

	dir := t.TempDir()
	root := filepath.Join(dir, "served")
	for path, body := range served {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// curl, over a directory instead of the network: the path after the host is
	// looked up under served/, and anything absent answers 404 the way the
	// address would.
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/usr/bin/env bash\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("curl", `
out=""; writeout=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) writeout="$2"; shift 2 ;;
    --max-time) shift 2 ;;
    -fsS|-fsS*|-s|-f|-S) shift ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
path="${url#*github.io/}"; path="${path#*/}"
file="$SERVED/$path"
if [ -f "$file" ]; then
  if [ -n "$out" ]; then cp "$file" "$out"; else cat "$file"; fi
  [ -n "$writeout" ] && printf '200\n'
  exit 0
fi
[ -n "$writeout" ] && printf '404\n'
exit 22
`)
	write("gh", `printf '%s\n' "$PAGES_STATUS"`)

	summary := filepath.Join(dir, "summary.md")
	script := filepath.Join(dir, "step.sh")
	if err := os.WriteFile(script, []byte(job.Steps[0].Run), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", script)
	command.Dir = dir
	command.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"SERVED="+root,
		"PAGES_STATUS="+pagesStatus,
		"GITHUB_STEP_SUMMARY="+summary,
		"GH_TOKEN=stub",
		"REPOSITORY=ultherego/Flotestro",
		"CHANNEL=stable",
		"VERSION=0.62.1",
		"PUBLISHED_WAIT_SECONDS=1",
		"PUBLISHED_POLL_SECONDS=1",
	)
	output, err := command.CombinedOutput()
	return string(output), err == nil
}

// index writes a Packages stanza of the shape the signed repository really
// publishes: the one at the address on 09.10, with the digest of the body.
//
// Filename is relative to the root of the deb repository, which is
// .../packages/deb, so the served path below carries that deb/ as the
// published tree does. The first version of this test served the file one
// directory higher - where the step then looked for it - and both halves
// agreed with each other and with nothing else. The release of 0.62.1 failed
// on that, over an address no repository ever had.
func index(version, body string) (string, string) {
	sum := sha256.Sum256([]byte(body))
	digest := hex.EncodeToString(sum[:])
	stanza := fmt.Sprintf(`Package: flotestro-agent
Version: %s
Architecture: amd64
Filename: pool/stable/flotestro-agent_%s_amd64.deb
Size: %d
SHA256: %s

`, version, version, len(body), digest)
	return "packages/deb/dists/stable/main/binary-amd64/Packages",
		"Package: flotestro-agent\nVersion: 0.60.4\nFilename: pool/stable/old.deb\nSHA256: 00\n\n" + stanza
}

func TestTheReleaseAcceptsAnAddressThatServesIt(t *testing.T) {
	body := "the package as the address serves it"
	path, packages := index("0.62.1", body)
	output, ok := publishedStep(t, map[string]string{
		path: packages,
		"packages/deb/pool/stable/flotestro-agent_0.62.1_amd64.deb": body,
		"packages/rpm/stable/repodata/repomd.xml":                   "<repomd/>",
		"packages/arch/stable/flotestro.db":                         "db",
	}, "built")
	if !ok {
		t.Fatalf("the step refused an address that serves the release:\n%s", output)
	}
	for _, want := range []string{"names 0.62.1", "matches the digest",
		// The address it asked for: the one the published repository really
		// serves, with the deb/ that Filename is relative to.
		"/packages/deb/pool/stable/"} {
		if !strings.Contains(output, want) {
			t.Errorf("the step passed without saying %q:\n%s", want, output)
		}
	}
}

// The failure of 08.10: gh-pages held the files, the build had failed, and the
// address went on serving the previous release while the release announced
// itself as published.
func TestTheReleaseRefusesAnAddressStillServingTheOldVersion(t *testing.T) {
	path, packages := index("0.60.4", "old")
	output, ok := publishedStep(t, map[string]string{
		path: packages,
		"packages/rpm/stable/repodata/repomd.xml": "<repomd/>",
		"packages/arch/stable/flotestro.db":       "db",
	}, "errored")
	if ok {
		t.Fatalf("the step accepted an address that does not name the version:\n%s", output)
	}
	if !strings.Contains(output, "Pages build errored") {
		t.Errorf("the step did not name the failed build as the reason:\n%s", output)
	}
}

// An index that names the version over a file nobody can download is the same
// outage with a different symptom, and so is one whose digest disagrees.
func TestTheReleaseRefusesAPackageThatDoesNotMatchTheIndex(t *testing.T) {
	path, packages := index("0.62.1", "the package the index describes")
	output, ok := publishedStep(t, map[string]string{
		path: packages,
		"packages/deb/pool/stable/flotestro-agent_0.62.1_amd64.deb": "something else entirely",
		"packages/rpm/stable/repodata/repomd.xml":                   "<repomd/>",
		"packages/arch/stable/flotestro.db":                         "db",
	}, "built")
	if ok {
		t.Fatalf("the step accepted a package that is not the one the index describes:\n%s", output)
	}
	if !strings.Contains(output, "hashes to") {
		t.Errorf("the step did not say the digests disagree:\n%s", output)
	}
}

// Three families are written by the same push, so an address that serves one
// and not the others is a half-published release.
func TestTheReleaseRefusesAHalfPublishedAddress(t *testing.T) {
	body := "the package"
	path, packages := index("0.62.1", body)
	output, ok := publishedStep(t, map[string]string{
		path: packages,
		"packages/deb/pool/stable/flotestro-agent_0.62.1_amd64.deb": body,
		"packages/rpm/stable/repodata/repomd.xml":                   "<repomd/>",
	}, "built")
	if ok {
		t.Fatalf("the step accepted an address with no pacman database:\n%s", output)
	}
	if !strings.Contains(output, "flotestro.db") {
		t.Errorf("the step did not name the missing index:\n%s", output)
	}
}

// A build that succeeded over a branch that does not carry the release: the
// address answers, serves an index, and the version is simply not in it. This
// is the branch that waits, so the wait is one second here.
func TestTheReleaseRefusesAnAddressThatNeverNamesTheVersion(t *testing.T) {
	path, packages := index("0.61.0", "another release")
	output, ok := publishedStep(t, map[string]string{
		path: packages,
		"packages/rpm/stable/repodata/repomd.xml": "<repomd/>",
		"packages/arch/stable/flotestro.db":       "db",
	}, "built")
	if ok {
		t.Fatalf("the step accepted an index without the version in it:\n%s", output)
	}
	if !strings.Contains(output, "did not name 0.62.1 in time") {
		t.Errorf("the step did not say the address never named the version:\n%s", output)
	}
	if !strings.Contains(output, "the address is what a host reads") {
		t.Errorf("the step did not tell the reader where to look:\n%s", output)
	}
}

// The address the step asks for, on its own, because getting it wrong is what
// failed the release of 0.62.1 and the test of the step agreed with the
// mistake. Filename in a Packages index is relative to the root of that
// repository - .../packages/deb - and a step that asks one directory higher
// gets a 404 over a release that published perfectly well.
func TestTheReleaseAsksForThePackageAtTheRepositoryRoot(t *testing.T) {
	body := "the package as the address serves it"
	path, packages := index("0.62.1", body)
	served := map[string]string{
		path: packages,
		// Served only under deb/, as the published tree serves it. A step that
		// looks anywhere else finds nothing here either.
		"packages/deb/pool/stable/flotestro-agent_0.62.1_amd64.deb": body,
		"packages/rpm/stable/repodata/repomd.xml":                   "<repomd/>",
		"packages/arch/stable/flotestro.db":                         "db",
	}
	output, ok := publishedStep(t, served, "built")
	if !ok {
		t.Fatalf("the step did not find the package where the repository serves it:\n%s", output)
	}
	if !strings.Contains(output, "/packages/deb/pool/stable/flotestro-agent_0.62.1_amd64.deb") {
		t.Errorf("the step asked for another address than the repository root:\n%s", output)
	}
}
