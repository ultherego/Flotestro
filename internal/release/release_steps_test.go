package release

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The order of the publish, the signature and the names is asserted elsewhere
// by reading the workflow. That reading cannot answer the question the owner's
// criterion asks: when the signing or its verification fails, is a name left
// pointing at an unsigned image? So the steps are run here, with docker and
// cosign replaced by stubs that record what they were asked and can be told to
// fail.
//
// This is the trial the criterion asked for and the structural test was
// standing in for. The structural test stays, because it holds the order in
// the file; this one holds what the order is for.

// stubbedRun executes the run scripts of the named steps of a job with a
// recording docker and cosign on the path. failing names the stub that exits
// non-zero. It returns the log of calls and whether the whole sequence passed.
func stubbedRun(t *testing.T, workflow, job string, steps []string, failing string) (calls []string, ok bool) {
	return stubbedRunWithIdentity(t, workflow, job, steps, failing, true)
}

// stubbedRunWithIdentity is the same, with the run's OIDC identity present or
// absent: a signature cannot be made without one, and what the steps do then
// is a question of its own.
func stubbedRunWithIdentity(t *testing.T, workflow, job string, steps []string,
	failing string, identity bool) (calls []string, ok bool) {
	t.Helper()
	parsed := parsedWorkflow(t, workflow)
	declared, found := parsed.Jobs[job]
	if !found {
		t.Fatalf("%s declares no job %s", workflow, job)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	// The stubs: every call recorded, and the one named told to fail. docker
	// answers imagetools inspect with a manifest so that the digest the script
	// computes is stable, and writes the metadata file buildx would write.
	stub := func(name, body string) {
		script := "#!/usr/bin/env bash\nprintf '%s %s\\n' " + name + " \"$*\" >> " + log + "\n" + body
		// failing may name a binary ("cosign") or one of its subcommands
		// ("cosign verify"), because a signature that is made and does not
		// verify is a different failure from one that is never made.
		switch {
		case failing == name:
			script += "\nexit 1\n"
		case strings.HasPrefix(failing, name+" "):
			script += "\n[ \"$1\" = " + strings.TrimPrefix(failing, name+" ") + " ] && exit 1\nexit 0\n"
		default:
			script += "\nexit 0\n"
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	manifest := "a manifest\n"
	digest := sha256Hex(manifest)
	stub("cosign", "")
	// jq is stubbed for the same reason docker and cosign are: the harness must
	// answer for the step's own logic and not for what happens to be installed.
	// It was not stubbed at first, and the laboratory's panel guest has no jq -
	// so this test passed on a workstation and failed in the lab, which is the
	// shape of fault that blocks a gate run for a reason nothing to do with
	// what is being gated.
	stub("jq", `
# jq -r '."containerimage.digest"' <file>
for arg in "$@"; do last="$arg"; done
sed -n 's/.*"containerimage.digest":"\([^"]*\)".*/\1/p' "$last"`)
	stub("docker", strings.Replace(`
case "$1 $2" in
"buildx build")
  prev=""
  for arg in "$@"; do
    case "$prev" in --metadata-file) printf '{"containerimage.digest":"sha256:DIGEST"}\n' > "$arg" ;; esac
    prev="$arg"
  done
  ;;
"buildx imagetools")
  case "$3" in inspect) printf 'a manifest\n' ;; esac
  ;;
esac`, "DIGEST", digest, 1))

	outputs := filepath.Join(dir, "outputs")
	if err := os.WriteFile(outputs, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"HOME=" + dir,
		"RUNNER_TEMP=" + dir,
		"GITHUB_OUTPUT=" + outputs,
		"GITHUB_REF_NAME=v9.9.9",
		"GITHUB_REPOSITORY_OWNER=Ultherego",
		"GITHUB_SHA=0123456789abcdef0123456789abcdef01234567",
	}
	if identity {
		env = append(env, "ACTIONS_ID_TOKEN_REQUEST_URL=https://token.example.test/?audience=sigstore")
	}

	ran := 0
	for _, want := range steps {
		for _, step := range declared.Steps {
			if step.Name != want || step.Run == "" {
				continue
			}
			ran++
			// The expressions of the step's own env, resolved from the outputs
			// the earlier steps wrote - which is what the runner does.
			script := step.Run
			stepEnv := append([]string{}, env...)
			for key, value := range step.Env {
				text, isString := value.(string)
				if !isString {
					continue
				}
				stepEnv = append(stepEnv, key+"="+resolveExpression(t, text, outputs))
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = stepEnv
			cmd.Dir = dir
			output, err := cmd.CombinedOutput()
			t.Logf("-- %s\n%s", want, output)
			if err != nil {
				recorded, _ := os.ReadFile(log)
				return strings.Split(strings.TrimSpace(string(recorded)), "\n"), false
			}
		}
	}
	if ran != len(steps) {
		t.Fatalf("%d of %d steps were found by name in %s/%s", ran, len(steps), workflow, job)
	}
	recorded, _ := os.ReadFile(log)
	return strings.Split(strings.TrimSpace(string(recorded)), "\n"), true
}

// resolveExpression replaces ${{ steps.<id>.outputs.<name> }} with what an
// earlier step wrote to GITHUB_OUTPUT.
func resolveExpression(t *testing.T, text, outputs string) string {
	t.Helper()
	for strings.Contains(text, "${{") {
		open := strings.Index(text, "${{")
		close := strings.Index(text[open:], "}}")
		if close < 0 {
			break
		}
		expression := strings.TrimSpace(text[open+3 : open+close])
		value := ""
		if parts := strings.Split(expression, "."); len(parts) == 4 && parts[0] == "steps" {
			written, err := os.ReadFile(outputs)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(written), "\n") {
				if name, got, found := strings.Cut(line, "="); found && name == parts[3] {
					value = got
				}
			}
		}
		text = text[:open] + value + text[open+close+2:]
	}
	return text
}

// A release that goes right: the candidate is pushed, the digest is read back,
// the signature is made and verified, and only then are the names moved.
func TestTheNamesAreMovedOnlyAfterTheSignatureVerifies(t *testing.T) {
	calls, ok := stubbedRun(t, "release.yml", "repository-image", releaseImageSteps, "")
	if !ok {
		t.Fatalf("the steps did not get through on their own stubs: %v", calls)
	}
	order := strings.Join(calls, "\n")
	for _, want := range []string{"cosign sign", "cosign verify", "imagetools create"} {
		if !strings.Contains(order, want) {
			t.Errorf("%s was never called:\n%s", want, order)
		}
	}
	// Asked of the property and not of the command. The first shape of this
	// test looked for "imagetools create" before the verification - and the
	// shape it was written against had no imagetools create at all, because
	// the build pushed the public names itself. It would have passed over the
	// very defect it exists for. What matters is when a name a deployment
	// follows first reaches the registry, by whatever command.
	if publicNameAt(calls) < callAt(calls, "cosign verify") {
		t.Errorf("a name a deployment follows reached the registry before the signature was read back:\n%s", order)
	}
	// The candidate is what the build pushed, and no public name is in it.
	build := firstLine(calls, "buildx build")
	for _, name := range []string{":9.9.9", ":latest", ":9.9"} {
		if strings.Contains(build, name) {
			t.Errorf("the build pushes %s itself: %s", name, build)
		}
	}
	if !strings.Contains(build, "candidate-") {
		t.Errorf("the build pushes no candidate tag: %s", build)
	}
	// And all three names end up on the digest that verified.
	move := firstLine(calls, "imagetools create")
	for _, name := range []string{":9.9.9", ":latest", ":9.9"} {
		if !strings.Contains(move, name) {
			t.Errorf("the promotion does not move %s: %s", name, move)
		}
	}
}

// The signing fails. Nothing may have moved: a red run is read, a registry is
// not, so a name left pointing at an unsigned image outlives the failure.
func TestAFailedSigningMovesNoName(t *testing.T) {
	calls, ok := stubbedRun(t, "release.yml", "repository-image", releaseImageSteps, "cosign")
	if ok {
		t.Fatal("the sequence passed although the signing failed")
	}
	order := strings.Join(calls, "\n")
	if moved := publicNameAt(calls); moved < 1<<30 {
		t.Errorf("a name a deployment follows reached the registry although the signing failed:\n%s", order)
	}
}

func firstLine(calls []string, containing string) string {
	for _, line := range calls {
		if strings.Contains(line, containing) {
			return line
		}
	}
	return ""
}

// releaseImageSteps are the steps of the job that publishes and signs the
// repository image, in the order the workflow declares them.
var releaseImageSteps = []string{
	"Build under a candidate tag nobody follows",
	"Sign the image the air-gap procedure verifies",
	"The signature is read back before any name is moved",
	"Move the names a deployment follows",
}

// sha256Hex is what sha256sum prints for the given text.
func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// A run with no OIDC identity cannot sign. It must publish nothing a
// deployment follows either, and this is the half that is easy to get wrong:
// the candidate is already in the registry by then, and moving the names would
// be one command away.
func TestARunThatCannotSignMovesNoName(t *testing.T) {
	calls, ok := stubbedRunWithIdentity(t, "release.yml", "repository-image",
		releaseImageSteps, "", false)
	if ok {
		t.Fatal("the sequence passed although the run could not sign anything")
	}
	order := strings.Join(calls, "\n")
	if moved := publicNameAt(calls); moved < 1<<30 {
		t.Errorf("a name a deployment follows reached the registry from a run that could not sign:\n%s", order)
	}
	if strings.Contains(order, "cosign sign") {
		t.Errorf("the run tried to sign without an identity:\n%s", order)
	}
}

// And the verification failing is the other way a signature can be absent in
// effect: cosign sign exited zero and the thing still does not verify.
func TestAFailedVerificationMovesNoName(t *testing.T) {
	calls, ok := stubbedRun(t, "release.yml", "repository-image", releaseImageSteps, "cosign verify")
	if ok {
		t.Fatal("the sequence passed although the verification failed")
	}
	order := strings.Join(calls, "\n")
	if moved := publicNameAt(calls); moved < 1<<30 {
		t.Errorf("a name a deployment follows reached the registry although the verification failed:\n%s", order)
	}
}

// publicNames are the names a deployment follows for the version under test.
var publicNames = []string{":9.9.9", ":latest", ":9.9"}

// publicNameAt returns where in the log a name a deployment follows first
// reaches the registry - by a push, by a promotion, by anything - or a large
// number when none does. A call that only reads the registry does not count.
func publicNameAt(calls []string) int {
	for index, call := range calls {
		if strings.Contains(call, "imagetools inspect") {
			continue
		}
		for _, name := range publicNames {
			if strings.Contains(call, name) {
				return index
			}
		}
	}
	return 1 << 30
}

// callAt returns the index of the first call containing the text, or a large
// number when there is none, so an ordering comparison cannot read "absent" as
// "first".
func callAt(calls []string, text string) int {
	for index, call := range calls {
		if strings.Contains(call, text) {
			return index
		}
	}
	return 1 << 30
}
