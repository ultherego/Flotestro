package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The workflow as a structure, so that a question about one job is asked of
// that job and not of the file's text: the promotion and the build used to be
// the same job, and a check over the whole file cannot tell them apart.
type workflowFile struct {
	Jobs map[string]struct {
		Needs       any    `yaml:"needs"`
		If          string `yaml:"if"`
		Environment any    `yaml:"environment"`
		Steps       []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
			Env  map[string]any
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func parsedWorkflow(t *testing.T, name string) workflowFile {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var parsed workflowFile
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		t.Fatalf("%s is not readable as a workflow: %v", name, err)
	}
	if len(parsed.Jobs) == 0 {
		t.Fatalf("%s declares no job; this check read nothing", name)
	}
	return parsed
}

func (w workflowFile) script(job string) string {
	var script strings.Builder
	for _, step := range w.Jobs[job].Steps {
		script.WriteString(step.Run)
		script.WriteString("\n")
	}
	return script.String()
}

// The images workflow has workflow_dispatch, a dispatch can be run on a tag,
// and the build published under a name a deployment reads as soon as the ref
// was a tag. The approval that gates a release sat on another workflow, which
// that dispatch never touches. These are the four things that must stay true
// for a dispatch not to be a release.
func TestOnlyAnApprovedJobMovesThePublicNames(t *testing.T) {
	images := parsedWorkflow(t, "images.yml")

	promote, declared := images.Jobs["promote"]
	if !declared {
		t.Fatal("images.yml has no promote job: whatever builds also publishes")
	}
	// The approval itself. An environment is what makes a job wait for a human.
	if promote.Environment != "release-signing" {
		t.Errorf("the promote job runs in the environment %v, not release-signing", promote.Environment)
	}
	// A name a deployment reads is moved by imagetools create. It must happen
	// in the approved job and nowhere else.
	for job := range images.Jobs {
		if job == "promote" {
			continue
		}
		if strings.Contains(images.script(job), "imagetools create") {
			t.Errorf("the job %s moves a tag itself, so it publishes without the approval", job)
		}
	}
	if !strings.Contains(images.script("promote"), "imagetools create") {
		t.Error("the promote job moves no tag; the names are published somewhere this check cannot see")
	}

	script := images.script("promote")
	// Self-sufficient: the three questions are asked here, whatever started
	// the run.
	for what, needle := range map[string]string{
		"the tag is on the default branch":               "merge-base --is-ancestor",
		"the laboratory verdict is read for this commit": "/statuses",
		"only a clean run is promoted":                   "verdict=pass",
	} {
		if !strings.Contains(script, needle) {
			t.Errorf("the promote job does not check that %s", what)
		}
	}
	// The identity a signature is verified against is constructed from the
	// repository and the ref. Read out of the run's own token it asks "was
	// this signed by whatever signed it", which the run satisfies by existing.
	if !strings.Contains(script, "cosign verify") {
		t.Error("the promote job verifies no signature before moving a name")
	}
	if strings.Contains(script, "job_workflow_ref") {
		t.Error("the promote job takes the signing identity out of its own token again")
	}
}

// Two parsers of one archive is how a verified bundle stopped the workflow
// before it recorded anything: the checker accepts ./result.json, the step
// beside it asked tar for result.json, and the gate writes the archive with
// tar -C dir . - so that member is named ./result.json and the command exits 2.
// The workflow takes the report from the checker now, and this is here so that
// a convenience cannot put the second parser back.
func TestOnlyTheCheckerReadsTheEvidenceArchive(t *testing.T) {
	script := parsedWorkflow(t, "lab-gate.yml").script("record")
	if strings.Contains(script, "tar -xzOf") || strings.Contains(script, "tar -xf") {
		t.Error("lab-gate.yml opens the evidence archive itself again")
	}
	if !strings.Contains(script, "-report report.json") {
		t.Error("lab-gate.yml does not ask the checker for the report it verified")
	}
}

// The release of the packages waits for the same approval, and the gate is read
// there the same way. A promotion that trusted a branch-level status would
// release a tree nobody ran.
func TestThePromotionReadsTheVerdictOfItsOwnCommit(t *testing.T) {
	script := parsedWorkflow(t, "images.yml").script("promote")
	if !strings.Contains(script, "commits/$commit/statuses") {
		t.Error("the promote job does not read the lab-suite status of the commit it is promoting")
	}
	if !strings.Contains(script, "lab-suite") {
		t.Error("the promote job does not name the status it reads")
	}
}

// The same question, asked of every workflow rather than of one.
//
// TestOnlyAnApprovedJobMovesThePublicNames above reads images.yml, and that is
// how a job added to release.yml came to push :version, :latest and the minor
// alias straight from the build and sign afterwards: the rule was being kept in
// one file, so breaking it in another file broke nothing a test could see. A
// failure of the signing left the run red and the registry pointing at an
// unsigned image, which is the worse of the two outcomes.
//
// The invariant: a job that moves a name a deployment follows must read a
// signature back in that same job. Promotion by imagetools create is the shape
// that moves a name; a build pushes a candidate nobody follows.
func TestNoWorkflowMovesANameWithoutReadingASignature(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	promotions := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		workflow := parsedWorkflow(t, name)
		for job := range workflow.Jobs {
			script := workflow.script(job)
			// Asked of the build invocation itself, and of every job - not of
			// jobs that do not promote. The first shape of this test let a job
			// push :version and :latest from the build and pass, because it
			// also promoted later on, so the question about pushing was never
			// reached. The structure of the test carried the assumption that a
			// job either pushes or promotes.
			for _, tag := range buildTags(script) {
				if !strings.Contains(tag, "candidate") {
					t.Errorf("%s: the job %s builds with --tag %s and pushes it, "+
						"so a name a deployment follows is moved before anything is signed",
						name, job, tag)
				}
			}
			if !strings.Contains(script, "imagetools create") {
				continue
			}
			promotions++
			if !strings.Contains(script, "cosign verify") {
				t.Errorf("%s: the job %s moves a name without reading a signature back; "+
					"a failure of the signing then leaves the registry pointing at an unsigned image",
					name, job)
			}
		}
	}
	if promotions == 0 {
		t.Fatal("no job in any workflow moves a name, so this check read nothing")
	}
	t.Logf("%d job(s) move a public name, each after reading a signature", promotions)
}

// And the order inside such a job: the names are moved after the verification,
// not merely in its company. A job that promotes first and verifies second
// passes the check above and is exactly the defect.
func TestANameIsMovedAfterTheSignatureIsVerified(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		workflow := parsedWorkflow(t, name)
		for job := range workflow.Jobs {
			script := workflow.script(job)
			move := strings.Index(script, "imagetools create")
			verify := strings.Index(script, "cosign verify")
			if move < 0 || verify < 0 {
				continue
			}
			checked++
			if verify > move {
				t.Errorf("%s: the job %s moves a name at %d and verifies at %d, in that order",
					name, job, move, verify)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no job both verifies and promotes, so this check read nothing")
	}
}

// buildTags returns the tags every pushing `docker buildx build` in a script
// carries. A build that does not push moves no name and is not asked.
func buildTags(script string) []string {
	var tags []string
	for rest := script; ; {
		start := strings.Index(rest, "docker buildx build")
		if start < 0 {
			return tags
		}
		rest = rest[start+len("docker buildx build"):]
		// The invocation ends at the first line that is not a continuation.
		invocation := rest
		if end := strings.Index(invocation, "--push"); end >= 0 {
			invocation = invocation[:end]
		} else {
			continue
		}
		for _, field := range strings.Fields(invocation) {
			if field == "--tag" {
				continue
			}
			if strings.HasPrefix(field, "--tag=") {
				tags = append(tags, strings.TrimPrefix(field, "--tag="))
			}
		}
		// --tag and its value are separate words in every build here.
		fields := strings.Fields(invocation)
		for i, field := range fields {
			if field == "--tag" && i+1 < len(fields) {
				tags = append(tags, fields[i+1])
			}
		}
	}
}

// Naming an environment is not the same statement as being gated by one.
//
// TestOnlyAnApprovedJobMovesThePublicNames asserts that the job declares
// environment: release-signing, and its comment calls that "the approval
// itself - an environment is what makes a job wait for a human". In this
// repository, on 05.10, release-signing carried zero protection rules: the
// job waited for nobody, and every test about the approval was green. The
// workflow's own comment admitted it ("an environment that does not exist yet
// simply runs without the wait") while the test beside it said the opposite,
// and the test is what produced the signal.
//
// So the job that claims the approval has to ask whether it exists.
func TestTheJobThatClaimsTheApprovalAsksWhetherItHasAReviewer(t *testing.T) {
	release := parsedWorkflow(t, "release.yml")
	claiming := ""
	for job, declared := range release.Jobs {
		if environment, ok := declared.Environment.(string); ok && environment == "release-signing" {
			claiming = job
		}
	}
	if claiming == "" {
		t.Fatal("no job of release.yml runs in release-signing, so this check read nothing")
	}
	script := release.script(claiming)
	for what, needle := range map[string]string{
		"it asks the API about the environment it names": "environments/release-signing",
		"it asks for the reviewers and not for any rule": "required_reviewers",
	} {
		if !strings.Contains(script, needle) {
			t.Errorf("the job %s claims the approval but %s", claiming, what)
		}
	}
	// An answer nobody could read is not an approval: the project's rule is
	// that unknown is never zero, and here the unknown is a refusal.
	if !strings.Contains(script, "not knowing is not an approval") {
		t.Errorf("the job %s does not refuse a stable release when the approval cannot be read", claiming)
	}
}
