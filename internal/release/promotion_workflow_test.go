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
