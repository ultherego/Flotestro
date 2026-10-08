package release

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// permissionsOf reads a workflow far enough to answer what each job may do: the
// workflow's own default, and the override a job declares.
type permissionedWorkflow struct {
	Permissions any `yaml:"permissions"`
	Jobs        map[string]struct {
		Uses        string `yaml:"uses"`
		Permissions any    `yaml:"permissions"`
	} `yaml:"jobs"`
}

// A reusable workflow may not ask for a permission the job calling it was not
// granted, and GitHub does not answer that with a failed job: it refuses to
// start the run, with no job, no log and no annotation an API can read. The
// promotion job of images.yml was given "statuses: read" on 06.10, release.yml
// was not told, and the first tag pushed after that - v0.62.0 - came back as a
// bare startup_failure thirteen minutes after a gate that had passed 826 of 826.
//
// Nothing could have caught that before the tag: the workflows are only
// validated when something triggers them, and nothing triggers a release but a
// release. This asks the question without pushing a tag.
func TestACalledWorkflowAsksForNothingItWasNotGranted(t *testing.T) {
	root := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("the workflows are not readable, so this guard checks nothing: %v", err)
	}

	loaded := map[string]permissionedWorkflow{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var parsed permissionedWorkflow
		if err := yaml.Unmarshal(content, &parsed); err != nil {
			t.Fatalf("%s does not parse: %v", entry.Name(), err)
		}
		loaded[entry.Name()] = parsed
	}
	if len(loaded) == 0 {
		t.Fatal("no workflow was read at all")
	}

	checked := 0
	for name, workflow := range loaded {
		for jobName, job := range workflow.Jobs {
			called, local := localCall(job.Uses)
			if !local {
				continue
			}
			target, ok := loaded[called]
			if !ok {
				t.Errorf("%s: job %q calls %s, which is not a workflow of this repository",
					name, jobName, job.Uses)
				continue
			}
			granted := permissionNames(job.Permissions)
			for targetJob, inner := range target.Jobs {
				asked := inner.Permissions
				if asked == nil {
					asked = target.Permissions
				}
				for _, permission := range permissionNames(asked) {
					checked++
					if !contains(granted, permission) {
						t.Errorf("%s: job %q grants %v to %s, whose job %q asks for %q as well; "+
							"GitHub refuses to start the whole run over this",
							name, jobName, granted, called, targetJob, permission)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no permission of any called workflow was compared; either nothing calls one any more " +
			"or this guard stopped reading them")
	}
	t.Logf("%d permission requests of called workflows compared with what their callers grant", checked)
}

// localCall says whether a job calls a workflow of this repository, and which.
func localCall(uses string) (string, bool) {
	const prefix = "./.github/workflows/"
	if !strings.HasPrefix(uses, prefix) {
		return "", false
	}
	return strings.TrimPrefix(uses, prefix), true
}

// permissionNames reads the keys of a permissions block. "read-all" and
// "write-all" are every permission, and the shorthand is answered as such.
func permissionNames(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed == "read-all" || typed == "write-all" {
			return []string{"read-all"}
		}
		return nil
	case map[string]any:
		names := make([]string, 0, len(typed))
		for key := range typed {
			names = append(names, key)
		}
		sort.Strings(names)
		return names
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		// A caller that granted everything granted this too.
		if item == needle || item == "read-all" {
			return true
		}
	}
	return false
}
