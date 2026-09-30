package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const composeDir = "docker"

// composeFile is one deployment description, kept as a node tree rather than a
// plain map because every failure here has to name a line and a map has none.
type composeFile struct {
	name string
	text string
	root *yaml.Node
}

// composeFiles reads every compose file of the tree, and never a list written
// here: the panel is described more than once, so a variant added later has to
// be inspected on the day it appears.
func composeFiles(root string) ([]composeFile, error) {
	paths, err := filepath.Glob(filepath.Join(root, composeDir, "compose*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	files := make([]composeFile, 0, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var document yaml.Node
		if err := yaml.Unmarshal(content, &document); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		if len(document.Content) == 0 {
			continue
		}
		files = append(files, composeFile{
			name: composeDir + "/" + filepath.Base(path),
			text: string(content),
			root: document.Content[0],
		})
	}
	return files, nil
}

// field returns the value node of one key of a mapping, or nil.
func field(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// service is one entry of the services mapping, with its name.
type service struct {
	name string
	node *yaml.Node
}

func (c composeFile) services() []service {
	services := field(c.root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	var found []service
	for i := 0; i+1 < len(services.Content); i += 2 {
		found = append(found, service{name: services.Content[i].Value, node: services.Content[i+1]})
	}
	return found
}

func (c composeFile) at(node *yaml.Node) string {
	if node == nil {
		return c.name
	}
	return fmt.Sprintf("%s:%d", c.name, node.Line)
}

// environmentKeys returns the variable names a service hands to its container.
// Compose takes both a mapping and a list of "KEY=value" or bare "KEY", and the
// bare form is the one that passes a value through from the host.
func (s service) environmentKeys() map[string]bool {
	keys := map[string]bool{}
	environment := field(s.node, "environment")
	if environment == nil {
		return keys
	}
	switch environment.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(environment.Content); i += 2 {
			keys[environment.Content[i].Value] = true
		}
	case yaml.SequenceNode:
		for _, entry := range environment.Content {
			name, _, _ := strings.Cut(entry.Value, "=")
			if name != "" {
				keys[strings.TrimSpace(name)] = true
			}
		}
	}
	return keys
}

// imageTarget resolves the build stage a compose image was produced from, by the
// one convention the release holds to: the image of the stage called X is named
// flotestro-X. An image this repository does not build - postgres, busybox - and
// one named by a variable both resolve to nothing, and the caller has to cope
// with not knowing rather than assume.
func imageTarget(s service) string {
	image := field(s.node, "image")
	if image == nil {
		return ""
	}
	reference := image.Value
	if at := strings.IndexAny(reference, "${"); at >= 0 && strings.Contains(reference, "${") {
		// A reference built out of a variable still names the repository
		// before the tag in every case this tree has; what follows the
		// colon is the variable, so cutting at it is safe.
		reference = strings.SplitN(reference, "${", 2)[0]
		reference = strings.TrimSuffix(reference, ":")
	}
	reference = strings.SplitN(reference, "@", 2)[0]
	if colon := strings.LastIndex(reference, ":"); colon > strings.LastIndex(reference, "/") {
		reference = reference[:colon]
	}
	name := reference
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return strings.TrimPrefix(name, "flotestro-")
}

// shelllessTargets reads the Containerfile and returns the build stages whose
// final base is the distroless runtime. The fact is taken from the file that
// decides it rather than written down here, so a stage that stops being
// distroless stops being reported and one that becomes distroless starts.
func shelllessTargets(root string) (map[string]bool, error) {
	text, err := readText(root, composeDir, "Containerfile")
	if err != nil {
		return nil, err
	}
	// The variable the Containerfile names its distroless base with. Its
	// default is asserted below, because a rename of the variable would
	// otherwise leave this check looking for a stage list that is empty.
	const runtimeBase = "${RUNTIME_IMAGE}"
	if !strings.Contains(text, "ARG RUNTIME_IMAGE=") {
		return nil, fmt.Errorf("%s/Containerfile declares no RUNTIME_IMAGE, so which stages have no shell cannot be read",
			composeDir)
	}
	targets := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "FROM ") || !strings.Contains(line, runtimeBase) {
			continue
		}
		fields := strings.Fields(line)
		for i, word := range fields {
			if strings.EqualFold(word, "AS") && i+1 < len(fields) {
				targets[fields[i+1]] = true
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%s/Containerfile builds no stage on %s", composeDir, runtimeBase)
	}
	return targets, nil
}

// healthcheckTest is the test of one healthcheck, as written.
type healthcheckTest struct {
	node    *yaml.Node
	form    string // "exec", "shell", "disabled" or "unrecognised"
	command string
}

// readHealthcheck classifies the test of a service's healthcheck. Compose takes
// a list whose first element says how the rest is run, or a bare string, which
// is a shell command by definition.
func readHealthcheck(s service) (healthcheckTest, bool) {
	healthcheck := field(s.node, "healthcheck")
	if healthcheck == nil {
		return healthcheckTest{}, false
	}
	if disable := field(healthcheck, "disable"); disable != nil && disable.Value == "true" {
		return healthcheckTest{node: healthcheck, form: "disabled"}, true
	}
	test := field(healthcheck, "test")
	if test == nil {
		return healthcheckTest{node: healthcheck, form: "unrecognised"}, true
	}
	switch test.Kind {
	case yaml.ScalarNode:
		return healthcheckTest{node: test, form: "shell", command: test.Value}, true
	case yaml.SequenceNode:
		words := make([]string, 0, len(test.Content))
		for _, entry := range test.Content {
			words = append(words, entry.Value)
		}
		command := strings.Join(words, " ")
		if len(words) == 0 {
			return healthcheckTest{node: test, form: "unrecognised"}, true
		}
		switch words[0] {
		case "CMD":
			return healthcheckTest{node: test, form: "exec", command: strings.Join(words[1:], " ")}, true
		case "CMD-SHELL":
			return healthcheckTest{node: test, form: "shell", command: strings.Join(words[1:], " ")}, true
		case "NONE":
			return healthcheckTest{node: test, form: "disabled"}, true
		default:
			return healthcheckTest{node: test, form: "unrecognised", command: command}, true
		}
	}
	return healthcheckTest{node: test, form: "unrecognised"}, true
}

// The static client the distroless images carry instead of curl. It exists only
// in an image with no shell, so a healthcheck that runs it is a healthcheck on a
// shell-less image whatever the image reference says - which matters, because the
// relay's reference is a variable and resolves to no stage at all.
const staticHealthClient = "flotestro-healthcheck"

// healthcheckForm holds every healthcheck on a shell-less image to exec form.
//
// This is the opposite of the direction the finding was first written in. The
// files are already right: they say ["CMD", ...] because the images are
// distroless, and podman-compose rewrites that list into a shell string and then
// reports the container unhealthy for the rest of its life. Nothing in this tree
// waits on container health, so nothing hangs - docker/README.md records the
// limitation and points at /readyz instead. The risk worth guarding is the
// obvious-looking repair: somebody reads "the list form does not work under
// podman-compose", writes CMD-SHELL, and breaks the check on both engines for
// real, because then there is genuinely no shell to run it.
func healthcheckForm(root string) ([]finding, error) {
	shellless, err := shelllessTargets(root)
	if err != nil {
		return nil, err
	}
	files, err := composeFiles(root)
	if err != nil {
		return nil, err
	}

	var findings []finding
	inspected := 0
	for _, file := range files {
		for _, one := range file.services() {
			test, ok := readHealthcheck(one)
			if !ok || test.form == "disabled" {
				continue
			}
			// Two independent reasons to call an image shell-less, because
			// each covers the other's blind spot: the reference resolves to
			// a distroless stage, or the command is the static client that
			// only such an image carries.
			target := imageTarget(one)
			byImage := target != "" && shellless[target]
			byCommand := strings.Contains(test.command, staticHealthClient)
			if !byImage && !byCommand {
				continue
			}
			inspected++
			if test.form == "exec" {
				continue
			}
			findings = append(findings, finding{
				place: file.at(test.node),
				said: fmt.Sprintf("the healthcheck of %s is in %s form on an image with no shell; "+
					"write it as [\"CMD\", ...] so the engine runs the binary directly",
					one.name, test.form),
			})
		}
	}

	if inspected == 0 {
		return append(findings, finding{
			place: composeDir,
			said: fmt.Sprintf("no healthcheck on a shell-less image was found among %d compose file(s), "+
				"so this check inspected nothing", len(files)),
		}), nil
	}
	return findings, nil
}
