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

	// A healthcheck declared in a compose file for a shell-less image.
	//
	// This used to ask only that it be written in exec form, and our files
	// were. It did not help: podman-compose turns every form of a compose
	// healthcheck into CMD-SHELL and hands the line to /bin/sh, so on an
	// image with no shell the check cannot run whatever we write. 12.10,
	// measured on the relay - twenty-five failed checks with an empty output
	// while it carried the fleet, and a container reporting unhealthy is
	// something monitoring and orchestrators act on.
	//
	// So the question changed: a shell-less image carries its own check and
	// the compose file says nothing about it.
	for _, file := range files {
		for _, one := range file.services() {
			test, ok := readHealthcheck(one)
			if !ok || test.form == "disabled" {
				continue
			}
			target := imageTarget(one)
			byImage := target != "" && shellless[target]
			byCommand := strings.Contains(test.command, staticHealthClient)
			if !byImage && !byCommand {
				continue
			}
			findings = append(findings, finding{
				place: file.at(test.node),
				said: fmt.Sprintf("the healthcheck of %s is written here, and that image has no shell; "+
					"podman-compose hands every form of it to /bin/sh. The image carries the check, "+
					"and this file says nothing about it", one.name),
			})
		}
	}

	// And the images themselves: a check, in exec form, taking no arguments.
	// An argument is the thing a compose tool rewrites; the address comes
	// from FLOTESTRO_ADMIN_ADDR, which the deployment sets.
	deployed, err := deployedTargets(root, files, shellless)
	if err != nil {
		return nil, err
	}
	if len(deployed) == 0 {
		return append(findings, finding{
			place: composeDir,
			said:  "no deployment runs a shell-less image of ours, so this check inspected nothing",
		}), nil
	}
	text, err := readText(root, composeDir, "Containerfile")
	if err != nil {
		return nil, err
	}
	checks := imageHealthchecks(text)
	for _, target := range deployed {
		command, ok := checks[target]
		if !ok {
			findings = append(findings, finding{
				place: composeDir + "/Containerfile",
				said: fmt.Sprintf("the image %s runs as a service and carries no HEALTHCHECK, "+
					"and no compose file may declare one for it: nothing would ask whether it works", target),
			})
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(command), "[") {
			findings = append(findings, finding{
				place: composeDir + "/Containerfile",
				said: fmt.Sprintf("the HEALTHCHECK of %s is a shell string (%s); that image has no shell",
					target, command),
			})
			continue
		}
		if strings.Contains(command, ",") {
			findings = append(findings, finding{
				place: composeDir + "/Containerfile",
				said: fmt.Sprintf("the HEALTHCHECK of %s takes arguments (%s); it reads FLOTESTRO_ADMIN_ADDR "+
					"instead, so a compose tool has nothing to rewrite", target, command),
			})
		}
	}
	return findings, nil
}

// deployedTargets names the shell-less stages a compose file runs as a
// service, sorted, so the message is the same on every machine.
func deployedTargets(root string, files []composeFile, shellless map[string]bool) ([]string, error) {
	seen := map[string]bool{}
	for _, file := range files {
		for _, one := range file.services() {
			target := imageTarget(one)
			if target == "" {
				// A service whose image is a variable and nothing else: the
				// relay is deployed that way on purpose, pinned by digest out
				// of the release manifest, so imageTarget has no reference to
				// read. The variable names the component - and on 12.10 that
				// was the difference between this check covering the relay
				// and skipping it in silence, which is how the relay came to
				// report unhealthy for as long as it ran.
				target = componentOfImageVariable(one)
			}
			if target != "" && shellless[target] {
				seen[target] = true
			}
		}
	}
	targets := make([]string, 0, len(seen))
	for target := range seen {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets, nil
}

// imageHealthchecks reads the HEALTHCHECK of every stage of the Containerfile,
// by the stage's name, with its line continuations joined.
func imageHealthchecks(text string) map[string]string {
	checks := map[string]string{}
	stage := ""
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "FROM ") {
			fields := strings.Fields(line)
			stage = ""
			for j, word := range fields {
				if strings.EqualFold(word, "AS") && j+1 < len(fields) {
					stage = fields[j+1]
				}
			}
			continue
		}
		if !strings.HasPrefix(line, "HEALTHCHECK") || stage == "" {
			continue
		}
		joined := line
		for strings.HasSuffix(strings.TrimSpace(joined), "\\") && i+1 < len(lines) {
			i++
			joined = strings.TrimSuffix(strings.TrimSpace(joined), "\\") + " " + strings.TrimSpace(lines[i])
		}
		if at := strings.Index(joined, "CMD "); at >= 0 {
			checks[stage] = strings.TrimSpace(joined[at+len("CMD "):])
		}
	}
	return checks
}

// componentOfImageVariable reads FLOTESTRO_<NAME>_IMAGE as the component NAME.
func componentOfImageVariable(s service) string {
	image := field(s.node, "image")
	if image == nil || !strings.HasPrefix(strings.TrimSpace(image.Value), "${") {
		return ""
	}
	name := strings.TrimPrefix(strings.TrimSpace(image.Value), "${")
	for _, cut := range []string{":", "-", "}"} {
		name = strings.SplitN(name, cut, 2)[0]
	}
	name = strings.TrimPrefix(name, "FLOTESTRO_")
	name = strings.TrimSuffix(name, "_IMAGE")
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}
