package main

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// env.example is the file the panel's own settings screen points an operator at.
// Compose reads it for ${...} substitution and for nothing else: without an
// env_file: key, a variable set there never enters a container. So a key offered
// there has to be either handed to a service explicitly or used in a
// substitution, and a key that is neither is a setting the operator makes and the
// product never reads. Nothing breaks loudly - which is the whole problem.
const (
	envExample    = composeDir + "/env.example"
	inertBaseline = "tools/shipcheck/inert-env-keys.txt"
)

var (
	envExampleKey = regexp.MustCompile(`^\s*#?\s*([A-Z][A-Z0-9_]*)=`)
	variableName  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	interpolation = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)`)
)

// declaredKey is one key of env.example, with the line it is offered on.
type declaredKey struct {
	name string
	line int
}

// envExampleReachesTheDeployment compares what env.example offers with what the
// compose files can act on.
//
// The gap is real on the tree this landed against, and closing it is a decision
// about the deployment rather than a typo, so the keys that were already inert
// are listed in a baseline. The baseline may only shrink: a new inert key fails,
// and an entry that has been fixed or deleted fails too, so the list cannot rot
// into a rubber stamp.
func envExampleReachesTheDeployment(root string) ([]finding, error) {
	text, err := readText(root, composeDir, "env.example")
	if err != nil {
		return nil, err
	}
	var declared []declaredKey
	for number, line := range strings.Split(text, "\n") {
		if match := envExampleKey.FindStringSubmatch(line); match != nil {
			declared = append(declared, declaredKey{name: match[1], line: number + 1})
		}
	}

	files, err := composeFiles(root)
	if err != nil {
		return nil, err
	}
	reached, carried := reachableVariables(files)

	if len(declared) == 0 || (len(reached) == 0 && !carried) {
		return []finding{{
			place: envExample,
			said: fmt.Sprintf("offers %d key(s) and the compose files can act on %d, so this check compared nothing",
				len(declared), len(reached)),
		}}, nil
	}

	baseline, err := readBaseline(root)
	if err != nil {
		return nil, err
	}

	var findings []finding
	inert := map[string]bool{}
	for _, key := range declared {
		// An env_file: hands the whole file to the container, so once one is
		// declared every key of it arrives and the question is settled.
		if carried || reached[key.name] {
			continue
		}
		inert[key.name] = true
		if baseline[key.name] {
			continue
		}
		findings = append(findings, finding{
			place: fmt.Sprintf("%s:%d", envExample, key.line),
			said: fmt.Sprintf("%s reaches no container: no compose file hands it to a service and none "+
				"substitutes it, and there is no env_file: to carry it. Add it to the environment: of the "+
				"service that reads it, or take it out of %s", key.name, envExample),
		})
	}
	for _, name := range sorted(baseline) {
		if !inert[name] {
			findings = append(findings, finding{
				place: inertBaseline,
				said: fmt.Sprintf("still lists %s, which now reaches the deployment or is gone from %s: "+
					"delete the line, because a baseline that outlives what it excuses stops being a ratchet",
					name, envExample),
			})
		}
	}
	return findings, nil
}

// reachableVariables collects every name a compose file can act on: the keys of
// every service's environment, and every name used in a substitution. The
// substitutions are read from the parsed scalars rather than from the text,
// because a name written in a comment is not something the deployment acts on.
// The second result says whether any service carries a whole env file, which
// settles the question for every key at once.
func reachableVariables(files []composeFile) (map[string]bool, bool) {
	reached := map[string]bool{}
	carried := false
	for _, file := range files {
		for _, one := range file.services() {
			if field(one.node, "env_file") != nil {
				carried = true
			}
			for name := range one.environmentKeys() {
				reached[name] = true
			}
		}
		for _, value := range scalarValues(file.root) {
			for _, match := range interpolation.FindAllStringSubmatch(value, -1) {
				reached[match[1]] = true
			}
		}
	}
	return reached, carried
}

// scalarValues walks a node tree and returns every scalar in it.
func scalarValues(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	if len(node.Content) == 0 {
		return []string{node.Value}
	}
	var values []string
	for _, child := range node.Content {
		values = append(values, scalarValues(child)...)
	}
	return values
}

// readBaseline reads the checked-in list of keys that were already inert.
func readBaseline(root string) (map[string]bool, error) {
	text, err := readText(root, "tools", "shipcheck", "inert-env-keys.txt")
	if err != nil {
		return nil, err
	}
	baseline := map[string]bool{}
	for number, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !variableName.MatchString(trimmed) {
			return nil, fmt.Errorf("%s:%d: %q is not a variable name", inertBaseline, number+1, trimmed)
		}
		baseline[trimmed] = true
	}
	return baseline, nil
}
