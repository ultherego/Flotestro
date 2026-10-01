package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The first-run checklist is built on the server and mirrored by hand in the
// integration suite, which asserts the order of its steps. That suite is behind
// a build tag, so "go vet ./..." never compares the two: a step added on the
// server is caught only when the gate reaches the integration stage, four
// thousand seconds in. It happened on 01.10 with installation_keys, and the hour
// it cost is the reason this rule exists.
const (
	checklistSource = "internal/adminapi/setup.go"
	checklistMirror = "tests/integration/setup_test.go"
)

var (
	// Key: "fleet_ca" - the step as the server emits it.
	checklistStepKey = regexp.MustCompile(`Key:\s*"([a-z_]+)"`)
	// The mirror is one var block of quoted keys.
	checklistMirrorBlock = regexp.MustCompile(`(?s)var setupStepKeys = \[\]string\{(.*?)\}`)
	checklistQuoted      = regexp.MustCompile(`"([a-z_]+)"`)
)

// checklistMirrorIsComplete compares the steps the server builds with the list
// the integration suite checks them against.
func checklistMirrorIsComplete(root string) ([]finding, error) {
	server, err := os.ReadFile(filepath.Join(root, checklistSource))
	if err != nil {
		return nil, err
	}
	mirror, err := os.ReadFile(filepath.Join(root, checklistMirror))
	if err != nil {
		return nil, err
	}

	built := map[string]bool{}
	for _, match := range checklistStepKey.FindAllStringSubmatch(string(server), -1) {
		built[match[1]] = true
	}
	if len(built) == 0 {
		return []finding{{place: checklistSource, said: "no checklist step found; has the shape changed?"}}, nil
	}

	block := checklistMirrorBlock.FindStringSubmatch(string(mirror))
	if block == nil {
		return []finding{{place: checklistMirror, said: "no setupStepKeys list found; has the mirror moved?"}}, nil
	}
	named := map[string]bool{}
	for _, match := range checklistQuoted.FindAllStringSubmatch(block[1], -1) {
		named[match[1]] = true
	}

	var findings []finding
	for key := range built {
		if !named[key] {
			findings = append(findings, finding{
				place: checklistSource,
				said:  fmt.Sprintf("the server builds the step %q and the suite's list does not name it", key),
			})
		}
	}
	for key := range named {
		if !built[key] {
			findings = append(findings, finding{
				place: checklistMirror,
				said:  fmt.Sprintf("the suite expects the step %q and the server builds no such step", key),
			})
		}
	}
	// A stable order, so two runs read the same.
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if strings.Compare(findings[j].said, findings[i].said) < 0 {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
	return findings, nil
}
