package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A stage of the image calls a tool it never installed, and the image is built
// and published and only fails when an operator runs the command that needs it.
//
// Asked because jq nearly became that: it is called ten times in the
// admin-tools stage and installed once there, and nothing held the two
// together. The next stage to call it - or the next tool added to a script -
// would have had nothing to say so.
//
// The first shape of this check took the tools from the image's own install
// commands alone, on the reasoning that a package the image installs is one it
// has already decided is not in its base. That reasoning has a hole, and taking
// jq out of the install line to test the check showed it: with nothing
// installing jq, nothing asked about jq either, and the check reported that it
// had compared nothing. A tool called and never installed anywhere - the whole
// defect - was the one case it could not see.
//
// So the candidates are the union of two sets: every package the image installs
// anywhere, which needs no maintenance, and the list below, which does. The
// list exists because deciding whether a command is in a base image means
// knowing that base, and the bases here are ARGs this check may not pull.

// stageStart finds a build stage and the image it is built on.
var stageStart = regexp.MustCompile(`(?m)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)

// installs finds the packages a stage's scripts install.
var installs = regexp.MustCompile(`(?:apt-get|apt)\s+install[^&|\n]*|(?:apk)\s+add[^&|\n]*|(?:microdnf|dnf|yum)\s+install[^&|\n]*`)

// carriedByBase names what an external base image brings with it, by the name
// the Containerfile builds on. The tools stage stands on postgres:17-bookworm,
// so psql and the dump tools are there without being installed - and the first
// run of this check reported all three as missing, which is the false side of
// the list below and the reason this mapping exists.
//
// Read from the ARG's default in the file rather than by pulling the image:
// nothing here may reach a registry.
var carriedByBase = map[string][]string{
	"postgres": {"psql", "pg_dump", "pg_restore", "pg_isready", "createdb", "dropdb"},
	"golang":   {"go", "gofmt", "git", "curl", "gpg"},
	"node":     {"node", "npm"},
}

// notInASlimBase names commands a minimal Debian or distroless base does not
// carry, so a stage calling one has to install it. Short on purpose: a wrong
// entry here refuses a stage that was right, and tar, gzip, sed and the
// coreutils are in every base this image builds on.
var notInASlimBase = []string{
	"jq", "zstd", "curl", "gpg", "psql", "pg_dump", "pg_restore", "nc", "xz",
}

// commandNames maps a package to the command it provides, where the two differ.
// Each entry is a package this image actually installs; a package whose command
// has its own name needs no entry.
var commandNames = map[string][]string{
	"postgresql-client": {"psql", "pg_dump", "pg_restore"},
	"ca-certificates":   nil, // provides no command
	"netcat-openbsd":    {"nc"},
}

// argDefault finds the default of an ARG declared at the top of the file.
var argDefault = regexp.MustCompile(`(?m)^ARG\s+([A-Z_]+)=(\S+)`)

// resolveArgs replaces ${NAME} with the default the file declares for it. A
// stage builds on ${TOOLS_IMAGE}, not on the image's name, so without this the
// base is never recognised - which is how the first version of this check
// reported psql as missing from a stage standing on postgres.
func resolveArgs(base string, defaults map[string]string) string {
	for name, value := range defaults {
		base = strings.ReplaceAll(base, "${"+name+"}", value)
		base = strings.ReplaceAll(base, "$"+name, value)
	}
	return base
}

type imageStage struct {
	name     string
	base     string
	body     string
	installs map[string]bool
}

// imageStages splits the Containerfile into its stages.
func imageStages(root string) ([]imageStage, error) {
	text, err := readText(root, composeDir, "Containerfile")
	if err != nil {
		return nil, err
	}
	bounds := stageStart.FindAllStringSubmatchIndex(text, -1)
	if len(bounds) == 0 {
		return nil, fmt.Errorf("%s/Containerfile declares no build stage", composeDir)
	}
	defaults := map[string]string{}
	for _, found := range argDefault.FindAllStringSubmatch(text, -1) {
		defaults[found[1]] = found[2]
	}
	stages := make([]imageStage, 0, len(bounds))
	for i, at := range bounds {
		end := len(text)
		if i+1 < len(bounds) {
			end = bounds[i+1][0]
		}
		match := stageStart.FindStringSubmatch(text[at[0]:at[1]])
		stage := imageStage{base: resolveArgs(match[1], defaults), name: match[2],
			body: text[at[0]:end], installs: map[string]bool{}}
		for _, line := range installs.FindAllString(stage.body, -1) {
			for _, word := range strings.Fields(line) {
				switch {
				case strings.HasPrefix(word, "-"), word == "install", word == "add",
					word == "apt-get", word == "apt", word == "apk", word == "dnf",
					word == "yum", word == "microdnf", word == "&&", word == "\\":
					continue
				}
				stage.installs[word] = true
			}
		}
		stages = append(stages, stage)
	}
	return stages, nil
}

// baseCommands says what the external image a chain ends on carries.
func baseCommands(base string) map[string]bool {
	have := map[string]bool{}
	name := base
	if at := strings.LastIndex(name, "/"); at >= 0 {
		name = name[at+1:]
	}
	name = strings.SplitN(name, ":", 2)[0]
	for family, commands := range carriedByBase {
		if name == family || strings.HasPrefix(name, family) {
			for _, command := range commands {
				have[command] = true
			}
		}
	}
	return have
}

// reach returns every package a stage has: what it and its ancestors installed,
// and what the external image the chain ends on carries.
func reach(stages []imageStage, name string) map[string]bool {
	byName := map[string]imageStage{}
	for _, stage := range stages {
		byName[stage.name] = stage
	}
	have := map[string]bool{}
	for seen := map[string]bool{}; name != "" && !seen[name]; {
		seen[name] = true
		stage, found := byName[name]
		if !found {
			// The chain ends outside the file: this is the base image.
			for command := range baseCommands(name) {
				have[command] = true
			}
			break
		}
		for pkg := range stage.installs {
			have[pkg] = true
		}
		// A stage built on an external image ends the chain there.
		if _, local := byName[stage.base]; !local {
			for command := range baseCommands(stage.base) {
				have[command] = true
			}
		}
		name = stage.base
	}
	return have
}

// imageToolsAreInstalled holds every stage to installing the tools it calls.
func imageToolsAreInstalled(root string) ([]finding, error) {
	stages, err := imageStages(root)
	if err != nil {
		return nil, err
	}

	// Both sets: what the image installs, and what no slim base carries.
	packages := map[string]bool{}
	for _, stage := range stages {
		for pkg := range stage.installs {
			packages[pkg] = true
		}
	}
	for _, command := range notInASlimBase {
		packages[command] = true
	}

	var findings []finding
	asked := 0
	for _, stage := range stages {
		if stage.name == "" {
			continue
		}
		have := reach(stages, stage.name)
		for pkg := range packages {
			for _, command := range commandsOf(pkg) {
				if !callsCommand(stage.body, command) {
					continue
				}
				asked++
				if have[pkg] {
					continue
				}
				findings = append(findings, finding{
					place: composeDir + "/Containerfile",
					said: fmt.Sprintf("the stage %s calls %s and neither it nor the stages it is "+
						"built on install %s; the image publishes and the command fails when an "+
						"operator runs it", stage.name, command, pkg),
				})
			}
		}
	}
	if asked == 0 {
		return []finding{{
			place: composeDir + "/Containerfile",
			said: fmt.Sprintf("no stage calls any of the %d tool(s) this check knows (%s), so it "+
				"compared nothing", len(packages), strings.Join(sorted(packages), ", ")),
		}}, nil
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].said < findings[j].said })
	return findings, nil
}

// commandsOf names the commands a package provides.
func commandsOf(pkg string) []string {
	if mapped, found := commandNames[pkg]; found {
		return mapped
	}
	return []string{pkg}
}

// callsCommand says whether a stage's text invokes the command, as a word and
// not as part of another name: "jq" is called, "jquery" is not.
func callsCommand(body, command string) bool {
	word := regexp.MustCompile(`(^|[^-\w./])` + regexp.QuoteMeta(command) + `($|[^-\w.])`)
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		// A comment is not a call, and neither is the install itself.
		if strings.HasPrefix(trimmed, "#") || installs.MatchString(trimmed) {
			continue
		}
		if word.MatchString(trimmed) {
			return true
		}
	}
	return false
}
