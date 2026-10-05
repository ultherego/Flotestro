package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The documentation of a disconnected installation carries a loop that verifies
// every image and then copies it. It is the one place a signature is checked by
// a person rather than by a workflow, and it is the only way packages reach a
// site with no route to the registry - so what it claims to check has to be
// checkable, and a check that fails has to stop the copy.
//
// The documentation is read where installation procedures live. A copy of the
// loop written outside these directories escapes this check; that is why the
// check refuses to pass when it finds no loop at all, and why it reports how
// many it read.
var documentationRoots = []string{"docs", "docker"}

// verifyLoop is one documented loop: the lines it is made of, the images it
// names and where it starts.
type verifyLoop struct {
	place  string
	images []string
	body   string
}

var (
	loopHeader   = regexp.MustCompile(`^\s*for\s+\w+\s+in\s+(.+?);?\s*do\s*$`)
	imagesVector = regexp.MustCompile(`^\s*images="([^"]*)"\s*$`)
	imageName    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// verifyLoops finds every documented loop that runs cosign verify.
func verifyLoops(root string) ([]verifyLoop, error) {
	var loops []verifyLoop
	for _, directory := range documentationRoots {
		// A directory that is not there holds no procedure. Naming one that
		// never existed cannot hide a loop either, because finding none at
		// all is a failure of this check rather than a pass.
		if _, err := os.Stat(filepath.Join(root, directory)); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".html", ".htm", ".md":
			default:
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			loops = append(loops, loopsIn(filepath.ToSlash(relative), string(content))...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(loops, func(i, j int) bool { return loops[i].place < loops[j].place })
	return loops, nil
}

// loopsIn reads one document. A loop is the run of lines from its "for" to its
// "done"; the names it walks are either written into the header or set just above
// it in a variable, and both forms are in the tree.
func loopsIn(name, content string) []verifyLoop {
	lines := strings.Split(content, "\n")
	vector := ""
	var loops []verifyLoop
	for number, line := range lines {
		if match := imagesVector.FindStringSubmatch(stripMarkup(line)); match != nil {
			vector = match[1]
			continue
		}
		match := loopHeader.FindStringSubmatch(stripMarkup(line))
		if match == nil {
			continue
		}
		body := []string{stripMarkup(line)}
		for _, rest := range lines[number+1:] {
			body = append(body, stripMarkup(rest))
			if strings.TrimSpace(stripMarkup(rest)) == "done" ||
				strings.HasPrefix(strings.TrimSpace(stripMarkup(rest)), "done<") {
				break
			}
		}
		joined := strings.Join(body, "\n")
		if !strings.Contains(joined, "cosign verify") {
			vector = ""
			continue
		}
		words := strings.Fields(match[1])
		if len(words) == 1 && strings.HasPrefix(words[0], "$") {
			words = strings.Fields(vector)
		}
		var images []string
		for _, word := range words {
			if imageName.MatchString(word) {
				images = append(images, word)
			}
		}
		loops = append(loops, verifyLoop{
			place:  fmt.Sprintf("%s:%d", name, number+1),
			images: images,
			body:   joined,
		})
		vector = ""
	}
	return loops
}

// stripMarkup takes the HTML out of a line so that a snippet inside <pre><code>
// reads the same as one in a fenced Markdown block.
func stripMarkup(line string) string {
	var out strings.Builder
	inside := false
	for _, letter := range line {
		switch {
		case letter == '<':
			inside = true
		case letter == '>':
			inside = false
		case !inside:
			out.WriteRune(letter)
		}
	}
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`).Replace(out.String())
}

// The words that make a failed verification stop the copy. A pasted loop cannot
// use set -e - in an interactive shell it is either ignored or it closes the
// session - so the refusal has to be on the command itself.
var refusals = []string{"|| break", "|| exit", "|| return", "|| { ", "&& docker pull", "&& skopeo"}

// airgapVerifyStops holds every documented loop to stopping when a signature
// does not verify. Without it the loop walks on to docker pull and docker save,
// and the archive is then checksummed and signed with the site's own key as
// though the signature had been checked.
func airgapVerifyStops(root string) ([]finding, error) {
	loops, err := verifyLoops(root)
	if err != nil {
		return nil, err
	}
	if len(loops) == 0 {
		return []finding{{
			place: strings.Join(documentationRoots, ", "),
			said:  "no documented cosign verify loop was found, so this check inspected nothing",
		}}, nil
	}
	var findings []finding
	for _, loop := range loops {
		stops := false
		for _, refusal := range refusals {
			if strings.Contains(loop.body, refusal) {
				stops = true
				break
			}
		}
		if !stops {
			findings = append(findings, finding{
				place: loop.place,
				said: "a documented cosign verify loop carries on after a signature does not verify; " +
					"make the failure stop the copy (\"|| break\" and a line saying why)",
			})
		}
	}
	return findings, nil
}

// airgapImagesAreSigned compares the set an operator is told to verify with the
// set the release signs.
func airgapImagesAreSigned(root string) ([]finding, error) {
	signed, err := signedImages(root)
	if err != nil {
		return nil, err
	}
	loops, err := verifyLoops(root)
	if err != nil {
		return nil, err
	}
	if len(loops) == 0 || len(signed) == 0 {
		return []finding{{
			place: ".github/workflows/images.yml",
			said: fmt.Sprintf("%d documented loop(s) and %d signed image(s) were found, so this check compared nothing",
				len(loops), len(signed)),
		}}, nil
	}

	var findings []finding
	for _, loop := range loops {
		if len(loop.images) == 0 {
			findings = append(findings, finding{
				place: loop.place,
				said:  "a documented cosign verify loop names no image this check could read",
			})
			continue
		}
		for _, short := range loop.images {
			if signed["flotestro-"+short] {
				continue
			}
			findings = append(findings, finding{
				place: loop.place,
				said: fmt.Sprintf("tells the operator to verify flotestro-%s, which no job signs; "+
					"the images signed are %s", short, strings.Join(sorted(signed), ", ")),
			})
		}
	}
	return findings, nil
}

// signedImages reads the images the release signs out of the workflows
// themselves, so that an image added to a matrix is counted without anybody
// editing this tool.
//
// Every workflow is read, not one: the repository image of an isolated site is
// built and signed by release.yml and nowhere near the matrix of images.yml,
// and reading only that matrix reported it as signed by nobody for as long as
// it was. A job counts only when one of its own steps runs cosign sign, so a
// matrix whose job stopped signing does not read as four signed images.
//
// A name is taken either from the job's matrix or from the scripts of the job
// that signs. Shell comments are cut out of those scripts first: a name
// mentioned in a comment beside the signing would otherwise read as signed,
// and this check exists to refuse exactly that kind of agreement.
func signedImages(root string) (map[string]bool, error) {
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading the workflows: %w", err)
	}
	signed := map[string]bool{}
	read := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		text, err := readText(root, ".github", "workflows", name)
		if err != nil {
			return nil, err
		}
		var document yaml.Node
		if err := yaml.Unmarshal([]byte(text), &document); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(document.Content) == 0 {
			return nil, fmt.Errorf("%s is empty", name)
		}
		read++
		jobs := field(document.Content[0], "jobs")
		if jobs == nil {
			continue
		}
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			collectSignedImages(jobs.Content[i+1], signed)
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("no workflow was read, so nothing could say which images are signed")
	}
	return signed, nil
}

// collectSignedImages adds the images one job signs, and nothing when it does
// not sign.
func collectSignedImages(job *yaml.Node, signed map[string]bool) {
	steps := field(job, "steps")
	if steps == nil {
		return
	}
	var scripts []string
	signs := false
	for _, step := range steps.Content {
		run := field(step, "run")
		if run == nil {
			continue
		}
		scripts = append(scripts, run.Value)
		if strings.Contains(run.Value, "cosign sign") {
			signs = true
		}
	}
	if !signs {
		return
	}
	if include := field(field(field(job, "strategy"), "matrix"), "include"); include != nil {
		for _, entry := range include.Content {
			if image := field(entry, "image"); image != nil && image.Value != "" {
				signed[image.Value] = true
			}
		}
	}
	for _, script := range scripts {
		for _, name := range imageNames.FindAllString(withoutShellComments(script), -1) {
			signed[name] = true
		}
	}
}

// imageNames matches an image of this product written out in full.
var imageNames = regexp.MustCompile(`flotestro-[a-z0-9]+(?:-[a-z0-9]+)*`)

// withoutShellComments drops what a script says about itself, keeping what it
// does.
func withoutShellComments(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
