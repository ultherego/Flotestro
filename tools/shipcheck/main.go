// shipcheck holds the product to what the product says about itself.
//
// The recurring defect in this repository is one thing described in two places
// and edited in one: the operator documentation against the panel, the two
// Compose variants against each other, the air-gap procedure against the
// workflow that signs. Each of those cost a day, and none of them needed the
// laboratory to find - they are all properties of the tree, so they belong on a
// runner that looks at every push rather than in a run somebody pays for.
//
// Each check below answers one question and names the file and line of every
// answer it did not like. A check that finds nothing to inspect fails: a guard
// that cannot fail is decoration, and "no pages read" must never read as "every
// page has its translation".
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A finding is one thing that is not the way the product says it is. The place
// is "file:line" wherever a line means anything, because a failure that does not
// say where costs the next person the investigation this tool exists to remove.
type finding struct {
	place string
	said  string
}

func (f finding) String() string { return f.place + ": " + f.said }

type check struct {
	name string
	// why is printed with the failures: a rule nobody can explain is a rule
	// nobody keeps.
	why string
	run func(root string) ([]finding, error)
}

var checks = []check{
	{
		name: "site-languages",
		why: "every page of the site exists in English and in Polish; a page with no counterpart " +
			"is half a change, and the site publishes it either way",
		run: siteLanguages,
	},
	{
		name: "healthcheck-form",
		why: "a healthcheck on a shell-less image has to be written in exec form; a shell string " +
			"there cannot run at all, and the container reports unhealthy while serving",
		run: healthcheckForm,
	},
	{
		name: "airgap-verify-stops",
		why: "a documented verification loop must stop when a signature does not verify, or the " +
			"operator carries an unverified image across the gap and signs it as checked",
		run: airgapVerifyStops,
	},
	{
		name: "airgap-images-are-signed",
		why: "every image the air-gap procedure tells an operator to verify has to be one the " +
			"release actually signs, or the verification cannot succeed and the step is theatre",
		run: airgapImagesAreSigned,
	},
	{
		name: "checklist-mirror-is-complete",
		why: "the first-run checklist is built on the server and mirrored by hand in the integration " +
			"suite, which is behind a build tag: a step added on one side is caught only when the " +
			"gate reaches the integration stage, an hour in",
		run: checklistMirrorIsComplete,
	},
	{
		name: "table-headers-declare-scope",
		why: "a column header that does not say scope stops being a header to a screen reader as " +
			"soon as the browser takes its table for a layout, which it does whenever the table " +
			"is short; the cells are then read without their column",
		run: tableHeadersDeclareScope,
	},
	{
		name: "env-example-reaches-the-deployment",
		why: "a key offered in env.example has to reach the deployment; one that reaches nothing " +
			"is a setting the operator makes and the product never reads",
		run: envExampleReachesTheDeployment,
	},
}

func main() {
	root := flag.String("root", ".", "the root of the repository to inspect")
	list := flag.Bool("list", false, "print the names of the checks and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage: shipcheck [-root dir] [check ...]\n\nWith no check named, every check runs.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *list {
		for _, one := range checks {
			fmt.Println(one.name)
		}
		return
	}

	selected, err := selectChecks(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	failed := false
	for _, one := range selected {
		findings, err := one.run(*root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", one.name, err)
			failed = true
			continue
		}
		if len(findings) == 0 {
			fmt.Printf("%s: ok\n", one.name)
			continue
		}
		failed = true
		fmt.Fprintf(os.Stderr, "%s: %d finding(s)\n%s\n", one.name, len(findings), one.why)
		for _, found := range findings {
			fmt.Fprintf(os.Stderr, "  %s\n", found)
		}
	}
	if failed {
		os.Exit(1)
	}
}

// selectChecks resolves the names on the command line. A name that matches
// nothing is an error rather than an empty run, because a workflow that asks for
// a check by a name nobody has any more would otherwise pass by asking for
// nothing - which is how a green run over zero tests happens.
func selectChecks(names []string) ([]check, error) {
	if len(names) == 0 {
		return checks, nil
	}
	byName := map[string]check{}
	for _, one := range checks {
		byName[one.name] = one
	}
	selected := make([]check, 0, len(names))
	for _, name := range names {
		one, ok := byName[name]
		if !ok {
			known := make([]string, 0, len(checks))
			for _, each := range checks {
				known = append(known, each.name)
			}
			return nil, fmt.Errorf("there is no check called %q; there are %s",
				name, strings.Join(known, ", "))
		}
		selected = append(selected, one)
	}
	return selected, nil
}

func sorted(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// readText reads one file of the tree, saying which file when it cannot.
func readText(root string, parts ...string) (string, error) {
	path := filepath.Join(append([]string{root}, parts...)...)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", filepath.Join(parts...), err)
	}
	return string(content), nil
}
