// archcheck holds the tree to the boundaries it is supposed to have.
//
// The product is one repository and one deployable, and that is the right shape
// for it - but without a rule that is checked, "one repository" turns into "any
// package may reach into any other", and it had: the root helper owned a piece
// of plumbing that internal/packages and internal/modules/backup imported from
// it, so a module depended on the helper rather than the other way round.
//
// The rules below are the ones that hold now. A rule that does not hold yet is
// not written here, because a rule nobody enforces is worse than none: it reads
// like a promise. The ones that remain - opspec free of the concrete modules,
// and the panel's shared components free of its pages - are in the audit and
// come with the changes that make them true.
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// module is the import path of this repository.
const module = "github.com/ultherego/flotestro/"

// rule says which packages may not import what, and why. The reason is printed
// with the failure: a boundary nobody can explain is a boundary nobody keeps.
type rule struct {
	// within is the prefix of the packages the rule applies to, relative to the
	// repository root.
	within string
	// forbidden are the import prefixes those packages may not use.
	forbidden []string
	// except are the import prefixes allowed inside the forbidden ones.
	except []string
	reason string
}

var rules = []rule{
	{
		within:    "internal/modules/",
		forbidden: []string{"internal/helper"},
		reason: "a module describes and carries out one kind of change and the root helper calls it; " +
			"a module that imports the helper turns that round, and the helper is the privileged side",
	},
	{
		within:    "internal/platform/",
		forbidden: []string{"internal/"},
		except:    []string{"internal/platform/"},
		reason: "the platform packages are the neutral ground everything may use, so they depend on " +
			"nothing of ours; one that imports a feature is no longer neutral",
	},
	{
		within:    "",
		forbidden: []string{"internal/helper/"},
		except:    []string{},
		reason: "the helper owns no plumbing that anything else needs: a package under internal/helper " +
			"that another part imports belongs in internal/platform instead",
	},
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		fail(err)
	}
	problems, err := violations(root)
	if err != nil {
		fail(err)
	}
	if len(problems) == 0 {
		fmt.Println("the boundaries hold")
		return
	}
	for _, problem := range problems {
		fmt.Fprintln(os.Stderr, problem)
	}
	fmt.Fprintf(os.Stderr, "\n%d import(s) cross a boundary this repository keeps\n", len(problems))
	os.Exit(1)
}

// violations walks the tree and returns every import that crosses a boundary,
// sorted so the answer is the same twice.
func violations(root string) ([]string, error) {
	var problems []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "web", "docs", "Vagrant":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		problems = append(problems, checkFile(relative, path)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(problems)
	return problems, nil
}

func checkFile(relative, path string) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		// A file that does not parse is the compiler's business, not this tool's.
		return nil
	}
	var problems []string
	for _, spec := range parsed.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !strings.HasPrefix(imported, module) {
			continue
		}
		inside := strings.TrimPrefix(imported, module)
		for _, r := range rules {
			if !strings.HasPrefix(relative, r.within) {
				continue
			}
			// A package does not break a rule by importing itself or its own kind.
			if r.within != "" && strings.HasPrefix(inside, r.within) {
				continue
			}
			if r.within == "" && strings.HasPrefix(relative, "internal/helper/") {
				continue
			}
			if !anyPrefix(inside, r.forbidden) || anyPrefix(inside, r.except) {
				continue
			}
			problems = append(problems, fmt.Sprintf("%s imports %s\n    %s", relative, inside, r.reason))
		}
	}
	return problems
}

func anyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "archcheck:", err)
	os.Exit(1)
}
