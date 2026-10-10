package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing compiled the browser suite until 10.10. tsconfig.json includes
// "src" and nothing else, and Playwright transpiles without checking types,
// so the first compiler between an edit in e2e/ and its author was a
// laboratory run seventy minutes long - and only if the suite reached that
// file at all. Eighty skips were rewritten that day with no compiler in
// between, and one of them passed undefined where a string was wanted.
//
// Three pieces make the check exist, and each of them is one delete away from
// being gone again: the configuration that names e2e, the script that runs
// the compiler over it, and the job in CI that runs the script. Removing any
// one leaves the other two looking healthy, which is why this reads all three.

func TestTheBrowserSuiteIsTypeChecked(t *testing.T) {
	root := filepath.Join("..", "..")

	// 1. The configuration compiles e2e, and extends the panel's own, so the
	//    suite is held to the same strictness as the product.
	raw, err := os.ReadFile(filepath.Join(root, "web", "tsconfig.e2e.json"))
	if err != nil {
		t.Fatalf("web/tsconfig.e2e.json: %v; without it the browser suite is compiled by nothing", err)
	}
	// JSON with comments: the file is read by tsc, which allows them, so the
	// comment lines come off before it is parsed.
	var config struct {
		Extends string   `json:"extends"`
		Include []string `json:"include"`
	}
	if err := json.Unmarshal(withoutComments(raw), &config); err != nil {
		t.Fatalf("web/tsconfig.e2e.json is not readable as JSON: %v", err)
	}
	if config.Extends == "" {
		t.Error("web/tsconfig.e2e.json extends nothing, so the suite is held to " +
			"different rules than the panel it drives")
	}
	if !containsString(config.Include, "e2e") {
		t.Errorf("web/tsconfig.e2e.json includes %v, which does not name e2e", config.Include)
	}

	// 2. A script runs the compiler over it.
	pkg, err := os.ReadFile(filepath.Join(root, "web", "package.json"))
	if err != nil {
		t.Fatalf("web/package.json: %v", err)
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(pkg, &manifest); err != nil {
		t.Fatalf("web/package.json is not readable as JSON: %v", err)
	}
	script, ok := manifest.Scripts["typecheck:e2e"]
	if !ok {
		t.Fatal("web/package.json has no typecheck:e2e script; the configuration " +
			"above is then a file nothing reads")
	}
	if !strings.Contains(script, "tsconfig.e2e.json") {
		t.Errorf("the typecheck:e2e script is %q, which does not use tsconfig.e2e.json", script)
	}

	// 3. And CI runs the script, on every change rather than only where a
	//    laboratory happens to be.
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("ci.yml: %v", err)
	}
	if !strings.Contains(string(ci), "typecheck:e2e") {
		t.Error("ci.yml does not run typecheck:e2e; a script nobody runs is not a check")
	}
}

// withoutComments strips // lines, which tsconfig files are allowed to carry
// and encoding/json is not.
func withoutComments(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

func containsString(all []string, want string) bool {
	for _, one := range all {
		if one == want {
			return true
		}
	}
	return false
}
