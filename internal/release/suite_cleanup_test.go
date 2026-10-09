package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// t.Cleanup runs last in, first out, and the integration harness opens its
// database pool the first time anything asks for it - registering Close at
// that moment. A cleanup that asks for the pool inside its own closure
// therefore races the pool's own Close: if the test touched the database after
// registering that cleanup, Close was registered later and runs earlier, and
// the cleanup finds a closed pool.
//
// It did. One run on 09.10 left four synthetic hosts in the laboratory's
// installation - counted by the fleet list, the dashboard and the readiness
// page ever after - and the only trace was a Logf in a test that passed.
//
// So a cleanup takes what it needs before it is registered, and this reads the
// suite to make sure it still does.
func TestNoCleanupInTheSuiteOpensTheDatabaseInsideItself(t *testing.T) {
	dir := filepath.Join("..", "..", "tests", "integration")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("the integration suite is not readable, so this guard checks nothing: %v", err)
	}
	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		for _, block := range cleanupBlocks(string(body)) {
			checked++
			if strings.Contains(block.text, ".database(") {
				t.Errorf("%s:%d: a cleanup opens the database inside its own closure; "+
					"the pool's Close may already have run by then. Take the pool before "+
					"registering the cleanup, as harness.forgetHostOnCleanup does",
					entry.Name(), block.line)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the suite registers no cleanup at all; either it changed shape or this guard " +
			"stopped reading it")
	}
	t.Logf("%d cleanup closures read", checked)
}

type sourceBlock struct {
	line int
	text string
}

// cleanupBlocks returns the body of every t.Cleanup(func() { ... }) it finds,
// by counting braces from the opening one.
func cleanupBlocks(source string) []sourceBlock {
	var blocks []sourceBlock
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "Cleanup(func()") {
			continue
		}
		depth, body := 0, []string{}
		for _, rest := range lines[i:] {
			depth += strings.Count(rest, "{") - strings.Count(rest, "}")
			body = append(body, rest)
			if depth <= 0 && len(body) > 1 {
				break
			}
		}
		blocks = append(blocks, sourceBlock{line: i + 1, text: strings.Join(body, "\n")})
	}
	return blocks
}
