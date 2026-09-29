package release

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// absent emits the classification the release gate reads out of a skipped test,
// exactly as the integration harness does. These two tests are the regression
// tests for a panel that did not come back after a reboot and for a pre-flight
// check that performed the migration it was asked about; a silent skip of
// either reads like a pass.
func absent(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("FLOTESTRO-SKIP class=%s reason=%q", SkipAbsent, fmt.Sprintf(format, args...))
}

// The restart policy is not a preference. Rootless Podman replays the policies
// at boot with the unit it ships, and that unit runs
//
//	podman start --all --filter restart-policy=always
//
// so a service that says "unless-stopped" is skipped by it: the unit reports
// success, starts nothing, and the panel is down after every reboot of the
// host with nothing saying why. That is how it was for a while, and a test is
// cheaper than finding it again.
func TestEveryServiceThatMustSurviveARebootSaysAlways(t *testing.T) {
	service := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):$`)
	restart := regexp.MustCompile(`(?m)^    restart: (.+)$`)
	for _, file := range []string{"compose.yaml", "compose.relay.yaml"} {
		path := filepath.Join("..", "..", "docker", file)
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			absent(t, "%s is not in this tree, so the restart policies were never read", path)
		}
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)

		// Which service a policy belongs to, by the last service header above it.
		names := service.FindAllStringSubmatchIndex(text, -1)
		nameAt := func(offset int) string {
			name := "(none)"
			for _, match := range names {
				if match[0] > offset {
					break
				}
				name = text[match[2]:match[3]]
			}
			return name
		}

		found := 0
		for _, match := range restart.FindAllStringSubmatchIndex(text, -1) {
			policy := strings.TrimSpace(text[match[2]:match[3]])
			name := nameAt(match[0])
			found++
			switch policy {
			case `"no"`:
				// A one-shot: init, the migrator, the tools. Nothing should bring
				// these back on their own.
			case "always":
			default:
				t.Errorf("%s: the service %s says restart: %s; the unit podman ships starts only "+
					"restart-policy=always, so this service would not come back after a reboot",
					file, name, policy)
			}
		}
		if found == 0 {
			t.Errorf("%s declares no restart policy at all", file)
		}
	}
}

// The question an upgrade asks before it decides anything has to cost nothing.
// "run" starts what the named service depends on, so asking it through the
// control plane - which depends on migrate - performs the migration it is
// about and then reports that nothing needs migrating. That was the documented
// procedure once, and it was measured doing exactly this on both engines: an
// empty database came back at the head of the schema, exit 0. --no-deps is no
// answer either, because podman-compose puts the dependency on the one-off
// container itself with --requires and podman honours it.
func TestThePreFlightSchemaCheckDependsOnNothing(t *testing.T) {
	path := filepath.Join("..", "..", "docker", "compose.yaml")
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		absent(t, "%s is not in this tree, so the pre-flight service was never read", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	start := regexp.MustCompile(`(?m)^  schema-check:$`).FindStringIndex(text)
	if start == nil {
		t.Fatalf("%s declares no schema-check service; the upgrade has nothing to ask "+
			"that does not first migrate the database it is asking about", path)
	}
	block := text[start[1]:]
	// As far as the next service header or the next top-level key.
	if next := regexp.MustCompile("(?m)^(?:[a-z]|  [a-z])").FindStringIndex(block[1:]); next != nil {
		block = block[:next[0]+1]
	}
	if regexp.MustCompile(`(?m)^    depends_on:$`).MatchString(block) {
		t.Errorf("%s: the schema-check service declares depends_on; a pre-flight check that "+
			"starts anything can start the migration it was asked to look for", path)
	}
	if !strings.Contains(block, `command: ["schema-check"]`) {
		t.Errorf("%s: the schema-check service does not run the schema-check command", path)
	}
	if !strings.Contains(block, `profiles: ["check"]`) {
		t.Errorf("%s: the schema-check service carries no profile, so an ordinary up would "+
			"run it and leave a refusal behind before the migration has had its turn", path)
	}
}

// And nothing may tell an operator to ask it the old way again. The service
// that answers writes nothing; the one that used to be named drags migrate in
// behind it.
func TestNoDocumentAsksTheControlPlaneForASchemaCheck(t *testing.T) {
	asked := regexp.MustCompile(`run\s+(?:--rm\s+)?control-plane\s+schema-check`)
	for _, file := range []string{
		filepath.Join("..", "..", "docker", "README.md"),
		filepath.Join("..", "..", "docs", "runbooks", "install.md"),
		filepath.Join("..", "..", "docs", "site", "docs", "installation.html"),
		filepath.Join("..", "..", "docs", "site", "pl", "docs", "installation.html"),
	} {
		content, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			if asked.MatchString(line) {
				t.Errorf("%s: %q asks the control plane for the schema check, which starts "+
					"migrate first; the command is "+
					"\"docker compose --profile check run --rm schema-check\"",
					file, strings.TrimSpace(line))
			}
		}
	}
}
