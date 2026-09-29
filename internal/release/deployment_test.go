package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
			t.Skipf("%s is not in this tree", path)
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
