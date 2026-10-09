package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Replacing a socket unit's file and reloading systemd takes the listening
// descriptor away from the running unit: systemd says so in the journal -
// "Socket unit configuration has changed while unit has been running, no open
// socket file descriptor left. The socket unit is not functional until
// restarted" - and leaves the unit reporting active. "enable --now" then does
// nothing, because there is nothing for it to start.
//
// Every package did exactly that. An upgrade on a running host therefore left
// the helper unreachable: the agent logged "connecting to the helper: dial unix
// /run/flotestro/helper.sock: connect: connection refused", the panel showed no
// capability mode for the host, and every operation that needs a signed
// capability was refused until somebody restarted the unit by hand. Measured on
// agent-fedora on 09.10, and the arch upgrade hook did not mention the socket
// at all.
//
// So: a scriptlet that reloads systemd has to restart the socket.
func TestEveryPackageRestartsTheHelperSocketWhenItReloadsSystemd(t *testing.T) {
	const socket = "restart flotestro-helper.socket"
	// The arch hook is one file holding several scriptlets, so it is read per
	// function; the other two are one scriptlet each.
	scriptlets := map[string]string{
		"packaging/rpm/flotestro-agent.spec": "",
		"packaging/deb/agent.postinst":       "",
	}
	for path := range scriptlets {
		body, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatalf("%s is not readable, so this guard checks nothing: %v", path, err)
		}
		scriptlets[path] = string(body)
	}
	arch, err := os.ReadFile(filepath.Join("..", "..", "packaging", "arch", "flotestro-agent.install"))
	if err != nil {
		t.Fatalf("the arch hook is not readable: %v", err)
	}
	// post_install() { ... } up to the closing brace in the first column.
	function := regexp.MustCompile(`(?ms)^(post_install|post_upgrade)\(\) \{\n(.*?)^\}`)
	found := function.FindAllStringSubmatch(string(arch), -1)
	if len(found) != 2 {
		t.Fatalf("the arch hook declares %d of the two scriptlets this guard reads", len(found))
	}
	for _, match := range found {
		scriptlets["packaging/arch/flotestro-agent.install:"+match[1]] = match[2]
	}

	checked := 0
	for name, body := range scriptlets {
		// %systemd_post expands to a daemon-reload of its own, so a spec that
		// uses the macro reloads even without naming the command.
		if !strings.Contains(body, "daemon-reload") && !strings.Contains(body, "%systemd_post") {
			continue
		}
		checked++
		if !strings.Contains(body, socket) {
			t.Errorf("%s reloads systemd and never restarts the helper socket; "+
				"the unit it leaves behind reports active and listens on nothing, "+
				"so the host answers no capability after an upgrade", name)
		}
		if strings.Contains(body, "enable --now flotestro-helper.socket") {
			t.Errorf("%s still starts the helper socket with \"enable --now\", which does "+
				"nothing to the unit a reload has just emptied", name)
		}
	}
	if checked == 0 {
		t.Fatal("no scriptlet reloads systemd; either the packaging changed shape or this guard stopped reading it")
	}
	t.Logf("%d scriptlets reload systemd and restart the helper socket", checked)
}
