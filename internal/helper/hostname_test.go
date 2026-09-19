package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

func hostnameRequest(name, pretty string) *helperv1.HelperRequest {
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-rename",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		Action: &helperv1.HelperRequest_Hostname{
			Hostname: &helperv1.HostnameRequest{Hostname: name, Pretty: pretty},
		},
	}
}

// The rename sets the static and the transient name in one call and the pretty
// name only when the order carries one.
func TestRenameSetsTheNameAndFollowsInHostsFile(t *testing.T) {
	previous := staticHostname()
	if previous == "" {
		t.Skip("the host running the tests has no name")
	}
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	content := "127.0.0.1\tlocalhost\n127.0.1.1\t" + previous + "\n"
	if err := os.WriteFile(hosts, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	tool := &fakeAccountTool{}
	server := testServer()
	server.accountTool = tool.run
	server.hostsFile = hosts

	response := server.handle(context.Background(), hostnameRequest("renamed-host", "Renamed Host"), nil)
	if !response.GetAccepted() {
		t.Fatalf("the rename was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	if len(tool.calls) != 2 ||
		joinedCall(tool.calls[0]) != "hostnamectl set-hostname --static --transient renamed-host" ||
		joinedCall(tool.calls[1]) != "hostnamectl set-hostname --pretty Renamed Host" {
		t.Fatalf("calls = %v", tool.calls)
	}
	result := response.GetHostnameResult()
	if result.GetPrevious() != previous || result.GetCurrent() != "renamed-host" || !result.GetChanged() {
		t.Fatalf("result = %+v", result)
	}
	if !result.GetHostsFileUpdated() {
		t.Fatal("the hosts file named the old hostname and was not updated")
	}
	rewritten, _ := os.ReadFile(hosts)
	if !strings.Contains(string(rewritten), "127.0.1.1\trenamed-host\n") || strings.Contains(string(rewritten), previous) {
		t.Fatalf("hosts file:\n%s", rewritten)
	}
	backup, err := os.ReadFile(hosts + ".flotestro-before")
	if err != nil || string(backup) != content {
		t.Fatalf("the backup is missing or different: %q (%v)", backup, err)
	}
}

// A name the host would refuse, or would change, never reaches the tool.
func TestRenameRefusesABadName(t *testing.T) {
	tool := &fakeAccountTool{}
	server := testServer()
	server.accountTool = tool.run
	server.hostsFile = filepath.Join(t.TempDir(), "hosts")
	for _, name := range []string{"", "Web01", "web 01", "web01;reboot", "localhost"} {
		response := server.handle(context.Background(), hostnameRequest(name, ""), nil)
		if response.GetAccepted() || response.GetErrorCode() != ErrorMalformed {
			t.Errorf("%q: accepted=%v code=%q", name, response.GetAccepted(), response.GetErrorCode())
		}
	}
	if len(tool.calls) != 0 {
		t.Fatalf("hostnamectl ran: %v", tool.calls)
	}
}

// The hosts file is rewritten atomically and only when it names the old
// hostname; a file that is a link is left alone and reported.
func TestRewriteHostsFile(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	backup := hosts + ".before"
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	updated, err := rewriteHostsFile(hosts, backup, "old", "new")
	if err != nil || updated {
		t.Fatalf("a file without the name: updated=%v err=%v", updated, err)
	}
	if _, err := os.Stat(backup); err == nil {
		t.Fatal("a backup was written without a change")
	}
	if _, err := os.Stat(hosts + ".flotestro-tmp"); err == nil {
		t.Fatal("the temporary file was left behind")
	}

	link := filepath.Join(dir, "linked")
	if err := os.Symlink(hosts, link); err != nil {
		t.Fatal(err)
	}
	if _, err := rewriteHostsFile(link, link+".before", "localhost", "new"); err == nil {
		t.Fatal("a linked hosts file was rewritten")
	}

	if _, err := rewriteHostsFile(filepath.Join(dir, "missing"), backup, "old", "new"); err != nil {
		t.Fatalf("a missing file is nothing to rewrite: %v", err)
	}
}
