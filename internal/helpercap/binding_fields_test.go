package helpercap

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A capability names one operation on one target, and used to say nothing
// about what that operation would do there: a file capability for a path
// authorised any content at that path, and an account capability for a name
// authorised any key on that account. Both are grants of root by another name.
func TestTheCapabilityBindsWhatAFileOrderWouldWriteAndNotOnlyWhere(t *testing.T) {
	approved := &opspec.FilePayload{
		Path: "/etc/sudoers.d/ops", Content: "%ops ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n",
		Mode: "0440", Owner: "root", Group: "root",
	}
	honest := &helperv1.FileRequest{
		Path: approved.Path, Content: []byte(approved.Content),
		Mode: approved.Mode, Owner: approved.Owner, Group: approved.Group,
	}
	if err := sameFile(honest, approved); err != nil {
		t.Fatalf("the request the panel approved was refused: %v", err)
	}

	// Each substitution is built fresh: a protobuf message is not copied.
	fileWith := func(change func(*helperv1.FileRequest)) *helperv1.FileRequest {
		request := &helperv1.FileRequest{
			Path: approved.Path, Content: []byte(approved.Content),
			Mode: approved.Mode, Owner: approved.Owner, Group: approved.Group,
		}
		change(request)
		return request
	}
	forged := fileWith(func(r *helperv1.FileRequest) {
		r.Content = []byte("flotestro-agent ALL=(ALL) NOPASSWD: ALL\n")
	})
	if err := sameFile(forged, approved); err == nil {
		t.Error("other content at the approved path was accepted")
	}
	if err := sameFile(fileWith(func(r *helperv1.FileRequest) { r.Mode = "0666" }), approved); err == nil {
		t.Error("another mode at the approved path was accepted")
	}
	if err := sameFile(fileWith(func(r *helperv1.FileRequest) { r.Owner = "flotestro-agent" }), approved); err == nil {
		t.Error("another owner at the approved path was accepted")
	}
}

// The panel does not hold the bytes in two cases, and each is bound by the
// name they travel under instead of by a digest of nothing.
func TestContentThePanelDoesNotHoldIsBoundByItsName(t *testing.T) {
	secret := &opspec.FilePayload{Path: "/etc/app.conf",
		ContentSecret: &opspec.SecretRef{Name: "app.conf", Version: 3}}
	fromStore := &helperv1.FileRequest{Path: secret.Path, FromSecret: true,
		Content: []byte("whatever the store answered")}
	if err := sameContent(fromStore, secret); err != nil {
		t.Errorf("a file filled from the secret store was refused: %v", err)
	}
	// A request that carries its own content where the order named a secret is
	// the agent putting words in the panel's mouth.
	ownContent := &helperv1.FileRequest{Path: secret.Path, Content: []byte("mine")}
	if err := sameContent(ownContent, secret); err == nil {
		t.Error("content of the agent's own was accepted where a secret was ordered")
	}

	back := &opspec.FilePayload{Path: "/etc/app.conf", VersionSHA256: "abc123"}
	toVersion := &helperv1.FileRequest{Path: back.Path, VersionSha256: "abc123"}
	if err := sameContent(toVersion, back); err != nil {
		t.Errorf("a return to a kept version was refused: %v", err)
	}
	other := &helperv1.FileRequest{Path: back.Path, VersionSha256: "def456"}
	if err := sameContent(other, back); err == nil {
		t.Error("a return to another version was accepted")
	}
}

// The same for an account: the name was bound and the keys were not, so a
// capability to add a key to root authorised adding anybody's key.
func TestTheCapabilityBindsTheKeysAndNotOnlyTheAccount(t *testing.T) {
	approved := &opspec.LocalUserPayload{
		Name: "root", SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1 operator"},
		Groups: []string{"wheel"}, Shell: "/bin/bash",
	}
	honest := &helperv1.LocalUserActionRequest{
		Name: approved.Name, SshKeys: approved.SSHKeys,
		Groups: approved.Groups, Shell: approved.Shell,
	}
	if err := sameAccount(honest, approved); err != nil {
		t.Fatalf("the request the panel approved was refused: %v", err)
	}

	accountWith := func(change func(*helperv1.LocalUserActionRequest)) *helperv1.LocalUserActionRequest {
		request := &helperv1.LocalUserActionRequest{
			Name: approved.Name, SshKeys: approved.SSHKeys,
			Groups: approved.Groups, Shell: approved.Shell,
		}
		change(request)
		return request
	}
	substituted := accountWith(func(r *helperv1.LocalUserActionRequest) {
		r.SshKeys = []string{"ssh-ed25519 AAAAC3NzaC1 attacker"}
	})
	if err := sameAccount(substituted, approved); err == nil {
		t.Error("another key on the approved account was accepted")
	}
	widened := accountWith(func(r *helperv1.LocalUserActionRequest) {
		r.Groups = []string{"wheel", "sudo"}
	})
	if err := sameAccount(widened, approved); err == nil {
		t.Error("another group list on the approved account was accepted")
	}
	if err := sameAccount(accountWith(func(r *helperv1.LocalUserActionRequest) { r.Shell = "/bin/sh" }), approved); err == nil {
		t.Error("another shell on the approved account was accepted")
	}
}

// One capability for one process used to authorise signalling any process with
// any signal: the request carried the numbers and nothing compared them.
func TestTheCapabilityBindsWhichProcessAndWhichSignal(t *testing.T) {
	approved := &opspec.ProcessSignalPayload{PID: 4242, Signal: "TERM", ExpectedStart: 99}
	payload := opspec.Payload{ProcessSignal: approved}
	honest := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_ProcessSignal{
		ProcessSignal: &helperv1.ProcessSignalRequest{
			Pid: 4242, Signal: "TERM", ExpectedStartTicks: 99,
		},
	}}
	if err := CheckBinding(honest, &BoundPayload{Payload: payload}); err != nil {
		t.Fatalf("the request the panel approved was refused: %v", err)
	}
	for _, change := range []struct {
		name    string
		request *helperv1.ProcessSignalRequest
	}{
		{"another process", &helperv1.ProcessSignalRequest{Pid: 1, Signal: "TERM", ExpectedStartTicks: 99}},
		{"another signal", &helperv1.ProcessSignalRequest{Pid: 4242, Signal: "KILL", ExpectedStartTicks: 99}},
		{"another incarnation", &helperv1.ProcessSignalRequest{Pid: 4242, Signal: "TERM", ExpectedStartTicks: 7}},
	} {
		forged := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_ProcessSignal{
			ProcessSignal: change.request,
		}}
		if err := CheckBinding(forged, &BoundPayload{Payload: payload}); err == nil {
			t.Errorf("%s was accepted under the approved capability", change.name)
		}
	}
}

// The same for the host's own name, the declared objects, the repositories, the
// backup definitions and a certificate deployment: each names one thing, and
// the capability now says which.
func TestTheCapabilityBindsTheTargetOfTheRemainingOrders(t *testing.T) {
	cases := []struct {
		name    string
		payload opspec.Payload
		honest  *helperv1.HelperRequest
		forged  *helperv1.HelperRequest
	}{
		{
			name:    "hostname",
			payload: opspec.Payload{Hostname: &opspec.HostnamePayload{Hostname: "web-01"}},
			honest: &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Hostname{
				Hostname: &helperv1.HostnameRequest{Hostname: "web-01"}}},
			forged: &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Hostname{
				Hostname: &helperv1.HostnameRequest{Hostname: "db-01"}}},
		},
		{
			name:    "repository",
			payload: opspec.Payload{Repository: &opspec.RepositoryPayload{ID: "vendor", URL: "https://vendor.example/deb"}},
			honest: &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Repository{
				Repository: &helperv1.RepositoryRequest{Id: "vendor", Url: "https://vendor.example/deb"}}},
			forged: &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Repository{
				Repository: &helperv1.RepositoryRequest{Id: "vendor", Url: "https://elsewhere.example/deb"}}},
		},
		{
			name:    "backup definition",
			payload: opspec.Payload{Backup: &opspec.BackupPayload{ID: "nightly"}},
			honest: &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Backup{
				Backup: &helperv1.BackupRequest{Id: "nightly"}}},
			forged: &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Backup{
				Backup: &helperv1.BackupRequest{Id: "archive"}}},
		},
	}
	for _, test := range cases {
		bound := &BoundPayload{Payload: test.payload}
		if err := CheckBinding(test.honest, bound); err != nil {
			t.Errorf("%s: the approved request was refused: %v", test.name, err)
		}
		if err := CheckBinding(test.forged, bound); err == nil {
			t.Errorf("%s: another target was accepted under the approved capability", test.name)
		}
	}
}
