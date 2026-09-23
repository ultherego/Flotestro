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

	forged := *honest
	forged.Content = []byte("flotestro-agent ALL=(ALL) NOPASSWD: ALL\n")
	if err := sameFile(&forged, approved); err == nil {
		t.Error("other content at the approved path was accepted")
	}
	widened := *honest
	widened.Mode = "0666"
	if err := sameFile(&widened, approved); err == nil {
		t.Error("another mode at the approved path was accepted")
	}
	handedOver := *honest
	handedOver.Owner = "flotestro-agent"
	if err := sameFile(&handedOver, approved); err == nil {
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

	substituted := *honest
	substituted.SshKeys = []string{"ssh-ed25519 AAAAC3NzaC1 attacker"}
	if err := sameAccount(&substituted, approved); err == nil {
		t.Error("another key on the approved account was accepted")
	}
	widened := *honest
	widened.Groups = []string{"wheel", "sudo"}
	if err := sameAccount(&widened, approved); err == nil {
		t.Error("another group list on the approved account was accepted")
	}
	shell := *honest
	shell.Shell = "/bin/sh"
	if err := sameAccount(&shell, approved); err == nil {
		t.Error("another shell on the approved account was accepted")
	}
}
