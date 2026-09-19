package agent

import (
	"context"
	"strings"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// stubManager stands in for the package adapter of the host: a replacement has
// to be decided the same way whichever manager answers, and a unit test must
// not depend on the one the machine running it happens to have.
type stubManager struct{ name string }

func (s stubManager) Name() string             { return s.name }
func (s stubManager) Available() bool          { return true }
func (s stubManager) LockHeld() (bool, string) { return false, "" }

func (s stubManager) DatabaseBroken(context.Context) bool { return false }

func (s stubManager) Plan(context.Context, packages.Options) (packages.Plan, error) {
	return packages.Plan{}, nil
}

func (s stubManager) Refresh(context.Context) error { return nil }

func (s stubManager) Upgrade(context.Context, packages.Options) (packages.Apply, error) {
	return packages.Apply{}, nil
}

// withStubbedHost points the host reads of a replacement at a fixed manager
// and a fixed package database for the length of one test.
func withStubbedHost(t *testing.T, manager string, installed packages.InstalledList) {
	t.Helper()
	previousDetect, previousInstalled := detectManager, readInstalledPackages
	detectManager = func() (packages.Manager, error) { return stubManager{name: manager}, nil }
	readInstalledPackages = func(context.Context, string) packages.InstalledList { return installed }
	t.Cleanup(func() {
		detectManager, readInstalledPackages = previousDetect, previousInstalled
	})
}

// agentDatabase is a package database holding the agent at one version.
func agentDatabase(version string) packages.InstalledList {
	return packages.InstalledList{
		Manager:  "apt",
		Packages: []packages.InstalledPackage{{Name: packages.AgentPackage, Version: version}},
	}
}

// upgradeEnvelope is an order to replace the agent.
func upgradeEnvelope(payload *opspec.AgentUpgradePayload) *agentv1.TaskEnvelope {
	return &agentv1.TaskEnvelope{
		TaskId: "task-upgrade",
		Limits: &agentv1.Limits{TimeoutSeconds: 30},
		Action: &agentv1.TaskEnvelope_AgentUpgrade{
			AgentUpgrade: &agentv1.AgentUpgrade{TargetVersion: payload.TargetVersion},
		},
	}
}

// A refresh the helper did not accept is the refusal of the whole upgrade.
func TestARefusedMetadataRefreshRefusesTheUpgradeAndInstallsNothing(t *testing.T) {
	withStubbedHost(t, "apt", agentDatabase("0.54.0"))

	var installs int
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		action := request.GetPackageAction()
		if action.GetOperation() == helperv1.PackageActionRequest_OPERATION_REFRESH {
			return &helperv1.HelperResponse{
				Accepted: false, ErrorCode: packages.ErrorTransaction,
				Message: "the repository did not answer",
			}
		}
		installs++
		return &helperv1.HelperResponse{Accepted: true}
	})

	executor := &TaskExecutor{helper: client}
	payload := &opspec.AgentUpgradePayload{TargetVersion: "0.55.0"}
	result := executor.upgradeAgent(context.Background(), upgradeEnvelope(payload), payload)

	if result.GetErrorCode() != RejectMetadataStale {
		t.Fatalf("error code = %q (%s), expected %s",
			result.GetErrorCode(), result.GetMessage(), RejectMetadataStale)
	}
	if result.GetStatus() != agentv1.TaskResult_STATUS_REJECTED {
		t.Errorf("status = %s, expected rejected: nothing was changed on the host", result.GetStatus())
	}
	if installs != 0 {
		t.Errorf("the helper was asked to install %d times after a refused refresh", installs)
	}
	if !strings.Contains(result.GetMessage(), packages.ErrorTransaction) {
		t.Errorf("the message %q does not carry the helper's own reason", result.GetMessage())
	}
}

// An artefact that is not the one the release published stops the upgrade
// before the package manager is allowed near the database.
func TestAnArtefactDigestThatDoesNotMatchRefusesAndChangesNothing(t *testing.T) {
	withStubbedHost(t, "apt", agentDatabase("0.54.0"))

	var started int
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		action := request.GetPackageAction()
		if action.GetOperation() == helperv1.PackageActionRequest_OPERATION_REFRESH {
			return &helperv1.HelperResponse{Accepted: true}
		}
		if action.GetPackageSha256() == "" {
			t.Errorf("the install order carries no digest, so the helper could not check the artefact")
		}
		started++
		return &helperv1.HelperResponse{
			Accepted: false, ErrorCode: helper.ErrorArtefactDigest,
			Message: "the order names 9f... and the host obtained 11...",
		}
	})

	executor := &TaskExecutor{helper: client}
	payload := &opspec.AgentUpgradePayload{
		TargetVersion: "0.55.0",
		PackageSHA256: strings.Repeat("9f", 32),
	}
	result := executor.upgradeAgent(context.Background(), upgradeEnvelope(payload), payload)

	if result.GetErrorCode() != helper.ErrorArtefactDigest {
		t.Fatalf("error code = %q (%s), expected %s",
			result.GetErrorCode(), result.GetMessage(), helper.ErrorArtefactDigest)
	}
	// A rejection rather than a failure: the host was not touched, so the
	// operator corrects the release and orders again, and a campaign is not told
	// the host broke.
	if result.GetStatus() != agentv1.TaskResult_STATUS_REJECTED {
		t.Errorf("status = %s, expected rejected", result.GetStatus())
	}
	if started != 1 {
		t.Errorf("the helper was asked %d times, expected exactly one order", started)
	}
}

// A host already at the ordered version still has the order proven.
func TestAnOrderForTheRunningVersionIsProvenWithoutInstallingAnything(t *testing.T) {
	previousVersion := Version
	Version = "0.54.0"
	t.Cleanup(func() { Version = previousVersion })
	withStubbedHost(t, "apt", agentDatabase("0.54.0-1"))

	var verifyOnly, transactions int
	_, client := startFakeHelper(t, func(request *helperv1.HelperRequest) *helperv1.HelperResponse {
		action := request.GetPackageAction()
		if action.GetOperation() == helperv1.PackageActionRequest_OPERATION_REFRESH {
			return &helperv1.HelperResponse{Accepted: true}
		}
		if action.GetVerifyOnly() {
			verifyOnly++
			return &helperv1.HelperResponse{
				Accepted: true,
				PackageResult: &helperv1.PackageActionResult{
					Manager:              "apt",
					VerifiedArtefactPath: "/var/lib/flotestro-helper/agent-upgrade/download/agent.deb",
					RollbackArtefactPath: "/var/lib/flotestro-helper/agent-upgrade/rollback/agent.deb",
				},
			}
		}
		transactions++
		return &helperv1.HelperResponse{Accepted: true}
	})

	executor := &TaskExecutor{helper: client}
	payload := &opspec.AgentUpgradePayload{
		TargetVersion:   "0.54.0",
		PackageSHA256:   strings.Repeat("ab", 32),
		RollbackVersion: "0.53.0",
	}
	result := executor.upgradeAgent(context.Background(), upgradeEnvelope(payload), payload)

	if result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("status = %s (%s), expected succeeded", result.GetStatus(), result.GetMessage())
	}
	if verifyOnly != 1 || transactions != 0 {
		t.Fatalf("verify-only orders = %d, transactions = %d, expected 1 and 0", verifyOnly, transactions)
	}
	// The result says where the way back waits: a prepared return nobody can
	// find is no return at all.
	if !strings.Contains(result.GetMessage(), "rollback/agent.deb") {
		t.Errorf("the message %q does not say where the artefact to go back to is kept", result.GetMessage())
	}
	// The version is the one the package database holds, not the one that
	// was ordered.
	if !strings.Contains(result.GetMessage(), "0.54.0-1") {
		t.Errorf("the message %q does not name the installed version from the package database",
			result.GetMessage())
	}
}

// The order the helper receives carries the fields the panel approved: the
// digest to check the artefact against and the version to keep a way back to.
func TestTheReplacementOrderCarriesTheDigestAndTheRollbackVersion(t *testing.T) {
	payload := &opspec.AgentUpgradePayload{
		TargetVersion:   "0.55.0",
		PackageSHA256:   strings.Repeat("3c", 32),
		RollbackVersion: "0.54.0",
	}
	request := replacementRequest(upgradeEnvelope(payload), "flotestro-agent=0.55.0", payload, 0, false)
	action := request.GetPackageAction()
	if action.GetPackageSha256() != payload.PackageSHA256 {
		t.Errorf("the order carries the digest %q, expected %q",
			action.GetPackageSha256(), payload.PackageSHA256)
	}
	if action.GetRollbackVersion() != payload.RollbackVersion {
		t.Errorf("the order carries the rollback version %q, expected %q",
			action.GetRollbackVersion(), payload.RollbackVersion)
	}
	if action.GetVerifyOnly() {
		t.Error("a replacement order asks to verify only")
	}
	if !action.GetAllowDowngrade() {
		t.Error("the order does not allow a downgrade, so a return to an older release would be refused")
	}
}

// The package database writes a version with the epoch its manager keeps and
// the packaging revision its distribution appends.
func TestTheInstalledVersionIsTheOrderedReleaseWhateverThePackagingAddsToIt(t *testing.T) {
	cases := []struct {
		installed, target string
		same              bool
	}{
		{"0.54.0", "0.54.0", true},
		{"0.54.0-1", "0.54.0", true},
		{"1:0.54.0-2.el9", "0.54.0", true},
		{"0.54.1", "0.54.0", false},
		{"0.54.0rc1", "0.54.0", false},
		{"0.5", "0.54.0", false},
	}
	for _, tc := range cases {
		if got := versionIs(tc.installed, tc.target); got != tc.same {
			t.Errorf("versionIs(%q, %q) = %v, expected %v",
				tc.installed, tc.target, got, tc.same)
		}
	}
}

// An unreadable package database is not a host without the agent package.
// The result says the version is unknown and why, instead of leaving it out.
func TestAnUnreadablePackageDatabaseGivesNoVersionAndAReason(t *testing.T) {
	withStubbedHost(t, "apt", packages.InstalledList{
		Manager: "apt", UnavailableReason: "dpkg-query did not run",
	})
	version, reason := installedAgentVersion(context.Background(), "apt")
	if version != "" || reason == "" {
		t.Fatalf("version = %q, reason = %q, expected no version and a reason", version, reason)
	}
	if described := describeInstalled(version, reason); !strings.Contains(described, "unknown") {
		t.Errorf("the description %q does not say the version is unknown", described)
	}
}
