package agent

import (
	"context"
	"encoding/json"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// listPackages reads the full list of the installed packages.
//
// Without root and without the helper: the dpkg database and the RPM database
// are readable by everyone, and every trip through root has to be justified.
// The list is big, so it travels on request from the panel - the inventory
// keeps only the digest and the number of packages.
func (e *TaskExecutor) listPackages(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	manager := hostManager(readCtx)
	list := packages.Installed(readCtx, manager)
	encoded, err := json.Marshal(list.Packages)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	// The vendor findings are read on the same occasion: for dnf they lie in the
	// repository metadata the host has anyway. They are facts about packages,
	// exactly like the list itself - the judgement is made in the panel.
	advisories, advisoriesReason := packages.Advisories(readCtx, manager, list.Packages)
	encodedAdvisories, err := json.Marshal(advisories)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}

	// A list that was not read must not look like a host without packages: it is
	// the answer "not known", and nothing about vulnerabilities may be said on
	// its basis.
	message := "read " + itoa(list.Count) + " packages, " +
		itoa(len(advisories)) + " vendor findings"
	if list.UnavailableReason != "" {
		message = "the package list was not read: " + list.UnavailableReason
	}
	return &agentv1.TaskResult{
		TaskId:  task.GetTaskId(),
		Status:  agentv1.TaskResult_STATUS_SUCCEEDED,
		Message: message,
		InstalledPackagesResult: &agentv1.InstalledPackagesResult{
			Packages:                    encoded,
			Digest:                      list.Digest,
			Count:                       uint32(list.Count),
			Manager:                     list.Manager,
			UnavailableReason:           list.UnavailableReason,
			Advisories:                  encodedAdvisories,
			AdvisoriesUnavailableReason: advisoriesReason,
		},
	}
}

// hostManager returns the name of the package manager of the host or an empty
// string.
func hostManager(ctx context.Context) string {
	manager, err := packages.Detect()
	if err != nil {
		return ""
	}
	_ = ctx
	return manager.Name()
}

// itoa is a short rendering of a number in a message.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// packageDigest computes the fingerprint of the package list for the inventory.
func packageDigest(ctx context.Context, manager string) (string, int, string) {
	if manager == "" {
		return "", 0, "this host has no supported package manager"
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	list := packages.Installed(readCtx, manager)
	return list.Digest, list.Count, list.UnavailableReason
}
