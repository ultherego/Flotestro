package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/sudoers"
	"github.com/ultherego/flotestro/internal/modules/system"
)

// systemProbe reads the DMI facts that belong to root through the helper.
// Without it the picture is still built, with the serial number and the
// UUID named as refused.
var systemProbe func(context.Context) (system.Supplement, error)

// SetSystemProbe points at the function that reads the privileged part of
// the platform picture.
func SetSystemProbe(probe func(context.Context) (system.Supplement, error)) {
	systemProbe = probe
}

// sudoersProbe reads the local sudo policy through the helper. The files
// are root's; the agent does not open them.
var sudoersProbe func(context.Context) (sudoers.Snapshot, error)

// SetSudoersProbe points at the function that reads the sudo policy.
func SetSudoersProbe(probe func(context.Context) (sudoers.Snapshot, error)) {
	sudoersProbe = probe
}

// CollectSystem reads the platform picture of the host.
//
// First what can be seen without root: the processor, the memory, the
// kernel, the distribution, the firmware and the public DMI fields. Only
// what the kernel refused - the serial numbers and the UUID - is ordered
// from the helper, and only when it was refused: a container without DMI
// tables has nothing for root to read either.
func CollectSystem(ctx context.Context) system.Snapshot {
	snapshot := system.Collect(os.DirFS("/"), time.Now())
	if !refusedToAgent(snapshot) || systemProbe == nil {
		return snapshot
	}
	supplement, err := systemProbe(ctx)
	if err != nil {
		// A missing helper does not invalidate what is already known: the
		// refused facts stay missing, and the reason now names the helper.
		for _, fact := range []string{system.FactDMISerial, system.FactDMIUUID} {
			if _, missing := snapshot.Missing[fact]; missing {
				snapshot.Missing[fact] = "helper: " + err.Error()
			}
		}
		return snapshot
	}
	return snapshot.Supplemented(supplement)
}

// refusedToAgent says whether a DMI fact is missing because the read was
// refused to the unprivileged agent - the one case root can mend.
func refusedToAgent(snapshot system.Snapshot) bool {
	for _, fact := range []string{system.FactDMISerial, system.FactDMIUUID} {
		if reason, missing := snapshot.Missing[fact]; missing && strings.Contains(reason, "permission denied") {
			return true
		}
	}
	return false
}

// CollectSudoers reads the local sudo policy through the helper. A host
// without a helper reports the policy as not read, with the reason: the
// panel must not take silence for "nobody has sudo here".
func CollectSudoers(ctx context.Context) sudoers.Snapshot {
	if sudoersProbe == nil {
		return sudoers.Snapshot{
			Rules: []sudoers.Rule{}, Defaults: []sudoers.Default{}, Files: []sudoers.File{},
			UnavailableReason: "the agent has no helper to read the sudo policy with",
			ObservedAt:        time.Now().UTC(),
		}
	}
	snapshot, err := sudoersProbe(ctx)
	if err != nil {
		return sudoers.Snapshot{
			Rules: []sudoers.Rule{}, Defaults: []sudoers.Default{}, Files: []sudoers.File{},
			UnavailableReason: "helper: " + err.Error(),
			ObservedAt:        time.Now().UTC(),
		}
	}
	return snapshot
}

// ProbeSystem asks the helper for the DMI identity of the machine.
func (e *TaskExecutor) ProbeSystem(ctx context.Context) (system.Supplement, error) {
	response, err := e.callSystem(ctx, helperv1.SystemRequest_FACT_DMI_IDENTITY)
	if err != nil {
		return system.Supplement{}, err
	}
	var supplement system.Supplement
	if data := response.GetDmi(); len(data) > 0 {
		if err := json.Unmarshal(data, &supplement); err != nil {
			return system.Supplement{}, err
		}
	}
	return supplement, nil
}

// ProbeSudoers asks the helper for the local sudo policy.
func (e *TaskExecutor) ProbeSudoers(ctx context.Context) (sudoers.Snapshot, error) {
	response, err := e.callSystem(ctx, helperv1.SystemRequest_FACT_SUDOERS)
	if err != nil {
		return sudoers.Snapshot{}, err
	}
	var snapshot sudoers.Snapshot
	data := response.GetSudoers()
	if len(data) == 0 {
		return sudoers.Snapshot{}, errors.New("the helper answered without the sudo policy")
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return sudoers.Snapshot{}, err
	}
	return snapshot, nil
}

// callSystem orders one fact of the system module from the helper and
// returns its result, or the refusal as an error.
func (e *TaskExecutor) callSystem(ctx context.Context, fact helperv1.SystemRequest_Fact) (*helperv1.SystemResult, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_System{
			System: &helperv1.SystemRequest{Facts: []helperv1.SystemRequest_Fact{fact}},
		},
	}, time.Minute)
	if err != nil {
		return nil, err
	}
	if !response.GetAccepted() {
		return nil, errors.New(response.GetMessage())
	}
	return response.GetSystemResult(), nil
}
