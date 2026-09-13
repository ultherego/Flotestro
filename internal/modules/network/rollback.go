package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RollbackDir holds the rollback plans of network changes.
//
// The directory belongs to root and only root has access to it. A plan
// contains no commands to run, only profile settings - the arguments are
// assembled from them by the same code that assembles them at write time. A
// file that could steer the execution would be a door to root even for a
// root that made a mistake.
const RollbackDir = "/var/lib/flotestro-helper/rollbacks"

// RollbackPlan describes the state the host returns to when a network
// change cuts it off from the panel.
//
// The rollback is armed before the change and disarmed only after the agent
// confirms it still talks to the panel. The reverse order would leave a
// window in which the host is already cut off and nothing rescues it.
type RollbackPlan struct {
	ID string `json:"id"`
	// Profile is the state before the change, read from NetworkManager.
	Profile Profile `json:"profile"`
	// Interface and Management say what the change concerned. A change of
	// the management interface is the case all of this exists for.
	Interface  string    `json:"interface"`
	Management bool      `json:"management"`
	CreatedAt  time.Time `json:"created_at"`
	// Deadline is the moment after which the rollback is to run.
	Deadline time.Time `json:"deadline"`
	Reason   string    `json:"reason,omitempty"`
}

// PlanPath returns the plan file with the given identifier.
func PlanPath(dir, id string) (string, error) {
	if !ValidPlanID(id) {
		return "", fmt.Errorf("invalid plan identifier %q", id)
	}
	return filepath.Join(dir, id+".json"), nil
}

// ValidPlanID allows only characters that cannot lead the path outside
// the plans directory.
func ValidPlanID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// SavePlan writes a rollback plan.
func SavePlan(dir string, plan RollbackPlan) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path, err := PlanPath(dir, plan.ID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	// Atomic write: a plan read half-way is a plan that restores nothing,
	// and that is exactly when it is needed.
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// LoadPlan reads a rollback plan.
func LoadPlan(dir, id string) (RollbackPlan, error) {
	path, err := PlanPath(dir, id)
	if err != nil {
		return RollbackPlan{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return RollbackPlan{}, err
	}
	var plan RollbackPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return RollbackPlan{}, err
	}
	return plan, nil
}

// SetAsideFailedPlan sets aside a plan whose rollback failed.
//
// A plan whose clock has already struck is dead regardless of the result:
// nobody runs it again. Left in the plans directory it would look like a
// rollback still waiting for its moment, so it is set aside next to it - as
// a trace of what the host could not restore.
func SetAsideFailedPlan(dir, id string) error {
	path, err := PlanPath(dir, id)
	if err != nil {
		return err
	}
	return os.Rename(path, path+".failed")
}

// RemovePlan deletes a rollback plan.
func RemovePlan(dir, id string) error {
	path, err := PlanPath(dir, id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RollbackSteps assembles the commands restoring the state before the
// change.
//
// The arguments are made from the profile settings by the same code that
// assembles them at write time: the plan cannot express a command this
// module does not know.
func RollbackSteps(plan RollbackPlan) ([][]string, error) {
	profile := plan.Profile
	if profile.Connection == "" {
		return nil, fmt.Errorf("rollback plan without a connection profile")
	}
	// The profile before the change may be empty in fields NetworkManager
	// did not have set - and exactly that is meant to return.
	if profile.Method == "" {
		profile.Method = "auto"
	}
	if profile.Method == "manual" && len(profile.Addresses) == 0 {
		return nil, fmt.Errorf("rollback plan with the manual method but no addresses")
	}
	return ProfileArguments(profile)
}

// RollbackUnitName returns the name of the transient systemd unit that runs
// the rollback. One unit per plan: a second change must not silently take
// over the clock of the first.
func RollbackUnitName(id string) string {
	return "flotestro-rollback-" + id
}
