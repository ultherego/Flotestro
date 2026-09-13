package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Plan describes the difference between the sshd configuration the host
// applies and the requested one.
//
// The same change ordered on two hosts is almost never the same change: one
// already has PasswordAuthentication no, another has it in an administrator
// file that shadows the panel's file, a third would have no login method
// left after the change. The operator's approval is meant to cover those
// differences.
type Plan struct {
	// Action names what would happen: update or no_change.
	Action string `json:"action"`

	// Current carries the values the server applies for the settings in the
	// order; Desired - the order.
	Current map[string]string `json:"current,omitempty"`
	Desired Settings          `json:"desired"`
	// Changes lists in human terms what will change.
	Changes []string `json:"changes,omitempty"`

	// ManagedPresent and ManagedHash describe the panel's file on the host:
	// the write overwrites it whole, so a file changed after planning is a
	// different change than the one viewed.
	ManagedPresent bool   `json:"managed_present"`
	ManagedHash    string `json:"managed_hash,omitempty"`

	// Refusal names the reason the change will not land on this host: no
	// sshd, a configuration the server will not accept, or cutting off all
	// login methods without explicit consent.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanUpdate   = "update"
	PlanNoChange = "no_change"
)

// Compute computes the difference between the server state and the order.
func Compute(state Snapshot, desired Settings, allowLockout bool) Plan {
	plan := Plan{Desired: desired, ManagedPresent: state.ManagedPresent}
	if state.ManagedPresent {
		plan.ManagedHash = textFingerprint(state.Managed)
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	content, err := ComposeDropIn(desired)
	if err != nil {
		return plan.withRefusal(err.Error())
	}
	if !allowLockout && CutsOffAllMethods(desired, state) {
		return plan.withRefusal("after this change no working authentication method would remain; " +
			"a deliberate lockout requires the operator's explicit consent")
	}

	plan.Current = map[string]string{}
	compare := func(name, wanted, current string) {
		if wanted == "" {
			return
		}
		plan.Current[name] = current
		if !strings.EqualFold(wanted, current) {
			plan.Changes = append(plan.Changes, fmt.Sprintf("%s from %s to %s",
				name, orNone(current), wanted))
		}
	}
	compare("PermitRootLogin", desired.PermitRootLogin, state.PermitRootLogin)
	compare("PasswordAuthentication", desired.PasswordAuthentication, state.PasswordAuthentication)
	compare("PubkeyAuthentication", desired.PubkeyAuthentication, state.PubkeyAuthentication)
	compare("KbdInteractiveAuthentication", desired.KbdInteractive, state.KbdInteractive)
	if desired.MaxAuthTries != "" {
		compare("MaxAuthTries", desired.MaxAuthTries, strconv.Itoa(state.MaxAuthTries))
	}
	if desired.Port != "" {
		current := ""
		if len(state.Ports) > 0 {
			current = state.Ports[0]
		}
		compare("Port", desired.Port, current)
	}
	compareList := func(name string, wanted, current []string) {
		if len(wanted) == 0 {
			return
		}
		plan.Current[name] = strings.Join(current, " ")
		if !sameSet(wanted, current) {
			plan.Changes = append(plan.Changes, fmt.Sprintf("%s from %s to %s",
				name, orNone(strings.Join(current, " ")), strings.Join(wanted, " ")))
		}
	}
	compareList("AllowUsers", desired.AllowUsers, state.AllowUsers)
	compareList("AllowGroups", desired.AllowGroups, state.AllowGroups)
	compareList("DenyUsers", desired.DenyUsers, state.DenyUsers)

	// The panel's file is overwritten whole: different content is a change
	// even when the server already applies the requested values - because
	// after the write it applies them for a different reason, and the
	// settings from the previous file vanish.
	switch {
	case !state.ManagedPresent:
		plan.Changes = append(plan.Changes, "the panel's file will be created")
	case state.Managed != content:
		plan.Changes = append(plan.Changes, "the panel's file will be overwritten")
	}

	plan.Action = PlanUpdate
	if len(plan.Changes) == 0 {
		plan.Action = PlanNoChange
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// Refuse records a refusal reason learned after the differences were
// computed and recomputes the fingerprint: a plan with a refusal is a
// different answer than a plan without one.
func (p *Plan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = planFingerprint(*p)
}

func (p Plan) withRefusal(reason string) Plan {
	p.Refusal = reason
	p.PlanHash = planFingerprint(p)
	return p
}

// DescribesChange says whether the settings carry anything to write.
func (s Settings) DescribesChange() bool {
	return s.Port != "" || s.PermitRootLogin != "" || s.PasswordAuthentication != "" ||
		s.PubkeyAuthentication != "" || s.KbdInteractive != "" || s.MaxAuthTries != "" ||
		len(s.AllowUsers) > 0 || len(s.AllowGroups) > 0 || len(s.DenyUsers) > 0
}

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func textFingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// planFingerprint computes the plan fingerprint excluding the fingerprint
// itself. It covers the state found together with the requested one: a host
// changed since planning yields a different fingerprint.
func planFingerprint(plan Plan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
