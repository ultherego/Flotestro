package helper

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/network"
)

// applyDNS changes the host resolver through the connection profile.
//
// It does not write to /etc/resolv.conf: a file owned by resolved or by
// NetworkManager gets overwritten at the next network event, so a write into it
// would be a change that disappears on its own - and without a trace.
//
// The change is armed with a rollback just like an address change: a host
// without a working resolver loses the directory, Kerberos and logins, so the
// effect of a mistake reaches further than one unresolved name.
func (s *Server) applyDNS(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DnsRequest) *helperv1.HelperResponse {
	planning := action.GetOperation() == helperv1.DnsRequest_OPERATION_PLAN
	if !planning && action.GetOperation() != helperv1.DnsRequest_OPERATION_APPLY {
		return reject(ErrorUnknownAction, "unknown resolver operation")
	}
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "another unit operation is in flight")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if !network.Exists(network.NmcliPath) {
		reason := "this host has no NetworkManager; the resolver is read-only here"
		if planning {
			// A missing write mechanism is an answer of the plan, not a read
			// error: the campaign is to see this host as a refusal.
			return resolverPlanResponse(nil,
				network.RefusedPlan(action.GetInterface(), network.PlanDNS, reason))
		}
		return reject(ErrorUnsupported, reason)
	}

	connection, profile, err := s.interfaceProfile(actionCtx, action.GetInterface())
	if err != nil {
		if planning {
			return resolverPlanResponse(s.readProfiles(actionCtx),
				network.RefusedPlan(action.GetInterface(), network.PlanDNS, err.Error()))
		}
		return reject(ErrorUnsupported, err.Error())
	}

	if planning {
		return resolverPlanResponse(s.readProfiles(actionCtx), resolverPlan(action, profile))
	}
	// A change approved on the basis of a plan is to enter the state the
	// operator looked at. A different digest means the profile changed since the
	// planning - and that is a refusal, not a warning.
	if expected := action.GetPlanHash(); expected != "" {
		if now := resolverPlan(action, profile); now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the profile "+connection+" changed since the planning; the change needs a new plan")
		}
	}

	steps, err := network.DNSArguments(connection, action.GetServers(),
		action.GetSearchDomains(), action.GetIgnoreAutoDns())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	plan := network.RollbackPlan{
		ID:        rollbackIdentifier(),
		Profile:   profile,
		Interface: action.GetInterface(),
		CreatedAt: time.Now().UTC(),
	}
	window := rollbackWindow(action.GetRollbackSeconds())
	plan.Deadline = plan.CreatedAt.Add(window)
	if _, err := network.RollbackSteps(plan); err != nil {
		return reject(ErrorUnsupported, "the rollback cannot be assembled: "+err.Error())
	}
	if err := network.SavePlan(network.RollbackDir, plan); err != nil {
		return reject(ErrorExecFailed, "writing the rollback plan: "+err.Error())
	}
	if err := s.armRollback(actionCtx, plan, window); err != nil {
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "arming the rollback: "+err.Error())
	}

	for _, step := range steps {
		if output, err := runNmcli(actionCtx, step); err != nil {
			response := reject(ErrorExecFailed, err.Error()+": "+output)
			response.DnsResult = &helperv1.DnsResult{
				Message:          output,
				RollbackId:       plan.ID,
				RollbackDeadline: plan.Deadline.Format(time.RFC3339),
			}
			return response
		}
	}

	profiles := s.readProfiles(actionCtx)
	encoded, err := encodeProfiles(profiles)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DnsResult: &helperv1.DnsResult{
			Profiles: encoded,
			Message: "the resolver was changed; rollback at " +
				plan.Deadline.Format(time.RFC3339) + " unless the agent confirms connectivity",
			RollbackId:       plan.ID,
			RollbackDeadline: plan.Deadline.Format(time.RFC3339),
		},
	}
}

// resolverPlan computes the plan of a resolver change against the profile
// found.
func resolverPlan(action *helperv1.DnsRequest, profile network.Profile) network.Plan {
	return network.ComputeDNS(action.GetInterface(), profile, action.GetServers(),
		action.GetSearchDomains(), action.GetIgnoreAutoDns())
}

func resolverPlanResponse(profiles []network.Profile, plan network.Plan) *helperv1.HelperResponse {
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	encoded, err := encodeProfiles(profiles)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == network.PlanNoChange:
		message = "the resolver of the profile " + plan.Connection + " is already in the desired state"
	default:
		message = "the resolver of the profile " + plan.Connection + ": " + strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DnsResult: &helperv1.DnsResult{
			Profiles: encoded, Message: message, Plan: encodedPlan,
		},
	}
}
