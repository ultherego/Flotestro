package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A service keytab rotation is one consent over two halves in two places: the
// directory retires the current keytab, and the fleet host fetches a new one.

var (
	// ErrHostNotInFleet means the host the principal names is not a host of the
	// panel: nobody could fetch the new keytab, so the old one must not be
	// retired.
	ErrHostNotInFleet = errors.New("the host the principal names is not a host of the fleet")
	// ErrHostOffline means the fleet host is not connected: the retirement would
	// leave the service without a keytab for as long as the host stays away.
	ErrHostOffline = errors.New("the host the principal names is not connected")
)

// FleetHost is what the rotation needs to know about the host that will
// fetch the new keytab.
type FleetHost struct {
	ID       string
	Hostname string
	OSFamily string
	Online   bool
}

// FleetLookup binds the name a principal carries to a host of the panel, so
// that the plan of a rotation and its execution name the same host.
type FleetLookup interface {
	// FleetHost resolves the FQDN of the principal to a host of the panel, or
	// ErrHostNotInFleet when no host carries the name and ErrFleetHostAmbiguous
	// when more than one does.
	FleetHost(ctx context.Context, fqdn string) (FleetHost, error)
}

// HostOrderer finds the fleet host of a principal and orders the host's half
// of the rotation on it.
type HostOrderer interface {
	FleetLookup
	// OrderKeytabRenewal creates the pre-approved renewal task on the host
	// and returns its identifier.
	OrderKeytabRenewal(ctx context.Context, host FleetHost, principal string, change Change) (string, error)
}

// FleetOrderer is the HostOrderer over the panel's own tables.
type FleetOrderer struct {
	hosts FleetLister
	jobs  *jobs.Store
	audit *audit.Recorder
}

func NewFleetOrderer(pool *pgxpool.Pool, recorder *audit.Recorder) *FleetOrderer {
	return &FleetOrderer{hosts: hosts.NewStore(pool), jobs: jobs.NewStore(pool), audit: recorder}
}

// FleetHost binds the FQDN the principal names to a fleet host through the
// resolution the view of the services uses, so that both name one identifier.
func (o *FleetOrderer) FleetHost(ctx context.Context, fqdn string) (FleetHost, error) {
	if o == nil || o.hosts == nil {
		return FleetHost{}, fmt.Errorf("this panel has no fleet store to order the renewal through")
	}
	host, err := LookupFleetHost(ctx, o.hosts, fqdn)
	if err != nil {
		return FleetHost{}, err
	}
	// The safeguard sits after the binding: a host on its way out of the fleet
	// cannot be given a task - the rotation would retire a keytab nobody renews -
	// and now it is refused as itself rather than as a name nobody carries.
	if host.LifecycleState != "" && host.LifecycleState != hosts.StateActive {
		return FleetHost{}, fmt.Errorf("%w: %s is %s, not active",
			ErrHostNotInFleet, host.Hostname, host.LifecycleState)
	}
	return FleetHost{ID: host.ID, Hostname: host.Hostname, OSFamily: host.OSFamily,
		Online: host.ConnectionState == "online"}, nil
}

// OrderKeytabRenewal creates the renewal task under the change's consent: the
// change was approved with fresh authentication, and the task carries that
// approval rather than asking for a second one.
func (o *FleetOrderer) OrderKeytabRenewal(ctx context.Context, host FleetHost, principal string,
	change Change) (string, error) {
	if o == nil || o.jobs == nil {
		return "", fmt.Errorf("this panel has no job store to order the renewal through")
	}
	tx, err := o.jobs.Pool().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	action := opspec.ActionIdentityKeytabRenew
	job, err := o.jobs.Create(ctx, tx, jobs.Spec{
		HostID:           host.ID,
		Action:           action,
		Payload:          opspec.Payload{Keytab: &opspec.KeytabPayload{Principal: principal}},
		IdempotencyKey:   "directory-change:" + change.ID + ":keytab-renew",
		RequiresApproval: false,
		TimeoutSeconds:   action.DefaultTimeout(),
		TTL:              time.Duration(action.DefaultTimeout()+600) * time.Second,
		CreatedBy:        "directory-change:" + change.ID,
		CreatedByKind:    jobs.ActorMachinery,
		RequestID:        change.RequestID,
		Preconditions: jobs.Preconditions{
			OSFamily:             host.OSFamily,
			RequiredCapabilities: []string{action.RequiredCapability()},
		},
	})
	if err != nil {
		return "", err
	}
	if o.audit != nil {
		if err := o.audit.RecordTx(ctx, tx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: "directory-change:" + change.ID,
			Action: "job.create", TargetType: "job", TargetID: job.ID,
			RequestID: change.RequestID, Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"directory_change_id": change.ID, "host_id": host.ID,
				"action_type": string(action), "principal": principal,
				"approved_by": change.ApprovedBy, "created_by": change.CreatedBy,
			},
		}); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return job.ID, nil
}

// planKeytabRotate describes the rotation before anything happens: which
// principal, which host, and the gap in between.
func (p *Planner) planKeytabRotate(ctx context.Context, spec *KeytabPayload) (Plan, error) {
	host := spec.Host()
	plan := Plan{
		Summary: fmt.Sprintf("Rotating the keytab of the service principal %s on the host %s", spec.Principal, host),
		Steps: []string{
			"retiring the current keytab of " + spec.Principal + " in the directory: the keytab and the certificates issued to the service are revoked, the entry stays",
			"ordering identity.keytab.renew on the fleet host " + host + ": the host takes a Kerberos ticket with its own key out of /etc/krb5.keytab, and ipa-getkeytab fetches the new key into that file with it",
		},
		ReachableHosts: []string{host},
		Warnings: []string{
			"between the retirement and the renewal the service cannot authenticate: tickets it already issued keep working until they expire, new ones are refused",
			"certificates issued to the service principal are revoked together with the keytab",
			"the renewal runs on the fleet host of that name; a host that is not in the fleet or not connected refuses the rotation before the keytab is retired",
			"the two halves cannot be ordered the other way round: the fetch itself replaces the key in the directory, so retiring afterwards would delete the key just fetched. The gap is inherent to the operation",
			"the change is reported as partially applied until the host's renewal task reports the key it fetched; the retired key cannot be put back from the panel, and a renewal that fails is ordered again as identity.keytab.renew on " + host,
		},
	}
	services, err := p.directory.Services(ctx)
	if err != nil {
		return plan, err
	}
	var found *freeipa.Service
	for index := range services {
		if samePrincipal(services[index].Principal, spec.Principal) {
			found = &services[index]
			break
		}
	}
	if found == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the directory has no service principal %s", spec.Principal))
		return plan, nil
	}
	if found.HasKeytab != nil && !*found.HasKeytab {
		// Nothing to retire is not a refusal: the host fetches a first key the same
		// way.
		plan.Warnings = append(plan.Warnings, "the directory reports no keytab for this principal; the host fetches a first key rather than replacing one")
	}
	if found.HasKeytab == nil {
		plan.Warnings = append(plan.Warnings, "the directory did not say whether the principal has a keytab")
	}
	if len(found.ManagedBy) > 0 && !containsFold(found.ManagedBy, host) {
		// ipa-getkeytab with the host credential works when the host manages the
		// entry.
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the host %s does not manage the entry of %s (managed by %s); it could not fetch the new keytab",
			host, spec.Principal, strings.Join(found.ManagedBy, ", ")))
	}
	p.bindFleetHost(ctx, &plan, host)
	return plan, nil
}

// bindFleetHost names in the plan the host the renewal will be ordered on. The
// execution resolves the same name again and refuses a plan that named another
// host, so an unresolved binding is a conflict here rather than a failure after
// the keytab is already retired.
func (p *Planner) bindFleetHost(ctx context.Context, plan *Plan, host string) {
	if p.fleet == nil {
		return
	}
	bound, err := p.fleet.FleetHost(ctx, host)
	switch {
	case errors.Is(err, ErrFleetHostAmbiguous):
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf(
			"%s; the renewal could not be routed to one of them", err))
	case errors.Is(err, ErrHostNotInFleet):
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf(
			"%s is not a host of this fleet; nobody would fetch the new keytab", host))
	case err != nil:
		plan.Warnings = append(plan.Warnings,
			"the panel could not read its own host table, so the plan names no fleet host: "+err.Error())
	default:
		plan.FleetHostID = bound.ID
		if !bound.Online {
			// Not a conflict: the host may be back by the time the second person
			// approves, and the execution refuses an absent host by itself.
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"the fleet host %s (%s) is not connected now; the rotation refuses while it stays away",
				bound.Hostname, bound.ID))
		}
	}
}

// samePrincipal compares two principals with or without their realms: the
// directory prints the realm, the operator often does not.
func samePrincipal(listed, wanted string) bool {
	if strings.EqualFold(listed, wanted) {
		return true
	}
	listedName, _, _ := strings.Cut(listed, "@")
	wantedName, _, wantedRealm := strings.Cut(wanted, "@")
	return !wantedRealm && strings.EqualFold(listedName, wantedName)
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

// rotateKeytab carries out the two halves in the only order there is: the host
// is resolved first, then the keytab retired, then the renewal ordered. The
// halves cannot be swapped - ipa-getkeytab sets a new key in the directory, so
// service_disable after the fetch would delete the key just fetched - which is
// why the gap between them is the one thing the operator has to be told about.
func (e *Executor) rotateKeytab(ctx context.Context, change Change, spec *KeytabPayload) []Phase {
	resolving := startPhase("finding the fleet host " + spec.Host())
	if e.fleet == nil {
		return []Phase{finishPhase(resolving, fmt.Errorf("this panel cannot order the renewal on a host; the keytab is not retired"), "")}
	}
	host, err := e.fleet.FleetHost(ctx, spec.Host())
	if err != nil {
		return []Phase{finishPhase(resolving, fmt.Errorf("%w; the keytab is not retired", err), "")}
	}
	planned, err := plannedFleetHost(change)
	if err != nil {
		return []Phase{finishPhase(resolving, fmt.Errorf("%w; the keytab is not retired", err), "")}
	}
	if planned != "" && planned != host.ID {
		// The fleet moved between the approval and now: the renewal would go to a
		// host nobody approved it for.
		return []Phase{finishPhase(resolving, fmt.Errorf(
			"the plan named the host %s and %s now resolves to %s (%s); the keytab is not retired",
			planned, spec.Host(), host.Hostname, host.ID), "")}
	}
	if !host.Online {
		return []Phase{finishPhase(resolving, fmt.Errorf("%w: %s; the keytab is not retired", ErrHostOffline, host.Hostname), "")}
	}
	phases := []Phase{finishPhase(resolving, nil, host.Hostname+" ("+host.ID+"), connected")}

	retiring := startPhase("retiring the keytab of " + spec.Principal + " in the directory")
	if err := e.retireKeytab(ctx, spec.Principal); err != nil {
		phases = append(phases, finishPhase(retiring, err, ""))
		return phases
	}
	phases = append(phases, finishPhase(retiring, nil, "the keytab and the service certificates are revoked; the entry stays"))

	ordering := startPhase("ordering the renewal on " + host.Hostname)
	jobID, err := e.fleet.OrderKeytabRenewal(ctx, host, spec.Principal, change)
	if err != nil {
		// The keytab is gone and the task was not placed: a partial result
		// the operator has to read as such, and order the renewal by hand.
		phases = append(phases, finishPhase(ordering, fmt.Errorf("%w; the keytab is retired and the renewal has to be ordered by hand", err), ""))
		return phases
	}
	// Placing the task is not renewing the keytab. The service holds a key the
	// directory has retired until the host reports the key it fetched, so the
	// change stays out of a success until that task settles.
	phases = append(phases, outstandingPhase(ordering, "task "+jobID+" carries the renewal on "+
		host.Hostname+"; the keytab of "+spec.Principal+" is retired and the service cannot "+
		"authenticate until that task reports the key it fetched. The retired key cannot be put "+
		"back from the panel: if the task fails, read its result and order identity.keytab.renew "+
		"on "+host.Hostname+" again."))
	return phases
}

// plannedFleetHost reads the host the approved plan named. An empty identifier
// is a plan made before the binding existed; the execution then routes the task
// by its own resolution alone.
func plannedFleetHost(change Change) (string, error) {
	var planned struct {
		FleetHostID string `json:"fleet_host_id"`
	}
	if len(change.Plan) == 0 {
		return "", nil
	}
	if err := json.Unmarshal(change.Plan, &planned); err != nil {
		return "", fmt.Errorf("the plan of the change does not read: %w", err)
	}
	return planned.FleetHostID, nil
}

// retireKeytab is the directory half of the rotation. The executor holds
// the concrete connector, so the call goes through a seam a test replaces.
func (e *Executor) retireKeytab(ctx context.Context, principal string) error {
	if e.retire != nil {
		return e.retire(ctx, principal)
	}
	if e.directory == nil {
		return fmt.Errorf("the directory connector is not configured")
	}
	return e.directory.RetireServiceKeytab(ctx, principal)
}
