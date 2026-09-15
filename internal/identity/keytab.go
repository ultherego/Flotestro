package identity

import (
	"context"
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

// A service keytab rotation is one consent over two halves in two places:
// the directory retires the principal's current keytab, and the fleet host
// that carries the service fetches a new one into its own keytab file with
// the credentials it holds. The panel carries no key material in either
// direction; it orders, records and links.

var (
	// ErrHostNotInFleet means the host the principal names is not a host
	// of the panel: nobody could fetch the new keytab, so the old one must
	// not be retired.
	ErrHostNotInFleet = errors.New("the host the principal names is not a host of the fleet")
	// ErrHostOffline means the fleet host is not connected: the retirement
	// would leave the service without a keytab for as long as the host
	// stays away.
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

// HostOrderer finds the fleet host of a principal and orders the host's
// half of the rotation on it. The executor holds it as an interface so
// the rotation can be checked without a fleet database.
type HostOrderer interface {
	// FleetHost resolves the FQDN of the principal to a host of the panel,
	// or ErrHostNotInFleet.
	FleetHost(ctx context.Context, fqdn string) (FleetHost, error)
	// OrderKeytabRenewal creates the pre-approved renewal task on the host
	// and returns its identifier.
	OrderKeytabRenewal(ctx context.Context, host FleetHost, principal string, change Change) (string, error)
}

// FleetOrderer is the HostOrderer over the panel's own tables. It is built
// from the pool the change store already has, so the executor needs no
// wiring beyond what it holds.
type FleetOrderer struct {
	hosts *hosts.Store
	jobs  *jobs.Store
	audit *audit.Recorder
}

func NewFleetOrderer(pool *pgxpool.Pool, recorder *audit.Recorder) *FleetOrderer {
	return &FleetOrderer{hosts: hosts.NewStore(pool), jobs: jobs.NewStore(pool), audit: recorder}
}

// FleetHost matches the FQDN the principal names to a fleet host by its
// hostname, case aside. The search filter finds by substring, so the match
// is confirmed here: web1.example.test must not stand in for
// web10.example.test.
func (o *FleetOrderer) FleetHost(ctx context.Context, fqdn string) (FleetHost, error) {
	if o == nil || o.hosts == nil {
		return FleetHost{}, fmt.Errorf("this panel has no fleet store to order the renewal through")
	}
	listed, err := o.hosts.List(ctx, hosts.ListFilter{Search: fqdn, Limit: 50})
	if err != nil {
		return FleetHost{}, err
	}
	for _, host := range listed {
		if !strings.EqualFold(host.Hostname, fqdn) {
			continue
		}
		// A host on its way out of the fleet cannot be given a task: the
		// rotation would retire a keytab nobody renews.
		if host.LifecycleState != "" && host.LifecycleState != hosts.StateActive {
			continue
		}
		return FleetHost{ID: host.ID, Hostname: host.Hostname, OSFamily: host.OSFamily,
			Online: host.ConnectionState == "online"}, nil
	}
	return FleetHost{}, fmt.Errorf("%w: %s", ErrHostNotInFleet, fqdn)
}

// OrderKeytabRenewal creates the renewal task under the change's consent:
// the change was approved with fresh authentication, and the task carries
// that approval rather than asking for a second one. The task is
// idempotent on the change, so a repeated execution does not fetch twice.
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
// principal, which host, and the gap in between. The principal has to
// exist in the directory; a principal the directory does not know is a
// conflict, because service_disable on it would fail after the approval.
func (p *Planner) planKeytabRotate(ctx context.Context, spec *KeytabPayload) (Plan, error) {
	host := spec.Host()
	plan := Plan{
		Summary: fmt.Sprintf("Rotating the keytab of the service principal %s on the host %s", spec.Principal, host),
		Steps: []string{
			"retiring the current keytab of " + spec.Principal + " in the directory: the keytab and the certificates issued to the service are revoked, the entry stays",
			"ordering identity.keytab.renew on the fleet host " + host + ": ipa-getkeytab fetches the new key into /etc/krb5.keytab with the host's own credentials",
		},
		ReachableHosts: []string{host},
		Warnings: []string{
			"between the retirement and the renewal the service cannot authenticate: tickets it already issued keep working until they expire, new ones are refused",
			"certificates issued to the service principal are revoked together with the keytab",
			"the renewal runs on the fleet host of that name; a host that is not in the fleet or not connected refuses the rotation before the keytab is retired",
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
		// Nothing to retire is not a refusal: the host fetches a first key
		// the same way. The operator is told, because "rotation" then
		// promises more than happens.
		plan.Warnings = append(plan.Warnings, "the directory reports no keytab for this principal; the host fetches a first key rather than replacing one")
	}
	if found.HasKeytab == nil {
		plan.Warnings = append(plan.Warnings, "the directory did not say whether the principal has a keytab")
	}
	if len(found.ManagedBy) > 0 && !containsFold(found.ManagedBy, host) {
		// ipa-getkeytab with the host credential works when the host
		// manages the entry. A host that does not is a refusal the
		// directory makes after the retirement - too late.
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the host %s does not manage the entry of %s (managed by %s); it could not fetch the new keytab",
			host, spec.Principal, strings.Join(found.ManagedBy, ", ")))
	}
	return plan, nil
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

// rotateKeytab carries out the two halves, in the only safe order: the
// host is resolved and checked first, because a keytab retired with
// nobody to fetch a new one is an outage until somebody joins the host
// anew; then the directory retires the keytab; then the renewal task is
// ordered on the host. The task's own result - the key version numbers -
// is read on the task, not here: the executor does not wait on a host.
func (e *Executor) rotateKeytab(ctx context.Context, change Change, spec *KeytabPayload) []Phase {
	resolving := startPhase("finding the fleet host " + spec.Host())
	if e.fleet == nil {
		return []Phase{finishPhase(resolving, fmt.Errorf("this panel cannot order the renewal on a host; the keytab is not retired"), "")}
	}
	host, err := e.fleet.FleetHost(ctx, spec.Host())
	if err != nil {
		return []Phase{finishPhase(resolving, fmt.Errorf("%w; the keytab is not retired", err), "")}
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
	phases = append(phases, finishPhase(ordering, nil, "task "+jobID+": ipa-getkeytab on the host reports the old and the new key version"))
	return phases
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
