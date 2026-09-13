package certificates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Plan describes the difference between the certificate the host has under
// a path and the one that is to land there.
//
// The same certificate deployed to two hosts is almost never the same
// change: one has a certificate expiring tomorrow there, another the same
// as ordered, a third has no file at all, and each reloads a different
// service. The operator's approval is meant to cover those differences.
//
// The private key is not in the plan and not in the fingerprint: the plan
// is stored in the database and shown in the panel, so it would be a place
// of a leak. The plan says about the key only where the host takes it from
// - the secret name and version.
type Plan struct {
	// Kind names the plan kind. The certificates module computes three
	// different plans with the same task, and the receiver is not meant to
	// recognise them by which fields happen to be empty.
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	KeyPath string `json:"key_path,omitempty"`
	// Action names what would happen: create, update or no_change.
	Action string `json:"action"`

	// The state found. No fingerprint with Exists = true means a file that
	// could not be read - and then UnavailableReason carries it.
	Exists             bool       `json:"exists"`
	CurrentSubject     string     `json:"current_subject,omitempty"`
	CurrentFingerprint string     `json:"current_fingerprint,omitempty"`
	CurrentNotAfter    *time.Time `json:"current_not_after,omitempty"`
	UnavailableReason  string     `json:"unavailable_reason,omitempty"`

	// The desired state: what the panel sent explicitly. The certificate
	// is public material, so the plan describes it directly.
	DesiredSubject     string    `json:"desired_subject,omitempty"`
	DesiredFingerprint string    `json:"desired_fingerprint,omitempty"`
	DesiredNotAfter    time.Time `json:"desired_not_after,omitempty"`
	DesiredSANs        []string  `json:"desired_sans,omitempty"`
	ChainLength        int       `json:"chain_length,omitempty"`

	// KeySecret names the secret the host reaches for right before the
	// replacement. Never its value.
	KeySecret   string `json:"key_secret,omitempty"`
	ReloadUnit  string `json:"reload_unit,omitempty"`
	ProbeTarget string `json:"probe_target,omitempty"`

	Changes []string `json:"changes,omitempty"`
	// Refusal names the reason the deployment will not land on this host:
	// material the host will not accept, a target outside the certificate
	// scope, no reference to the key. A plan with a refusal is an answer
	// the operator is meant to see before approving.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan kinds of the certificates module.
const (
	KindDeployment = "certificate"
	KindRenewal    = "renewal"
	KindTrust      = "trust"
)

// Plan action names.
const (
	PlanCreate       = "create"
	PlanUpdate       = "update"
	PlanNoChange     = "no_change"
	PlanRemove       = "remove"
	PlanRemoveAbsent = "remove_absent"
)

// Order describes a deployment as seen by the planner. There is no key
// here: the plan is made without reaching into the secret store.
type Order struct {
	Path        string
	KeyPath     string
	Certificate string
	KeySecret   string
	Unit        string
	Target      string
	HasKey      bool
}

// Compute computes the difference between the certificate found and the
// ordered one.
//
// A missing file and an unread file are two different answers: the first
// means "the certificate will be created", the second "it is unknown what
// lies there" - and the second must not pretend to be the first.
func Compute(current Certificate, order Order, now time.Time) Plan {
	plan := Plan{
		Kind: KindDeployment,
		Path: order.Path, KeyPath: order.KeyPath,
		KeySecret: order.KeySecret, ReloadUnit: order.Unit,
		ProbeTarget: order.Target,
	}
	if current.FingerprintSHA256 != "" || (current.UnavailableReason != "" && !FileMissing(current.UnavailableReason)) {
		plan.Exists = true
		plan.CurrentSubject = current.Subject
		plan.CurrentFingerprint = current.FingerprintSHA256
		plan.CurrentNotAfter = current.NotAfter
		plan.UnavailableReason = current.UnavailableReason
	}

	if err := ValidatePath(order.Path); err != nil {
		return plan.withRefusal(err.Error())
	}
	if order.KeyPath != "" {
		if err := ValidatePath(order.KeyPath); err != nil {
			return plan.withRefusal(err.Error())
		}
	}
	if err := ValidateUnit(order.Unit); err != nil {
		return plan.withRefusal(err.Error())
	}
	if order.Target != "" {
		if err := ValidateTarget(order.Target); err != nil {
			return plan.withRefusal(err.Error())
		}
	}
	// The private key travels to the host only as a reference to the
	// store. A deployment without it would leave the new certificate with
	// the old key, and the service would not come up after the reload.
	if order.KeyPath != "" && !order.HasKey {
		return plan.withRefusal("a key deployment requires a reference to the secret store")
	}

	certs, err := ParsePEM([]byte(order.Certificate))
	if err != nil {
		return plan.withRefusal(err.Error())
	}
	if err := CheckDates(certs[0], now); err != nil {
		return plan.withRefusal(err.Error())
	}
	if err := CheckChain(certs); err != nil {
		return plan.withRefusal(err.Error())
	}
	// A probe target outside the certificate scope would end in rolling
	// back the deployment after the files were replaced. Better to say so
	// before approval.
	if order.Target != "" {
		if name := targetName(order.Target); name != "" && !Covers(certs[0], name) {
			return plan.withRefusal("the certificate does not cover the name " + name +
				" the host was to check the deployment at")
		}
	}

	plan.DesiredSubject = certs[0].Subject.String()
	plan.DesiredFingerprint = Fingerprint(certs[0])
	plan.DesiredNotAfter = certs[0].NotAfter.UTC()
	plan.DesiredSANs = AlternativeNames(certs[0])
	plan.ChainLength = len(certs)

	switch {
	case plan.Exists && plan.CurrentFingerprint == "":
		// The file could not be read. That means neither "will be created"
		// nor "no change": the operator is meant to see the reason before
		// approving.
		return plan.withRefusal("the current certificate was not read: " + plan.UnavailableReason)
	case !plan.Exists:
		plan.Action = PlanCreate
		plan.Changes = []string{"the certificate will be created, valid until " +
			plan.DesiredNotAfter.Format(time.RFC3339)}
	case plan.CurrentFingerprint == plan.DesiredFingerprint:
		plan.Action = PlanNoChange
	default:
		plan.Action = PlanUpdate
		plan.Changes = []string{fmt.Sprintf("certificate from %s to %s",
			shortened(plan.CurrentFingerprint), shortened(plan.DesiredFingerprint))}
		if plan.CurrentNotAfter != nil {
			plan.Changes = append(plan.Changes, "validity from "+
				plan.CurrentNotAfter.UTC().Format(time.RFC3339)+" to "+
				plan.DesiredNotAfter.Format(time.RFC3339))
		}
	}
	if plan.Action != PlanNoChange {
		if order.KeyPath != "" {
			plan.Changes = append(plan.Changes, "the private key will be replaced from the secret "+
				orNone(order.KeySecret))
		}
		if order.Unit != "" {
			plan.Changes = append(plan.Changes, "the service "+order.Unit+" will be reloaded")
		}
		if order.Target != "" {
			plan.Changes = append(plan.Changes, "the host will check the deployment with a probe to "+order.Target)
		}
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

// targetName extracts the host name from a "host:port" probe target.
func targetName(target string) string {
	if i := strings.LastIndex(target, ":"); i > 0 {
		return target[:i]
	}
	return target
}

func shortened(fingerprint string) string {
	if len(fingerprint) <= 16 {
		return orNone(fingerprint)
	}
	return fingerprint[:16]
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

// planFingerprint computes the plan fingerprint excluding the fingerprint
// itself. The private key is not in the plan, so it is not in the
// fingerprint either.
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

// FileMissing says whether the unavailability reason describes a file that
// does not exist.
//
// A non-existent file and an unread file are two different answers: the
// first is a target state to create, the second is no knowledge.
func FileMissing(reason string) bool {
	return strings.Contains(reason, "no such file or directory") ||
		strings.Contains(reason, os.ErrNotExist.Error())
}

// RenewalPlan describes a certificate renewal by the host daemon.
//
// A renewal is a different change than a deployment: the panel sends no
// material, it only asks the daemon to fetch a new certificate from its
// authority. That is why the plan talks about what the host has now and
// whether it has anyone to order the renewal from at all - not about the
// content that will come.
type RenewalPlan struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Action string `json:"action"`

	// The state found: the certificate and what watches it.
	CurrentFingerprint string     `json:"current_fingerprint,omitempty"`
	CurrentNotAfter    *time.Time `json:"current_not_after,omitempty"`
	DaysToExpiry       *int       `json:"days_to_expiry,omitempty"`
	// Request is the identifier of the certmonger request on this host.
	// The same certificate has a different identifier on every host, so
	// the campaign gives the path and the host finds the request itself.
	Request string `json:"request,omitempty"`
	Status  string `json:"status,omitempty"`
	CA      string `json:"ca,omitempty"`
	// AutoRenew says whether the daemon would renew this certificate on its
	// own too.
	AutoRenew *bool `json:"auto_renew,omitempty"`

	ReloadUnit string   `json:"reload_unit,omitempty"`
	Changes    []string `json:"changes,omitempty"`
	Refusal    string   `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// ComputeRenewal computes the renewal plan against the host state.
func ComputeRenewal(current Certificate, tracking *Tracking, hasDaemon bool,
	path, unit string, now time.Time) RenewalPlan {
	plan := RenewalPlan{Kind: KindRenewal, Path: path,
		ReloadUnit: unit, Action: PlanUpdate}
	if err := ValidatePath(path); err != nil {
		return plan.withRefusal(err.Error())
	}
	if err := ValidateUnit(unit); err != nil {
		return plan.withRefusal(err.Error())
	}
	// The host daemon is the only one here who can renew: the panel has
	// neither the key nor an agreement with the authority. A host without
	// the daemon is not a host to be fixed by a change - it is a host that
	// will not accept this change.
	if !hasDaemon {
		return plan.withRefusal("this host has no certmonger, so there is nobody to order the renewal from")
	}
	if current.FingerprintSHA256 != "" {
		plan.CurrentFingerprint = current.FingerprintSHA256
		plan.CurrentNotAfter = current.NotAfter
		plan.DaysToExpiry = current.DaysToExpiry(now)
	}
	if tracking == nil || tracking.Request == "" {
		return plan.withRefusal("certmonger does not track the file " + path + ", so there is nothing to renew")
	}
	plan.Request = tracking.Request
	plan.Status = tracking.Status
	plan.CA = tracking.CA
	plan.AutoRenew = tracking.AutoRenew

	plan.Changes = []string{"the host will ask the authority " + orNone(tracking.CA) +
		" for a new certificate for " + path}
	if plan.DaysToExpiry != nil {
		plan.Changes = append(plan.Changes,
			fmt.Sprintf("the current certificate expires in %d days", *plan.DaysToExpiry))
	}
	// The request state matters more here than the fact that the daemon
	// knows it: CA_UNREACHABLE means care that does not work, and the
	// operator is meant to see that before approval, not after.
	if tracking.Status != "" && tracking.Status != "MONITORING" {
		plan.Changes = append(plan.Changes, "certmonger reports the state "+tracking.Status)
	}
	if unit != "" {
		plan.Changes = append(plan.Changes, "the service "+unit+" will be reloaded")
	}
	plan.PlanHash = renewalPlanFingerprint(plan)
	return plan
}

// Refuse records a refusal reason learned after the plan was computed.
func (p *RenewalPlan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = renewalPlanFingerprint(*p)
}

func (p RenewalPlan) withRefusal(reason string) RenewalPlan {
	p.Refusal = reason
	p.Action = ""
	p.PlanHash = renewalPlanFingerprint(p)
	return p
}

// renewalPlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself.
//
// The request identifier is different on every host and changes with every
// new request, so it enters the fingerprint: a renewal approved for one
// request must not land on another.
func renewalPlanFingerprint(plan RenewalPlan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
