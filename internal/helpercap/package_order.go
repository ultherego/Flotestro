package helpercap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The binding of a package action compared the list of packages and, for a
// hold, the direction. Everything else the request carries went unchecked: the
// plan digest - which the agent sets on the request - the header of the plan
// envelope, its expiry, security_only and allow_downgrade. A consent to
// "install A and B" therefore authorized installing A and B out of any plan,
// including one from last week and one with allow_downgrade on, which is a way
// back to a version with a known hole in it.
//
// One digest of the whole order, as for a backup: a field added to the request
// is bound from the moment it is added to the struct below, rather than waiting
// for somebody to remember a list.

// packageOrder is the canonical form of a package order, filled from the
// payload the panel signed and from the request the helper received.
type packageOrder struct {
	Operation        string
	Packages         []string
	ExpectedRemovals []string
	Hold             bool
	SecurityOnly     bool
	AllowDowngrade   bool
	// PlanHash is the digest of the plan the order is bound to, in hex.
	PlanHash string
	// The header of the approved plan envelope.
	PlanSchemaVersion uint32
	PlannerVersion    string
	InventoryRevision string
	ResourceRevision  string
	PlanExpiresUnix   int64
	// Changes are the elements of the plan the operator approved, as the
	// request carries them.
	Changes []string
}

func (o packageOrder) digest() string {
	var text strings.Builder
	write := func(name string, value any) {
		fmt.Fprintf(&text, "%s=%v\n", name, value)
	}
	write("operation", o.Operation)
	write("packages", strings.Join(o.Packages, "\x1f"))
	write("expected_removals", strings.Join(o.ExpectedRemovals, "\x1f"))
	write("hold", o.Hold)
	write("security_only", o.SecurityOnly)
	write("allow_downgrade", o.AllowDowngrade)
	write("plan_hash", o.PlanHash)
	write("plan_schema_version", o.PlanSchemaVersion)
	write("planner_version", o.PlannerVersion)
	write("inventory_revision", o.InventoryRevision)
	write("resource_revision", o.ResourceRevision)
	write("plan_expires_unix", o.PlanExpiresUnix)
	write("changes", strings.Join(o.Changes, "\x1e"))
	sum := sha256.Sum256([]byte(text.String()))
	return hex.EncodeToString(sum[:])
}

// packageOrderDigest is the digest of the order a capability authorizes, from
// the payload the panel signed. The operation comes from the request, because
// install, remove and hold share one payload and the direction of a hold is
// compared on its own.
func packageOrderDigest(operation string, change *opspec.PackageChangePayload,
	upgrade *opspec.PackageUpgradePayload) string {
	order := packageOrder{Operation: operation}
	var reference *opspec.PlanReference
	switch {
	case change != nil:
		order.Packages = change.Packages
		order.ExpectedRemovals = change.ExpectedRemovals
		order.Hold = change.Hold
		order.PlanHash = normalHash(change.PlanHash)
		reference = change.Plan
	case upgrade != nil:
		order.Packages = upgrade.Packages
		order.SecurityOnly = upgrade.SecurityOnly
		order.PlanHash = normalHash(upgrade.PlanHash)
		reference = upgrade.Plan
	}
	// A hold carries no plan: the agent does not put one on the request for
	// that operation, so the payload's plan is not part of this order either.
	// Saying it here, where both sides are written, is what keeps them equal.
	if operation == "hold" {
		order.PlanHash = ""
		return order.digest()
	}
	if reference != nil {
		order.PlanSchemaVersion = reference.SchemaVersion
		order.PlannerVersion = reference.PlannerVersion
		order.InventoryRevision = reference.InventoryRevision
		order.ResourceRevision = reference.ResourceRevision
		if reference.ExpiresAt != "" {
			if moment, err := time.Parse(time.RFC3339, reference.ExpiresAt); err == nil {
				order.PlanExpiresUnix = moment.Unix()
			}
		}
		for _, change := range reference.Changes {
			order.Changes = append(order.Changes, strings.Join([]string{
				change.Name, change.CurrentVersion, change.CandidateVersion,
				change.Architecture, change.Origin, change.Action,
			}, "\x1f"))
		}
	}
	return order.digest()
}

// packageRequestDigest is the same digest, from the request the helper got.
func packageRequestDigest(request *helperv1.PackageActionRequest) string {
	order := packageOrder{
		Operation:         packageOperationName(request.GetOperation()),
		Packages:          request.GetPackages(),
		ExpectedRemovals:  request.GetExpectedRemovals(),
		Hold:              request.GetHold(),
		SecurityOnly:      request.GetSecurityOnly(),
		AllowDowngrade:    request.GetAllowDowngrade(),
		PlanHash:          hex.EncodeToString(request.GetPlanHash()),
		PlanSchemaVersion: request.GetPlanSchemaVersion(),
		PlannerVersion:    request.GetPlannerVersion(),
		InventoryRevision: request.GetPlanInventoryRevision(),
		ResourceRevision:  request.GetPlanResourceRevision(),
		PlanExpiresUnix:   request.GetPlanExpiresAtUnix(),
	}
	for _, spec := range request.GetExactSpecs() {
		order.Changes = append(order.Changes, strings.Join([]string{
			spec.GetName(), spec.GetCurrentVersion(), spec.GetCandidateVersion(),
			spec.GetArchitecture(), spec.GetOrigin(), spec.GetAction(),
		}, "\x1f"))
	}
	return order.digest()
}

// normalHash reads a digest the panel wrote as text the way the agent does, so
// the two sides spell the same bytes the same way.
func normalHash(text string) string {
	return strings.ToLower(strings.TrimSpace(text))
}

// packageOperationName names the operation the same way on both sides.
func packageOperationName(operation helperv1.PackageActionRequest_Operation) string {
	switch operation {
	case helperv1.PackageActionRequest_OPERATION_INSTALL:
		return "install"
	case helperv1.PackageActionRequest_OPERATION_REMOVE:
		return "remove"
	case helperv1.PackageActionRequest_OPERATION_UPGRADE:
		return "upgrade"
	case helperv1.PackageActionRequest_OPERATION_HOLD:
		return "hold"
	}
	return operation.String()
}

// The binding of a package source compared the identifier and the address. The
// agent fills fourteen fields; nine of them went unchecked - Remove, Enabled,
// AllowUnsigned, GpgKey, Priority, Suites, Components, Architectures, Username.
// A consent to "set the source X at the address Y" therefore authorized the
// same source with signature checking off and another GPG key, which is the
// installation of any package the holder likes, and package scripts run as
// root. The same consent also turned into a removal, which for a source of
// security updates is a silent stop to updating.
//
// One digest, as for a backup and a package order. The password is in it by the
// name of the secret and never by value: the panel holds a reference to the
// store and the host holds the value it fetched.
type repositoryOrder struct {
	ID            string
	Name          string
	URL           string
	Suites        []string
	Components    []string
	Architectures []string
	Enabled       bool
	Priority      int
	GPGKey        string
	AllowUnsigned bool
	Username      string
	SecretName    string
	Remove        bool
}

func (o repositoryOrder) digest() string {
	var text strings.Builder
	write := func(name string, value any) {
		fmt.Fprintf(&text, "%s=%v\n", name, value)
	}
	write("id", o.ID)
	write("name", o.Name)
	write("url", o.URL)
	write("suites", strings.Join(o.Suites, "\x1f"))
	write("components", strings.Join(o.Components, "\x1f"))
	write("architectures", strings.Join(o.Architectures, "\x1f"))
	write("enabled", o.Enabled)
	write("priority", o.Priority)
	write("gpg_key", o.GPGKey)
	write("allow_unsigned", o.AllowUnsigned)
	write("username", o.Username)
	write("secret_name", o.SecretName)
	write("remove", o.Remove)
	sum := sha256.Sum256([]byte(text.String()))
	return hex.EncodeToString(sum[:])
}

// repositoryOrderDigest is the digest from the payload the panel signed.
func repositoryOrderDigest(payload *opspec.RepositoryPayload) string {
	if payload == nil {
		return ""
	}
	order := repositoryOrder{
		ID: payload.ID, Name: payload.Name, URL: payload.URL,
		Suites: payload.Suites, Components: payload.Components,
		Architectures: payload.Architectures, Enabled: payload.Enabled,
		Priority: payload.Priority, GPGKey: payload.GPGKey,
		AllowUnsigned: payload.AllowUnsigned, Username: payload.Username,
		Remove: payload.Remove,
	}
	// The agent fetches the password only when the source stays, so a removal
	// carries no secret name even when the payload names one.
	if !payload.PasswordSecret.Empty() && !payload.Remove {
		order.SecretName = payload.PasswordSecret.Name
	}
	return order.digest()
}

// repositoryRequestDigest is the same digest from the request.
func repositoryRequestDigest(request *helperv1.RepositoryRequest) string {
	return repositoryOrder{
		ID: request.GetId(), Name: request.GetName(), URL: request.GetUrl(),
		Suites: request.GetSuites(), Components: request.GetComponents(),
		Architectures: request.GetArchitectures(), Enabled: request.GetEnabled(),
		Priority: int(request.GetPriority()), GPGKey: request.GetGpgKey(),
		AllowUnsigned: request.GetAllowUnsigned(), Username: request.GetUsername(),
		SecretName: request.GetSecretName(), Remove: request.GetRemove(),
	}.digest()
}
