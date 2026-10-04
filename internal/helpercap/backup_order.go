package helpercap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The binding of a backup used to be one field - the identifier of the
// definition - while the request carries everything that decides what happens:
// which snapshot, where to, over what, with which retention, running which
// runbook. A consent to "restore definition X" therefore authorized restoring
// any snapshot anywhere with overwriting, which is writing any file on the host
// as root under a signature of the panel's.
//
// Listing the fields in the binding is the wrong fix: the list would have to be
// extended with every new field of BackupRequest and nobody would remember -
// which is exactly how this came to bind the identifier alone. One digest of
// the whole order binds the lot, and keeps binding it when a field is added.
//
// Secrets are in the digest as names, never as values: the panel holds a
// reference to the store and the host holds the value it fetched, so a digest
// over values could not be computed on both sides at all.

// backupOrder is the one canonical form of a backup order. It is filled from
// the payload the panel signed and from the request the helper received, and
// the two have to come out identical - so the fields live in one struct rather
// than in two lists that drift apart.
type backupOrder struct {
	Operation   string
	ID          string
	Tool        string
	Repository  string
	Paths       []string
	Excludes    []string
	Tags        []string
	KeepLast    int
	KeepDaily   int
	KeepWeekly  int
	KeepMonthly int
	Prune       bool
	Runbook     string
	Initialize  bool
	ReadData    bool
	SnapshotID  string
	Target      string
	Include     []string
	Overwrite   string
	Plan        string
	PlanHash    string
	// HasPassword says a repository password travels with the order; the value
	// is not part of the digest.
	HasPassword bool
	// EnvNames are the environment variables the order sets, by name.
	EnvNames []string
}

// digest is the canonical text of the order, hashed. One field per line,
// name first, so a new field cannot silently collide with an old one.
func (o backupOrder) digest() string {
	names := append([]string(nil), o.EnvNames...)
	sort.Strings(names)
	var text strings.Builder
	write := func(name string, value any) {
		fmt.Fprintf(&text, "%s=%v\n", name, value)
	}
	write("operation", o.Operation)
	write("id", o.ID)
	write("tool", o.Tool)
	write("repository", o.Repository)
	write("paths", strings.Join(o.Paths, "\x1f"))
	write("excludes", strings.Join(o.Excludes, "\x1f"))
	write("tags", strings.Join(o.Tags, "\x1f"))
	write("keep_last", o.KeepLast)
	write("keep_daily", o.KeepDaily)
	write("keep_weekly", o.KeepWeekly)
	write("keep_monthly", o.KeepMonthly)
	write("prune", o.Prune)
	write("runbook", o.Runbook)
	write("initialize", o.Initialize)
	write("read_data", o.ReadData)
	write("snapshot_id", o.SnapshotID)
	write("target", o.Target)
	write("include", strings.Join(o.Include, "\x1f"))
	write("overwrite", o.Overwrite)
	write("plan", o.Plan)
	write("plan_hash", o.PlanHash)
	write("password", o.HasPassword)
	write("env", strings.Join(names, "\x1f"))
	sum := sha256.Sum256([]byte(text.String()))
	return hex.EncodeToString(sum[:])
}

// BackupOrderDigest is the digest of the order a capability authorizes, from
// the payload the panel signed.
func BackupOrderDigest(operation string, payload *opspec.BackupPayload) string {
	if payload == nil {
		return ""
	}
	order := backupOrder{
		Operation: operation, ID: payload.ID, Tool: payload.Tool,
		Repository: payload.Repository, Paths: payload.Paths,
		Excludes: payload.Excludes, Tags: payload.Tags,
		KeepLast: payload.KeepLast, KeepDaily: payload.KeepDaily,
		KeepWeekly: payload.KeepWeekly, KeepMonthly: payload.KeepMonthly,
		Prune: payload.Prune, Runbook: payload.Runbook,
		Initialize: payload.Initialize, ReadData: payload.ReadData,
		SnapshotID: payload.SnapshotID, Target: payload.Target,
		Include: payload.Include, Overwrite: payload.Overwrite,
		Plan: payload.Plan, PlanHash: payload.PlanHash,
		HasPassword: !payload.PasswordSecret.Empty(),
	}
	for name := range payload.EnvSecrets {
		order.EnvNames = append(order.EnvNames, name)
	}
	return order.digest()
}

// backupRequestDigest is the same digest, from the request the helper received.
func backupRequestDigest(request *helperv1.BackupRequest) string {
	if request == nil {
		return ""
	}
	order := backupOrder{
		Operation: backupOperationName(request.GetOperation()), ID: request.GetId(),
		Tool: request.GetTool(), Repository: request.GetRepository(),
		Paths: request.GetPaths(), Excludes: request.GetExcludes(), Tags: request.GetTags(),
		KeepLast: int(request.GetKeepLast()), KeepDaily: int(request.GetKeepDaily()),
		KeepWeekly: int(request.GetKeepWeekly()), KeepMonthly: int(request.GetKeepMonthly()),
		Prune: request.GetPrune(), Runbook: request.GetRunbook(),
		Initialize: request.GetInitialize(), ReadData: request.GetReadData(),
		SnapshotID: request.GetSnapshotId(), Target: request.GetTarget(),
		Include: request.GetInclude(), Overwrite: request.GetOverwrite(),
		Plan: request.GetPlan(), PlanHash: request.GetPlanHash(),
		HasPassword: len(request.GetPassword()) > 0,
	}
	for name := range request.GetEnv() {
		order.EnvNames = append(order.EnvNames, name)
	}
	return order.digest()
}

// backupOperationName names the operation the same way on both sides: the
// action type the panel put in the payload.
func backupOperationName(operation helperv1.BackupRequest_Operation) string {
	switch operation {
	case helperv1.BackupRequest_OPERATION_PLAN:
		return string(opspec.ActionBackupPlan)
	case helperv1.BackupRequest_OPERATION_RUN:
		return string(opspec.ActionBackupRun)
	case helperv1.BackupRequest_OPERATION_VERIFY:
		return string(opspec.ActionBackupVerify)
	case helperv1.BackupRequest_OPERATION_RESTORE:
		return string(opspec.ActionBackupRestore)
	}
	return operation.String()
}
