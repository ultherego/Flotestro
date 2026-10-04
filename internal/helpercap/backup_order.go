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
	// The operation is deliberately not here. Which operation is being carried
	// out is bound by the action type of the capability and by Expect, which
	// says for each request kind which action types may authorize it - and the
	// verification of a copy legitimately sends a plan under the capability of
	// the run it verifies. Putting the operation in the digest made those two
	// disagree by construction, so every verified backup ended as
	// "applied_unverified": the change made and the verifier refused at the
	// door for a difference nobody had introduced.
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

// BackupOrderDifference names the fields in which the request and the bound
// payload disagree. Field names only: a refusal says which part of the order
// differs without printing a repository address or a path back into a log.
//
// It exists because the refusal used to print two digests and nothing else. A
// verifier read that filled six fields of a twenty-field order was then
// indistinguishable from a tampered order, and the answer to "which field"
// cost an hour of reading the two sides. One line of the refusal now says it.
func BackupOrderDifference(request *helperv1.BackupRequest, payload *opspec.BackupPayload) []string {
	got, want := orderOfRequest(request), orderOfPayload(payload)
	var differing []string
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"id", got.ID, want.ID},
		{"tool", got.Tool, want.Tool},
		{"repository", got.Repository, want.Repository},
		{"paths", strings.Join(got.Paths, "\x1f"), strings.Join(want.Paths, "\x1f")},
		{"excludes", strings.Join(got.Excludes, "\x1f"), strings.Join(want.Excludes, "\x1f")},
		{"tags", strings.Join(got.Tags, "\x1f"), strings.Join(want.Tags, "\x1f")},
		{"keep_last", got.KeepLast, want.KeepLast},
		{"keep_daily", got.KeepDaily, want.KeepDaily},
		{"keep_weekly", got.KeepWeekly, want.KeepWeekly},
		{"keep_monthly", got.KeepMonthly, want.KeepMonthly},
		{"prune", got.Prune, want.Prune},
		{"runbook", got.Runbook, want.Runbook},
		{"initialize", got.Initialize, want.Initialize},
		{"read_data", got.ReadData, want.ReadData},
		{"snapshot_id", got.SnapshotID, want.SnapshotID},
		{"target", got.Target, want.Target},
		{"include", strings.Join(got.Include, "\x1f"), strings.Join(want.Include, "\x1f")},
		{"overwrite", got.Overwrite, want.Overwrite},
		{"plan", got.Plan, want.Plan},
		{"plan_hash", got.PlanHash, want.PlanHash},
		{"password", got.HasPassword, want.HasPassword},
		{"env", strings.Join(sorted(got.EnvNames), "\x1f"), strings.Join(sorted(want.EnvNames), "\x1f")},
	} {
		if fmt.Sprintf("%v", field.got) != fmt.Sprintf("%v", field.want) {
			differing = append(differing, field.name)
		}
	}
	return differing
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// BackupOrderDigest is the digest of the order a capability authorizes, from
// the payload the panel signed.
func BackupOrderDigest(payload *opspec.BackupPayload) string {
	if payload == nil {
		return ""
	}
	return orderOfPayload(payload).digest()
}

// orderOfPayload is the canonical order as the panel signed it.
func orderOfPayload(payload *opspec.BackupPayload) backupOrder {
	if payload == nil {
		return backupOrder{}
	}
	order := backupOrder{
		ID: payload.ID, Tool: payload.Tool,
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
	return order
}

// backupRequestDigest is the same digest, from the request the helper received.
func backupRequestDigest(request *helperv1.BackupRequest) string {
	return orderOfRequest(request).digest()
}

// orderOfRequest is the canonical order as the helper received it.
func orderOfRequest(request *helperv1.BackupRequest) backupOrder {
	if request == nil {
		return backupOrder{}
	}
	order := backupOrder{
		ID:   request.GetId(),
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
	return order
}
