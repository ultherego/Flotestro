package helpercap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
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

// backupOrderPrefix separates these bytes from every other thing this package
// hashes, so a digest of an order cannot be presented as a digest of anything
// else.
const backupOrderPrefix = "flotestro-backup-order/2\n"

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

	// Length-prefixed, not a text form with separators.
	//
	// It used to be one "name=value" line per field, with lists joined by
	// U+001F. Both choices were ambiguous: Include=["/safe\x1f/extra"] and
	// Include=["/safe","/extra"] produced identical bytes, so a restore could
	// be widened to another path under a digest that still matched - and a
	// value carrying a newline could do the same to the field after it. Every
	// field and every element now carries its own length, so no content can be
	// read as the structure around it.
	var out []byte
	out = append(out, backupOrderPrefix...)
	text := func(name, value string) {
		out = appendBytes(appendBytes(out, []byte(name)), []byte(value))
	}
	number := func(name string, value int) {
		out = appendUint(appendBytes(out, []byte(name)), uint64(value))
	}
	flag := func(name string, value bool) {
		set := 0
		if value {
			set = 1
		}
		number(name, set)
	}
	list := func(name string, values []string) {
		out = appendUint(appendBytes(out, []byte(name)), uint64(len(values)))
		for _, value := range values {
			out = appendBytes(out, []byte(value))
		}
	}

	// The operation is deliberately not here. Which operation is being carried
	// out is bound by the action type of the capability and by Expect, which
	// says for each request kind which action types may authorize it - and the
	// verification of a copy legitimately sends a plan under the capability of
	// the run it verifies. Putting the operation in the digest made those two
	// disagree by construction, so every verified backup ended as
	// "applied_unverified": the change made and the verifier refused at the
	// door for a difference nobody had introduced.
	text("id", o.ID)
	text("tool", o.Tool)
	text("repository", o.Repository)
	list("paths", o.Paths)
	list("excludes", o.Excludes)
	list("tags", o.Tags)
	number("keep_last", o.KeepLast)
	number("keep_daily", o.KeepDaily)
	number("keep_weekly", o.KeepWeekly)
	number("keep_monthly", o.KeepMonthly)
	flag("prune", o.Prune)
	text("runbook", o.Runbook)
	flag("initialize", o.Initialize)
	flag("read_data", o.ReadData)
	text("snapshot_id", o.SnapshotID)
	text("target", o.Target)
	list("include", o.Include)
	text("overwrite", o.Overwrite)
	text("plan", o.Plan)
	text("plan_hash", o.PlanHash)
	flag("password", o.HasPassword)
	list("env", names)
	sum := sha256.Sum256(out)
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
		{"paths", listText(got.Paths), listText(want.Paths)},
		{"excludes", listText(got.Excludes), listText(want.Excludes)},
		{"tags", listText(got.Tags), listText(want.Tags)},
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
		{"include", listText(got.Include), listText(want.Include)},
		{"overwrite", got.Overwrite, want.Overwrite},
		{"plan", got.Plan, want.Plan},
		{"plan_hash", got.PlanHash, want.PlanHash},
		{"password", got.HasPassword, want.HasPassword},
		{"env", listText(sorted(got.EnvNames)), listText(sorted(want.EnvNames))},
	} {
		if fmt.Sprintf("%v", field.got) != fmt.Sprintf("%v", field.want) {
			differing = append(differing, field.name)
		}
	}
	return differing
}

// listText renders a list for comparison without the ambiguity the digest used
// to have: an element carrying the separator cannot pass for two elements.
func listText(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Quote(value))
	}
	return "[" + strings.Join(parts, " ") + "]"
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
