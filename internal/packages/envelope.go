package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/plan"
)

// PlannerVersion names the package planner. It changes when the planner
// starts computing something else for the same host - another field in
// the envelope, another reading of the tools - so that an approval given
// on the old planner is not executed by the new one: a version mismatch
// at execution is replan_required, not a stale plan and not a JSON error.
const PlannerVersion = "packages/1"

// The kinds of the preconditions a package plan carries.
const (
	preconditionMetadata  = "metadata_revision"
	preconditionLockFree  = "lock_free"
	preconditionProtected = "protected_absent"
)

// The rollback mechanisms a package plan can name.
const (
	RollbackDNFHistory  = "dnf_history"
	RollbackPacmanCache = "pacman_cache"
	RollbackNone        = "none"
)

// ActionTypeOf names the operation a plan of this mode executes as: the
// action type of the envelope.
func ActionTypeOf(mode string) string {
	switch mode {
	case ModeInstall:
		return "packages.install"
	case ModeRemove:
		return "packages.remove"
	}
	return "packages.upgrade"
}

// Envelope renders the plan in the shape every planner's answer takes
// before it is hashed, approved and executed. Every element of the plan
// becomes an artifact (what is fetched), a step (the exact spec the tool
// gets) and an effect (what the host looks like afterwards); the
// removals become steps and effects without an artifact.
func (p Plan) Envelope() plan.Envelope {
	envelope := plan.Envelope{
		SchemaVersion:     p.SchemaVersion,
		PlannerVersion:    p.PlannerVersion,
		ActionType:        ActionTypeOf(p.Mode),
		HostID:            p.HostID,
		InventoryRevision: p.InventoryRevision,
		ResourceRevision:  p.ResourceRevision,
		ExpiresAt:         p.ExpiresAt,
		Rollback: plan.RollbackPlan{
			Mechanism: p.Rollback.Mechanism, ID: p.Rollback.ID,
			Available: p.Rollback.Available, Reason: p.Rollback.Reason,
		},
		Description: p.Description(),
	}
	if envelope.SchemaVersion == 0 {
		envelope.SchemaVersion = plan.SchemaVersion
	}
	if envelope.PlannerVersion == "" {
		envelope.PlannerVersion = PlannerVersion
	}
	envelope.Preconditions = append(envelope.Preconditions,
		plan.Precondition{Kind: preconditionMetadata, Subject: p.Manager, Expected: p.ResourceRevision})
	for _, path := range lockPathsOf(p.Manager) {
		envelope.Preconditions = append(envelope.Preconditions,
			plan.Precondition{Kind: preconditionLockFree, Subject: path, Expected: "not held"})
	}
	for _, name := range p.Protected {
		envelope.Preconditions = append(envelope.Preconditions,
			plan.Precondition{Kind: preconditionProtected, Subject: name, Expected: "not in the plan"})
	}

	var installDelta int64
	installKnown := len(p.Changes) > 0
	for _, change := range p.Changes {
		if change.Action != ActionRemove {
			envelope.Artifacts = append(envelope.Artifacts, plan.Artifact{
				Kind: "package", Name: change.Name, Version: change.CandidateVersion,
				Architecture: change.Architecture, Origin: change.Origin, Digest: change.Digest,
			})
			envelope.Effects.Expected = append(envelope.Effects.Expected, plan.Effect{
				Kind: plan.EffectPackageVersion, Subject: change.Name, Value: change.CandidateVersion,
			})
		} else {
			envelope.Effects.Expected = append(envelope.Effects.Expected, plan.Effect{
				Kind: plan.EffectPackageAbsent, Subject: change.Name,
			})
		}
		envelope.Steps = append(envelope.Steps, plan.Step{
			Kind: change.Action, Subject: change.Name, Spec: exactSpec(p.Manager, change),
		})
		if change.InstalledDeltaKnown {
			installDelta += change.InstalledDeltaBytes
		} else {
			installKnown = false
		}
	}
	// A removal plan of the older shape names its removals apart from its
	// changes; they are effects all the same.
	for _, name := range p.Removals {
		if hasChange(p.Changes, name) {
			continue
		}
		envelope.Steps = append(envelope.Steps, plan.Step{Kind: ActionRemove, Subject: name, Spec: name})
		envelope.Effects.Expected = append(envelope.Effects.Expected,
			plan.Effect{Kind: plan.EffectPackageAbsent, Subject: name})
	}
	envelope.Effects.RebootRequired = p.RebootPredicted
	envelope.Effects.ServicesRestartKnown = false
	envelope.Effects.DownloadBytes = p.DownloadBytes
	envelope.Effects.DownloadKnown = downloadKnown(p.Space)
	envelope.Effects.InstallDeltaBytes = installDelta
	envelope.Effects.InstallDeltaKnown = installKnown
	return envelope.Normalized()
}

// Description is the plan in words for the screen: the one part of the
// envelope outside the digest.
func (p Plan) Description() string {
	counts := map[string]int{}
	for _, change := range p.Changes {
		counts[change.Action]++
	}
	var parts []string
	for _, action := range []string{ActionInstall, ActionUpgrade, ActionDowngrade, ActionRemove} {
		if n := counts[action]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, action))
		}
	}
	if len(parts) == 0 {
		return "nothing to change (" + p.Manager + ")"
	}
	return strings.Join(parts, ", ") + " (" + p.Manager + ")"
}

// ExactSpecs returns the arguments the transaction hands to the tool: one
// per element of the plan, in the tool's own spelling of an exact version.
// The executor installs what is named here and nothing it resolves anew.
func (p Plan) ExactSpecs() []string {
	specs := make([]string, 0, len(p.Changes))
	for _, change := range p.Changes {
		if change.Action == ActionRemove {
			continue
		}
		specs = append(specs, exactSpec(p.Manager, change))
	}
	sort.Strings(specs)
	return specs
}

// HasDowngrade says whether any element of the plan goes back a version.
// APT gets --allow-downgrades only then.
func (p Plan) HasDowngrade() bool {
	for _, change := range p.Changes {
		if change.Action == ActionDowngrade {
			return true
		}
	}
	return false
}

// RepositoryIDs lists the repositories the plan draws from, each once.
func (p Plan) RepositoryIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, change := range p.Changes {
		if change.Action == ActionRemove || change.Origin == "" || seen[change.Origin] {
			continue
		}
		seen[change.Origin] = true
		ids = append(ids, change.Origin)
	}
	sort.Strings(ids)
	return ids
}

// exactSpec spells one element the way the manager takes an exact version
// on its command line: name=version for apt (with the architecture where
// the plan names one, so a foreign-architecture package is not resolved
// to the native one), the full NEVRA for dnf, name=version for pacman
// where the archive is later resolved from the download.
func exactSpec(manager string, change Change) string {
	if change.Action == ActionRemove {
		return change.Name
	}
	switch manager {
	case "apt":
		name := change.Name
		// An architecture-independent package ("all") is not addressed by
		// an architecture; apt knows it under its bare name only.
		if change.Architecture != "" && change.Architecture != "all" && !strings.Contains(name, ":") {
			name += ":" + change.Architecture
		}
		return name + "=" + change.CandidateVersion
	case "dnf":
		spec := change.Name + "-" + change.CandidateVersion
		if change.Architecture != "" {
			spec += "." + change.Architecture
		}
		return spec
	default:
		return change.Name + "=" + change.CandidateVersion
	}
}

func hasChange(changes []Change, name string) bool {
	for _, change := range changes {
		if change.Name == name {
			return true
		}
	}
	return false
}

func downloadKnown(facts []SpaceFact) bool {
	for _, fact := range facts {
		if fact.Purpose == SpaceDownload {
			return fact.Basis == BasisDownloadSize
		}
	}
	return false
}

// lockPathsOf names the lock files the transaction must find free.
func lockPathsOf(manager string) []string {
	switch manager {
	case "apt":
		return aptLockFiles
	case "dnf":
		return dnfLockFiles
	case PacmanName:
		return []string{pacmanLockPath}
	}
	return nil
}

// finishPlan completes what every manager's plan shares: the header from
// the options, the planner's own version, the metadata revision the plan
// was read against, the direction and the flags of every element, and the
// rollback answer. It runs on the agent when the plan is made and in the
// helper when the plan is made again before the transaction, so both
// compute the same envelope.
func finishPlan(ctx context.Context, manager Manager, p Plan, options Options) Plan {
	p.SchemaVersion = plan.SchemaVersion
	p.PlannerVersion = PlannerVersion
	p.HostID = options.Header.HostID
	p.InventoryRevision = options.Header.InventoryRevision
	p.ExpiresAt = options.Header.ExpiresAt
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = time.Now().Add(plan.DefaultTTL)
	}
	p.ExpiresAt = p.ExpiresAt.UTC().Truncate(time.Second)
	if p.Mode == "" {
		p.Mode = options.Mode
	}
	if p.ResourceRevision == "" {
		p.ResourceRevision = MetadataRevision(manager)
	}
	requested := map[string]bool{}
	for _, name := range options.Packages {
		requested[name] = true
		requested[strings.SplitN(name, ":", 2)[0]] = true
	}
	blocked := map[string]bool{}
	for _, entry := range p.Blocked {
		blocked[entry.Name] = true
	}
	// An ordinary upgrade skips the agent package - raised in a transaction
	// it carries out itself it would cut the host off halfway through - so
	// the plan does not promise a change the transaction will not make.
	// Replacing the agent has an operation of its own.
	if p.Mode == "" || p.Mode == ModeUpgrade {
		kept := p.Changes[:0]
		for _, change := range p.Changes {
			if change.Name != AgentPackage {
				kept = append(kept, change)
			}
		}
		p.Changes = kept
	}
	for i := range p.Changes {
		change := &p.Changes[i]
		if change.Action == "" {
			change.Action = changeAction(p.Manager, change.CurrentVersion, change.CandidateVersion)
		}
		if change.Reason == "" {
			change.Reason = ReasonDependency
			if requested[change.Name] || requested[strings.SplitN(change.Name, ":", 2)[0]] || p.Mode == "" || p.Mode == ModeUpgrade {
				change.Reason = ReasonRequested
			}
		}
		change.Blocked = blocked[change.Name]
		change.Protected = change.Action == ActionRemove && Protected(change.Name)
	}
	// The removals of the older shape become elements of the plan: a
	// removal plan whose only content was its list of removals read as
	// "nothing to change", and a dependency that goes away is exactly
	// what the operator approves or refuses.
	for _, name := range p.Removals {
		if hasChange(p.Changes, name) {
			continue
		}
		reason := ReasonDependency
		if requested[name] {
			reason = ReasonRequested
		}
		p.Changes = append(p.Changes, Change{
			Name: name, Action: ActionRemove, Reason: reason, Protected: Protected(name),
		})
	}
	sort.SliceStable(p.Changes, func(i, j int) bool { return p.Changes[i].Name < p.Changes[j].Name })
	if p.Rollback.Mechanism == "" {
		p.Rollback = rollbackOf(p.Manager)
	}
	return p
}

// rollbackOf is the plan's honest answer about undoing the change. Dnf
// records every transaction and can undo it; pacman keeps the archives of
// the previous versions in its cache, which is a rollback as long as the
// cache is not cleaned; apt keeps no transaction to undo. The identifier
// of a dnf transaction exists only once it ran, so the plan names the
// mechanism and the result names the identifier.
func rollbackOf(manager string) Rollback {
	switch manager {
	case "dnf":
		return Rollback{Mechanism: RollbackDNFHistory, Available: true,
			Reason: "dnf history undo of the transaction recorded"}
	case PacmanName:
		return Rollback{Mechanism: RollbackPacmanCache, Available: true,
			Reason: "the previous archives stay in " + pacmanCacheDir + " until the cache is cleaned"}
	default:
		return Rollback{Mechanism: RollbackNone, Available: false,
			Reason: "apt keeps no transaction to undo; the previous archives are not kept"}
	}
}

// MetadataRevision digests the repository indexes the plan is read
// against: the release files of apt, the repomd of every dnf repository
// in the cache, the databases of the pacman sync copy. The same indexes
// give the same revision whoever reads them, and a repository that
// published between the plan and the transaction gives another - which is
// the one signal that a plan approved against the old indexes is stale
// even when the versions it names happen to be the same.
func MetadataRevision(manager Manager) string {
	if manager == nil {
		return ""
	}
	var files []string
	switch manager.Name() {
	case "apt":
		files = aptIndexFiles()
	case "dnf":
		files = dnfIndexFiles()
	case PacmanName:
		files = pacmanIndexFiles()
	}
	return manager.Name() + ":" + digestFiles(files)
}

// aptIndexFiles lists the release files of the package lists; the
// Packages files are what they sign, so the release files alone stand for
// the indexes.
func aptIndexFiles() []string {
	entries, err := os.ReadDir(aptListsDir)
	if err != nil {
		return nil
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !(strings.HasSuffix(name, "_InRelease") || strings.HasSuffix(name, "_Release")) {
			continue
		}
		files = append(files, filepath.Join(aptListsDir, name))
	}
	return files
}

// dnfIndexFiles lists the repomd of every repository in the cache: the
// document every other index of the repository is checked against.
func dnfIndexFiles() []string {
	var files []string
	for _, root := range []string{"/var/cache/libdnf5", "/var/cache/dnf"} {
		matches, _ := filepath.Glob(filepath.Join(root, "*", "repodata", "repomd.xml"))
		files = append(files, matches...)
	}
	return files
}

// pacmanIndexFiles lists the databases of the sync copy the plan reads.
func pacmanIndexFiles() []string {
	copyDir := checkupdatesDB()
	if !fileExists(checkupdatesPath) {
		copyDir = SyncCopyDir
	}
	matches, _ := filepath.Glob(filepath.Join(copyDir, "sync", "*.db"))
	return matches
}

// digestFiles digests the names and the contents of the files, sorted by
// name. No file at all is written down as such rather than as the digest
// of nothing: a plan read against no index is not the same plan as one
// read against an index.
func digestFiles(files []string) string {
	if len(files) == 0 {
		return "none"
	}
	sort.Strings(files)
	total := sha256.New()
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(total, "%s\nunreadable\n", filepath.Base(path))
			continue
		}
		content := sha256.New()
		_, copyErr := io.Copy(content, file)
		_ = file.Close()
		if copyErr != nil {
			fmt.Fprintf(total, "%s\nunreadable\n", filepath.Base(path))
			continue
		}
		fmt.Fprintf(total, "%s\n%x\n", filepath.Base(path), content.Sum(nil))
	}
	return hex.EncodeToString(total.Sum(nil))[:32]
}
