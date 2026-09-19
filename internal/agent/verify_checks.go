package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/modules/accounts"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
)

// The verifiers themselves: one read of the host per promise the contract
// makes, compared with what the payload or the plan asked for.

// sortStrings orders a list of names, so that a sentence naming several of
// them reads the same way twice.
func sortStrings(values []string) { sort.Strings(values) }

// listOf renders a list of names for a sentence. An empty list is the word
// "none": a blank would read like a missing answer rather than an empty one.
func listOf(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	ordered := append([]string(nil), values...)
	sortStrings(ordered)
	if len(ordered) > 6 {
		return strings.Join(ordered[:6], ", ") + " and " +
			strconv.Itoa(len(ordered)-6) + " more"
	}
	return strings.Join(ordered, ", ")
}

// collapsed squeezes the whitespace of a value read from the host, so that a
// setting written with a tab and the same setting written with a space compare
// equal.
func collapsed(value string) string { return strings.Join(strings.Fields(value), " ") }

// yesNo picks the word an observation carries for a promise of two states.
func yesNo(value bool, yes, no string) string {
	if value {
		return yes
	}
	return no
}

// contentDigest is the digest of the content an order carries. It never
// leaves this function in any other form.
func contentDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// noReader says the agent has no way of reading this part of the host.
func noReader(what string) string { return "this agent carries no reader of " + what }

// verifyUnitState reads the unit after the change: active after a start,
// inactive after a stop, enabled or masked as the toggle said, not failed
// after a reset.
func verifyUnitState(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	unit := ""
	switch {
	case in.payload.Unit != nil:
		unit = in.payload.Unit.Unit
	case in.payload.UnitToggle != nil:
		unit = in.payload.UnitToggle.Unit
	}
	toggled := in.payload.UnitToggle != nil && in.payload.UnitToggle.Enabled

	expected := "active"
	switch in.action {
	case opspec.ActionUnitStop:
		expected = "inactive"
	case opspec.ActionUnitResetFailed:
		expected = "not failed"
	case opspec.ActionUnitEnableSet:
		expected = yesNo(toggled, "enabled", "disabled")
	case opspec.ActionUnitMaskSet:
		expected = yesNo(toggled, "masked", "not masked")
	}

	if unit == "" {
		return unreadable(expected, "the order names no unit")
	}
	if readers.unit == nil {
		return unreadable(expected, noReader("unit state"))
	}
	state, err := readers.unit(ctx, unit)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if state.LoadState == "not-found" {
		return unverified(expected, "not found", "systemd does not know the unit "+unit+" after the change")
	}

	switch in.action {
	case opspec.ActionUnitEnableSet:
		observed := firstNonEmpty(state.UnitFileState, "unknown")
		if state.UnitFileState == "" {
			return unreadable(expected, "the unit "+unit+" reports no unit file state")
		}
		if strings.HasPrefix(state.UnitFileState, "enabled") == toggled {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the unit file of "+unit+" reads "+observed+" and not "+expected)
	case opspec.ActionUnitMaskSet:
		observed := firstNonEmpty(state.UnitFileState, "unknown")
		if state.UnitFileState == "" {
			return unreadable(expected, "the unit "+unit+" reports no unit file state")
		}
		if strings.HasPrefix(state.UnitFileState, "masked") == toggled {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the unit file of "+unit+" reads "+observed+" and not "+expected)
	case opspec.ActionUnitStop:
		observed := firstNonEmpty(state.ActiveState, "unknown")
		if state.ActiveState == "inactive" {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the unit "+unit+" is "+observed+" after the stop")
	case opspec.ActionUnitResetFailed:
		observed := firstNonEmpty(state.ActiveState, "unknown")
		if state.ActiveState != "failed" {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the unit "+unit+" is still failed after the reset")
	}

	// A start, a restart or a reload: the unit is to run afterwards.
	observed := firstNonEmpty(state.ActiveState, "unknown")
	if state.SubState != "" {
		observed += "/" + state.SubState
	}
	switch {
	case state.ActiveState == "active" && state.SubState != "auto-restart":
		return verified(expected, observed)
	case state.ActiveState == "activating", state.ActiveState == "reloading":
		return verified(expected, observed)
	case state.ActiveState == "inactive" && state.Result == "success":
		// A one-shot unit is inactive once it has run.
		return verified(expected, observed+", ran to completion")
	}
	return unverified(expected, observed, "the unit "+unit+" is "+observed+" after the change, result "+
		firstNonEmpty(state.Result, "unknown"))
}

// verifyScheduleEntry reads the managed entry after the change: on the host
// and enabled, disabled as ordered, or gone after a removal.
func verifyScheduleEntry(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Schedule
	if payload == nil || payload.ID == "" {
		return unreadable("a managed schedule entry", "the order names no schedule entry")
	}
	expected := "entry " + payload.ID + " present and enabled"
	switch in.action {
	case opspec.ActionScheduleDisable:
		expected = "entry " + payload.ID + " " + yesNo(payload.Enabled, "enabled", "disabled")
	case opspec.ActionScheduleRemove:
		expected = "entry " + payload.ID + " gone"
	}
	if readers.schedules == nil {
		return unreadable(expected, noReader("the schedule of the host"))
	}
	snapshot, err := readers.schedules(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}

	var found *schedules.Schedule
	for i := range snapshot.Schedules {
		if snapshot.Schedules[i].ID == payload.ID {
			found = &snapshot.Schedules[i]
			break
		}
	}
	if in.action == opspec.ActionScheduleRemove {
		if found == nil {
			return verified(expected, "gone")
		}
		return unverified(expected, "present",
			"the entry "+payload.ID+" is still on the host after the removal")
	}
	if found == nil {
		return unverified(expected, "absent",
			"the entry "+payload.ID+" is not among the entries of the host")
	}
	wantEnabled := in.action != opspec.ActionScheduleDisable || payload.Enabled
	observed := yesNo(found.Enabled, "present and enabled", "present and disabled")
	if found.Enabled != wantEnabled {
		return unverified(expected, observed, "the entry "+payload.ID+" is "+observed+" and not "+expected)
	}
	if in.action == opspec.ActionScheduleEnsure && payload.Expression != "" &&
		collapsed(found.Expression) != collapsed(payload.Expression) {
		return unverified(expected, "runs on "+collapsed(found.Expression),
			"the entry "+payload.ID+" runs on "+collapsed(found.Expression)+
				" and not on "+collapsed(payload.Expression))
	}
	// An order that named the mechanism is verified against it: an entry written
	// as a cron line where a timer was ordered runs the command, but it is not
	// what the operator asked the host for, and the next order would write the.
	if in.action == opspec.ActionScheduleEnsure &&
		(payload.Kind == opspec.ScheduleKindCron || payload.Kind == opspec.ScheduleKindTimer) &&
		found.Kind != payload.Kind {
		return unverified(expected+" as a "+payload.Kind, "a "+found.Kind+" entry",
			"the entry "+payload.ID+" is on the host as a "+found.Kind+
				" entry and not as a "+payload.Kind)
	}
	return verified(expected, observed)
}

// packageTargets says which packages the order expects installed - at which
// version, where the plan named one - and which it expects gone.
func packageTargets(in verifyInput) (map[string]string, []string) {
	wanted := map[string]string{}
	var removed []string

	candidates := map[string]string{}
	plans := []*opspec.PlanReference{}
	if in.payload.PackageChange != nil {
		plans = append(plans, in.payload.PackageChange.Plan)
	}
	if in.payload.PackageUpgrade != nil {
		plans = append(plans, in.payload.PackageUpgrade.Plan)
	}
	for _, plan := range plans {
		if plan == nil {
			continue
		}
		for _, change := range plan.Changes {
			if change.Action == "remove" {
				removed = append(removed, change.Name)
				continue
			}
			candidates[change.Name] = change.CandidateVersion
		}
	}

	switch in.action {
	case opspec.ActionPackageRemove:
		if in.payload.PackageChange != nil {
			removed = append(removed, in.payload.PackageChange.Packages...)
			removed = append(removed, in.payload.PackageChange.ExpectedRemovals...)
		}
	case opspec.ActionPackageInstall:
		if in.payload.PackageChange != nil {
			for _, name := range in.payload.PackageChange.Packages {
				wanted[name] = candidates[name]
			}
		}
	case opspec.ActionPackageUpgrade:
		for name, version := range candidates {
			wanted[name] = version
		}
		if len(wanted) == 0 && in.payload.PackageUpgrade != nil {
			for _, name := range in.payload.PackageUpgrade.Packages {
				wanted[name] = ""
			}
		}
	}
	// A package that is to go and to stay at once is a contradiction the
	// plan carries; the removal is the stronger promise and wins.
	for _, name := range removed {
		delete(wanted, name)
	}
	return wanted, uniqueNames(removed)
}

// uniqueNames keeps every name once.
func uniqueNames(values []string) []string {
	seen := map[string]bool{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

// packageAtVersion says whether the installed package is at the version the
// plan named.
func packageAtVersion(found packages.InstalledPackage, wanted string) bool {
	if wanted == "" {
		return true
	}
	return wanted == found.Version || wanted == found.EVR() || wanted == found.DebVersion()
}

// packageExpectation describes in one short phrase what the plan asked for.
func packageExpectation(wanted map[string]string, removed []string) string {
	var parts []string
	switch {
	case len(wanted) == 1:
		for name, version := range wanted {
			parts = append(parts, strings.TrimSpace(name+" "+version))
		}
	case len(wanted) > 1:
		parts = append(parts, strconv.Itoa(len(wanted))+" packages at the planned versions")
	}
	switch {
	case len(removed) == 1:
		parts = append(parts, removed[0]+" absent")
	case len(removed) > 1:
		parts = append(parts, strconv.Itoa(len(removed))+" packages absent")
	}
	if len(parts) == 0 {
		return "the packages of the plan"
	}
	return strings.Join(parts, ", ")
}

// verifyPackageVersions reads the package database after the transaction.
func verifyPackageVersions(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	wanted, removed := packageTargets(in)
	expected := packageExpectation(wanted, removed)
	if len(wanted) == 0 && len(removed) == 0 {
		return unreadable(expected, "the order names no package to compare the database with")
	}
	if readers.installed == nil {
		return unreadable(expected, noReader("the package database"))
	}
	list := readers.installed(ctx)
	if list.UnavailableReason != "" {
		return unreadable(expected, list.UnavailableReason)
	}

	installed := map[string]packages.InstalledPackage{}
	for _, entry := range list.Packages {
		if _, seen := installed[entry.Name]; !seen {
			installed[entry.Name] = entry
		}
	}

	var missing, otherVersion, stillThere []string
	for name, version := range wanted {
		found, ok := installed[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if !packageAtVersion(found, version) {
			otherVersion = append(otherVersion, name+" "+found.DebVersion())
		}
	}
	for _, name := range removed {
		if _, ok := installed[name]; ok {
			stillThere = append(stillThere, name)
		}
	}

	if len(missing) == 0 && len(otherVersion) == 0 && len(stillThere) == 0 {
		observed := expected
		if len(wanted) == 1 {
			for name := range wanted {
				observed = name + " " + installed[name].DebVersion()
			}
		}
		return verified(expected, observed)
	}

	var differences []string
	if len(missing) > 0 {
		differences = append(differences, "not installed: "+listOf(missing))
	}
	if len(otherVersion) > 0 {
		differences = append(differences, "at another version: "+listOf(otherVersion))
	}
	if len(stillThere) > 0 {
		differences = append(differences, "still installed: "+listOf(stillThere))
	}
	observed := strings.Join(differences, "; ")
	return unverified(expected, observed, "the package database does not show what the plan named: "+observed)
}

// verifyPackageHold reads the hold list of the manager after the change.
func verifyPackageHold(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.PackageChange
	if payload == nil || len(payload.Packages) == 0 {
		return unreadable("a hold state", "the order names no package")
	}
	expected := yesNo(payload.Hold, "held: ", "not held: ") + listOf(payload.Packages)
	if readers.holds == nil {
		return unreadable(expected, noReader("the hold list"))
	}
	held, reason := readers.holds(ctx)
	if reason != "" {
		return unreadable(expected, reason)
	}
	onHold := map[string]bool{}
	for _, name := range held {
		onHold[name] = true
	}
	var wrong []string
	for _, name := range payload.Packages {
		if onHold[name] != payload.Hold {
			wrong = append(wrong, name)
		}
	}
	if len(wrong) == 0 {
		return verified(expected, yesNo(payload.Hold, "held", "not held"))
	}
	observed := yesNo(payload.Hold, "not held: ", "still held: ") + listOf(wrong)
	return unverified(expected, observed, "the hold list of the manager says "+observed)
}

// verifyPackageDatabase reads whether the database still needs attention after
// a repair.
func verifyPackageDatabase(ctx context.Context, readers *hostReaders) observation {
	expected := "a package database that needs no repair"
	if readers.packageState == nil {
		return unreadable(expected, noReader("the state of the package database"))
	}
	state := readers.packageState(ctx)
	if state == nil {
		return unreadable(expected, "the package adapter said nothing about the database")
	}
	if state.GetPackageDatabaseBroken() {
		return unverified(expected, "needs repair",
			"the package database still needs repair after the operation")
	}
	if waiting := state.GetPackagesNeedingAttention(); len(waiting) > 0 {
		return unverified(expected, "waiting: "+listOf(waiting),
			"the packages "+listOf(waiting)+" still wait for their configuration to be finished")
	}
	return verified(expected, "clean")
}

// verifyRepository reads the source list of the host after the change.
func verifyRepository(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Repository
	if payload == nil || payload.ID == "" {
		return unreadable("a repository entry", "the order names no repository")
	}
	expected := "repository " + payload.ID + " " +
		yesNo(payload.Remove, "gone", yesNo(payload.Enabled, "enabled", "disabled"))
	if readers.repositories == nil {
		return unreadable(expected, noReader("the source list"))
	}
	image := readers.repositories(ctx)
	if !image.Known {
		return unreadable(expected, firstNonEmpty(image.UnavailableReason, "the source list was not read"))
	}
	var found *packages.Repository
	for i := range image.Repositories {
		if image.Repositories[i].ID == payload.ID {
			found = &image.Repositories[i]
			break
		}
	}
	if payload.Remove {
		if found == nil {
			return verified(expected, "gone")
		}
		return unverified(expected, "present",
			"the source list still names the repository "+payload.ID)
	}
	if found == nil {
		return unverified(expected, "absent",
			"the source list does not name the repository "+payload.ID)
	}
	observed := yesNo(found.Enabled, "enabled", "disabled")
	if found.Enabled != payload.Enabled {
		return unverified(expected, observed,
			"the repository "+payload.ID+" is "+observed+" and not "+yesNo(payload.Enabled, "enabled", "disabled"))
	}
	if payload.URL != "" && found.URL != "" && found.URL != payload.URL {
		return unverified(expected, "another address",
			"the repository "+payload.ID+" points at "+found.URL+" and not at "+payload.URL)
	}
	return verified(expected, observed)
}

// verifyFileContent reads the file after the write: the digest of the content
// ordered, with the mode and the owner ordered, or a file that is no longer
// there after a removal.
func verifyFileContent(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.File
	if payload == nil || payload.Path == "" {
		return unreadable("a file state", "the order names no file")
	}
	removal := in.action == opspec.ActionFileRemove

	wanted := ""
	if !removal {
		switch {
		case payload.Content != "":
			wanted = contentDigest(payload.Content)
		case payload.VersionSHA256 != "":
			wanted = payload.VersionSHA256
		default:
			// A file whose content comes from the secret store: the order carries a
			// reference, so the digest the helper reported after the write is the only
			// description of it that may be shown.
			wanted = in.result.GetFileResult().GetSha256()
		}
	}
	expected := "sha256:" + shortDigest(wanted)
	if removal {
		expected = payload.Path + " gone"
	} else if wanted == "" {
		expected = "the content of the order at " + payload.Path
	}

	if readers.file == nil {
		return unreadable(expected, noReader("files"))
	}
	state, err := readers.file(ctx, payload.Path)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if removal {
		if !state.exists {
			return verified(expected, "gone")
		}
		return unverified(expected, "present", "the file "+payload.Path+" is still on the host after the removal")
	}
	if !state.exists {
		return unverified(expected, "gone", "the file "+payload.Path+" is not on the host after the write")
	}
	if wanted == "" {
		return unreadable("the content of the order at "+payload.Path,
			"the order carries neither the content nor its digest to compare with")
	}
	observed := "sha256:" + shortDigest(state.sha256)
	if state.sha256 == "" {
		return unreadable(expected, "the host reported no digest for "+payload.Path)
	}
	if state.sha256 != wanted {
		return unverified(expected, observed,
			"the file "+payload.Path+" carries another content than the one written")
	}
	if payload.Mode != "" && state.mode != "" && strings.TrimPrefix(state.mode, "0") != strings.TrimPrefix(payload.Mode, "0") {
		return unverified(expected+" mode "+payload.Mode, observed+" mode "+state.mode,
			"the file "+payload.Path+" has the mode "+state.mode+" and not "+payload.Mode)
	}
	if payload.Owner != "" && state.owner != "" && state.owner != payload.Owner {
		return unverified(expected+" owner "+payload.Owner, observed+" owner "+state.owner,
			"the file "+payload.Path+" belongs to "+state.owner+" and not to "+payload.Owner)
	}
	if payload.Group != "" && state.group != "" && state.group != payload.Group {
		return unverified(expected+" group "+payload.Group, observed+" group "+state.group,
			"the file "+payload.Path+" belongs to the group "+state.group+" and not to "+payload.Group)
	}
	return verified(expected, observed)
}

// verifyMountState reads the mount point after the change: mounted from the
// source with the filesystem ordered and in fstab where the order persists it,
// or unmounted and out of fstab after a removal.
func verifyMountState(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Storage
	if payload == nil || payload.Target == "" {
		return unreadable("a mount state", "the order names no mount point")
	}
	removal := in.action == opspec.ActionMountRemove
	expected := "mounted at " + payload.Target
	if payload.Source != "" {
		expected += " from " + payload.Source
	}
	if payload.Persist {
		expected += ", in fstab"
	}
	if removal {
		expected = payload.Target + " unmounted and out of fstab"
	}
	if readers.storage == nil {
		return unreadable(expected, noReader("the disk space of the host"))
	}
	snapshot := readers.storage(ctx)
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	mount := snapshot.MountAt(payload.Target)
	if removal {
		if mount == nil {
			return verified(expected, "gone")
		}
		observed := yesNo(mount.Mounted, "still mounted", "unmounted") +
			yesNo(mount.InFstab, ", still in fstab", "")
		if !mount.Mounted && !mount.InFstab {
			return verified(expected, "gone")
		}
		return unverified(expected, observed, "the mount point "+payload.Target+" is "+observed)
	}
	if mount == nil {
		return unverified(expected, "no such mount point",
			"nothing is mounted at "+payload.Target+" after the change")
	}
	observed := yesNo(mount.Mounted, "mounted at "+mount.Target, "not mounted at "+mount.Target)
	if mount.Source != "" {
		observed += " from " + mount.Source
	}
	if mount.InFstab {
		observed += ", in fstab"
	}
	if !mount.Mounted {
		return unverified(expected, observed, "the filesystem is not mounted at "+payload.Target)
	}
	if payload.FSType != "" && mount.FSType != "" && mount.FSType != payload.FSType {
		return unverified(expected, observed,
			"the filesystem at "+payload.Target+" is "+mount.FSType+" and not "+payload.FSType)
	}
	if payload.Persist && !mount.InFstab {
		return unverified(expected, observed,
			"the mount at "+payload.Target+" is not in fstab and would not survive a reboot")
	}
	return verified(expected, observed)
}

// verifyStorageLayout reads the device after the change: a volume or a
// filesystem that grew, a device that carries the filesystem ordered, a device
// that carries no signature after a wipe, an array that knows its member
func verifyStorageLayout(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Storage
	if payload == nil {
		return unreadable("a device state", "the order carries no storage payload")
	}
	switch in.action {
	case opspec.ActionRAIDMemberFail, opspec.ActionRAIDMemberRemove, opspec.ActionRAIDMemberAdd:
		return verifyArrayMember(ctx, readers, in.action, payload)
	case opspec.ActionLVMVolumeCreate, opspec.ActionLVMSnapshotCreate,
		opspec.ActionLVMVolumeRemove, opspec.ActionLVMSnapshotRemove,
		opspec.ActionLVMGroupExtend:
		return verifyVolumeLayer(ctx, readers, in.action, payload)
	}
	if payload.Device == "" {
		return unreadable("a device state", "the order names no device")
	}
	device := payload.Device

	switch in.action {
	case opspec.ActionFilesystemCheck:
		// A check that ran is confirmed by the filesystem still being there and
		// still being the one that was checked.
		expected := "the filesystem on " + device + " is still there after the check"
		snapshot, reason := storageLayers(ctx, readers)
		if reason != "" {
			return unreadable(expected, reason)
		}
		found := snapshot.DeviceAt(device)
		if found == nil {
			return unverified(expected, "no such device",
				"the host no longer reports the device "+device+" after the check")
		}
		if found.FSType == "" {
			return unverified(expected, device+" carries no filesystem",
				"the check left "+device+" without a filesystem the host recognises")
		}
		observed := device + " carries " + found.FSType
		if payload.ExpectedUUID != "" && found.UUID != "" && found.UUID != payload.ExpectedUUID {
			return unverified(expected, observed+" with the UUID "+found.UUID,
				"the filesystem on "+device+" is not the one that was checked")
		}
		return verified(expected, observed)

	case opspec.ActionFilesystemCreate:
		expected := device + " carries " + firstNonEmpty(payload.FSType, "a filesystem")
		if readers.storage == nil {
			return unreadable(expected, noReader("the disk space of the host"))
		}
		snapshot := readers.storage(ctx)
		if snapshot.UnavailableReason != "" {
			return unreadable(expected, snapshot.UnavailableReason)
		}
		found := snapshot.DeviceAt(device)
		if found == nil {
			return unreadable(expected, "the host did not report the device "+device)
		}
		observed := device + " carries " + firstNonEmpty(found.FSType, "no filesystem")
		if payload.FSType != "" && found.FSType != payload.FSType {
			return unverified(expected, observed,
				"the device "+device+" carries "+firstNonEmpty(found.FSType, "no filesystem")+
					" and not "+payload.FSType)
		}
		if found.FSType == "" {
			return unverified(expected, observed, "the device "+device+" carries no filesystem after the change")
		}
		if payload.Label != "" && found.Label != "" && found.Label != payload.Label {
			return unverified(expected+" labelled "+payload.Label, observed+" labelled "+found.Label,
				"the filesystem on "+device+" is labelled "+found.Label+" and not "+payload.Label)
		}
		return verified(expected, observed)

	case opspec.ActionDiskWipe:
		expected := device + " carries no signature"
		if readers.storage == nil {
			return unreadable(expected, noReader("the disk space of the host"))
		}
		snapshot := readers.storage(ctx)
		if snapshot.UnavailableReason != "" {
			return unreadable(expected, snapshot.UnavailableReason)
		}
		found := snapshot.DeviceAt(device)
		if found == nil {
			// A device gone from the list is a wiped device the kernel no
			// longer recognises - not a state nobody read.
			return verified(expected, "no such device")
		}
		var leftovers []string
		if found.FSType != "" {
			leftovers = append(leftovers, "filesystem "+found.FSType)
		}
		if len(found.Children) > 0 {
			leftovers = append(leftovers, strconv.Itoa(len(found.Children))+" partitions")
		}
		if len(leftovers) == 0 {
			return verified(expected, "no signature")
		}
		observed := strings.Join(leftovers, ", ")
		return unverified(expected, observed, "the device "+device+" still carries "+observed)
	}

	// An extension: the promise is relative, so it needs the size read
	// before the change.
	expected := device + " larger than before"
	if in.before == nil || len(in.before.volumeSizes) == 0 {
		return unreadable(expected, "the size before the change was not read")
	}
	if readers.volumes == nil && readers.storage == nil {
		return unreadable(expected, noReader("the volumes of the host"))
	}

	sizeNow := uint64(0)
	target := device
	if readers.volumes != nil {
		if snapshot, err := readers.volumes(ctx); err == nil {
			for _, volume := range snapshot.Volumes {
				if volume.Path == device {
					sizeNow = volume.SizeBytes
				}
			}
		}
	}
	if readers.storage != nil {
		snapshot := readers.storage(ctx)
		for _, mount := range snapshot.Mounts {
			if mount.Source != device && mount.Target != device {
				continue
			}
			if mount.SizeBytes != nil && *mount.SizeBytes > 0 {
				// A filesystem resize is measured on the filesystem, not on
				// the volume under it: the volume can be larger already.
				if in.action == opspec.ActionFilesystemResize {
					sizeNow = *mount.SizeBytes
					target = mount.Target
				} else if sizeNow == 0 {
					sizeNow = *mount.SizeBytes
					target = mount.Target
				}
			}
		}
	}
	sizeBefore, known := in.before.volumeSizes[target]
	if !known {
		sizeBefore, known = in.before.volumeSizes[device]
	}
	if !known {
		return unreadable(expected, "the size of "+target+" before the change was not read")
	}
	if sizeNow == 0 {
		return unreadable(expected, "the host did not report the size of "+target+" after the change")
	}
	observed := target + " " + strconv.FormatUint(sizeNow/(1<<20), 10) + " MiB, before " +
		strconv.FormatUint(sizeBefore/(1<<20), 10) + " MiB"
	if sizeNow > sizeBefore {
		return verified(expected, observed)
	}
	return unverified(expected, observed, "the size of "+target+" did not grow: "+observed)
}

// storageLayers reads the whole picture of the host's disks: the block
// devices, the volume manager and the software arrays.
func storageLayers(ctx context.Context, readers *hostReaders) (storage.Snapshot, string) {
	if readers.storage != nil {
		snapshot := readers.storage(ctx)
		if snapshot.UnavailableReason == "" {
			return snapshot, ""
		}
		if readers.volumes == nil {
			return snapshot, snapshot.UnavailableReason
		}
	}
	if readers.volumes == nil {
		return storage.Snapshot{}, noReader("the disk space of the host")
	}
	snapshot, err := readers.volumes(ctx)
	if err != nil {
		return storage.Snapshot{}, err.Error()
	}
	return snapshot, ""
}

// verifyArrayMember reads the array back after a member change. mdadm exits
// zero on a member it has accepted and on one the array had already forgotten.
func verifyArrayMember(ctx context.Context, readers *hostReaders,
	action opspec.ActionType, payload *opspec.StoragePayload) observation {
	member, arrayPath := payload.Device, payload.Array
	expected := member + " a member of " + arrayPath
	switch action {
	case opspec.ActionRAIDMemberFail:
		expected = member + " marked failed in " + arrayPath
	case opspec.ActionRAIDMemberRemove:
		expected = member + " out of " + arrayPath
	}
	if member == "" || arrayPath == "" {
		return unreadable(expected, "the order names no array or no member")
	}
	snapshot, reason := storageLayers(ctx, readers)
	if reason != "" {
		return unreadable(expected, reason)
	}
	if snapshot.RAIDUnavailableReason != "" {
		return unreadable(expected, snapshot.RAIDUnavailableReason)
	}
	array := snapshot.ArrayAt(arrayPath)
	if array == nil {
		return unverified(expected, "no such array",
			"the host no longer reports the array "+arrayPath)
	}
	// The array under the path has to be the one the order was bound to:
	// /dev/md0 is whichever array the kernel assembled first this boot.
	if wanted := payload.ExpectedArrayUUID; wanted != "" && array.UUID != wanted {
		return unverified(expected, arrayPath+" carries the UUID "+firstNonEmpty(array.UUID, "none"),
			"the array under "+arrayPath+" is not the one the change was bound to")
	}
	state := arrayState(*array)
	found := array.MemberAt(member)
	switch action {
	case opspec.ActionRAIDMemberFail:
		switch {
		case found == nil:
			// The array dropped the member altogether. It has stopped
			// reading from it, which is what failing it was for.
			return verified(expected, member+" is no longer a member of "+arrayPath+"; "+state)
		case found.Failed():
			return verified(expected, member+" is failed; "+state)
		default:
			return unverified(expected, member+" is "+firstNonEmpty(found.Role, "of a role the host did not name")+"; "+state,
				"the array still uses "+member+" after the change")
		}
	case opspec.ActionRAIDMemberRemove:
		if found == nil || found.Role == storage.MemberRemoved {
			return verified(expected, member+" is out of "+arrayPath+"; "+state)
		}
		return unverified(expected, member+" is still "+firstNonEmpty(found.Role, "listed")+"; "+state,
			"the array still lists "+member+" after the removal")
	}
	if found == nil {
		return unverified(expected, arrayPath+" does not list "+member+"; "+state,
			"the array did not take "+member+" in")
	}
	observed := member + " is " + firstNonEmpty(found.Role, "listed") + "; " + state
	return verified(expected, observed)
}

// arrayState sums the array up in the numbers an operator reads first.
func arrayState(array storage.RAIDArray) string {
	state := strconv.Itoa(array.ActiveDevices) + " of " + strconv.Itoa(array.RaidDevices) + " slots filled"
	if array.Degraded {
		state += ", degraded"
	}
	if array.SyncAction != "" {
		state += ", " + array.SyncAction + " running"
	}
	return state
}

// verifyVolumeLayer reads the volume manager back after a change.
func verifyVolumeLayer(ctx context.Context, readers *hostReaders,
	action opspec.ActionType, payload *opspec.StoragePayload) observation {
	snapshot, reason := storageLayers(ctx, readers)
	switch action {
	case opspec.ActionLVMVolumeRemove, opspec.ActionLVMSnapshotRemove:
		expected := payload.Device + " is gone"
		if reason != "" {
			return unreadable(expected, reason)
		}
		if snapshot.LVMUnavailableReason != "" {
			return unreadable(expected, snapshot.LVMUnavailableReason)
		}
		if volume := snapshot.VolumeAt(payload.Device); volume != nil {
			return unverified(expected, payload.Device+" is still there ("+
				strconv.FormatUint(volume.SizeBytes>>20, 10)+" MiB)",
				"LVM still lists "+payload.Device+" after the removal")
		}
		observed := payload.Device + " is gone"
		if group := snapshot.GroupAt(payload.Group); group != nil {
			observed += "; " + group.Name + " has " +
				strconv.FormatUint(group.FreeBytes>>20, 10) + " MiB free"
		}
		return verified(expected, observed)

	case opspec.ActionLVMGroupExtend:
		expected := payload.Device + " a physical volume of " + payload.Group
		if reason != "" {
			return unreadable(expected, reason)
		}
		if snapshot.LVMUnavailableReason != "" {
			return unreadable(expected, snapshot.LVMUnavailableReason)
		}
		physical := snapshot.PhysicalVolumeAt(payload.Device)
		if physical == nil {
			return unverified(expected, payload.Device+" is not a physical volume",
				"LVM does not list "+payload.Device+" as a physical volume after the change")
		}
		if physical.Group != payload.Group {
			return unverified(expected,
				payload.Device+" belongs to "+firstNonEmpty(physical.Group, "no group"),
				"the disk carries an LVM label and did not join "+payload.Group)
		}
		observed := payload.Device + " belongs to " + payload.Group
		if group := snapshot.GroupAt(payload.Group); group != nil {
			observed += ", which now holds " + strconv.FormatUint(group.SizeBytes>>20, 10) +
				" MiB with " + strconv.FormatUint(group.FreeBytes>>20, 10) + " MiB free"
		}
		return verified(expected, observed)
	}

	// What is left is a volume or a snapshot that was to be created.
	name := payload.Volume
	expected := "a volume named " + name
	if action == opspec.ActionLVMSnapshotCreate {
		expected = "a snapshot named " + name + " of " + payload.Device
	}
	if name == "" {
		return unreadable(expected, "the order names no volume")
	}
	if reason != "" {
		return unreadable(expected, reason)
	}
	if snapshot.LVMUnavailableReason != "" {
		return unreadable(expected, snapshot.LVMUnavailableReason)
	}
	group := payload.Group
	if group == "" && action == opspec.ActionLVMSnapshotCreate {
		// A snapshot order names its origin, not the group: the group is
		// the origin's, whatever it is called on this host.
		if origin := snapshot.VolumeAt(payload.Device); origin != nil {
			group = origin.Group
		}
	}
	var created *storage.LogicalVolume
	for i := range snapshot.Volumes {
		if snapshot.Volumes[i].Name == name && (group == "" || snapshot.Volumes[i].Group == group) {
			created = &snapshot.Volumes[i]
			break
		}
	}
	if created == nil {
		return unverified(expected, firstNonEmpty(group, "the host")+" holds no volume named "+name,
			"the tool reported no error and LVM does not list "+name)
	}
	observed := created.Path + ", " + strconv.FormatUint(created.SizeBytes>>20, 10) + " MiB"
	if action == opspec.ActionLVMSnapshotCreate {
		if !created.IsSnapshot() {
			return unverified(expected, observed+" and it is not a snapshot",
				"LVM created "+name+" as an ordinary volume, not as a snapshot")
		}
		observed += ", a snapshot of " + firstNonEmpty(created.Origin, "a volume the host did not name")
	}
	// The size asked for is a floor, not a promise of the exact number: LVM
	// allocates whole extents and rounds up.
	if wanted, absolute := storage.SizeInBytes(payload.Size); absolute && created.SizeBytes < wanted {
		return unverified(expected+" of at least "+strconv.FormatUint(wanted>>20, 10)+" MiB", observed,
			"LVM gave "+name+" less space than the order asked for")
	}
	return verified(expected, observed)
}

// verifyHostname reads the kernel's host name. It needs no context: the
// read is a system call, not a command.
func verifyHostname(readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Hostname
	if payload == nil || payload.Hostname == "" {
		return unreadable("a host name", "the order names no host name")
	}
	expected := payload.Hostname
	if readers.hostname == nil {
		return unreadable(expected, noReader("the host name"))
	}
	name, err := readers.hostname()
	if err != nil {
		return unreadable(expected, err.Error())
	}
	observed := firstNonEmpty(name, "unknown")
	wanted := strings.ToLower(strings.TrimSuffix(expected, "."))
	found := strings.ToLower(strings.TrimSuffix(name, "."))
	// A host renamed to a fully qualified name reports on some distributions only
	// its first label; that is the same name, not another one.
	label, _, _ := strings.Cut(wanted, ".")
	if found == wanted || found == label {
		return verified(expected, observed)
	}
	return unverified(expected, observed, "the host calls itself "+observed+" and not "+expected)
}

// verifySysctl reads every key of the order from /proc/sys. It needs no
// context: the read is a file read.
func verifySysctl(readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Kernel
	if payload == nil || len(payload.Settings) == 0 {
		return unreadable("kernel settings", "the order names no setting")
	}
	keys := make([]string, 0, len(payload.Settings))
	for key := range payload.Settings {
		keys = append(keys, key)
	}
	sortStrings(keys)

	expected := strconv.Itoa(len(keys)) + " keys at the ordered values"
	if len(keys) == 1 {
		expected = keys[0] + "=" + collapsed(payload.Settings[keys[0]])
	}
	if readers.sysctl == nil {
		return unreadable(expected, noReader("kernel settings"))
	}

	var different, unread []string
	for _, key := range keys {
		value, err := readers.sysctl(key)
		if err != nil {
			unread = append(unread, key)
			continue
		}
		if collapsed(value) != collapsed(payload.Settings[key]) {
			different = append(different, key+"="+collapsed(value))
		}
	}
	if len(unread) > 0 {
		return unreadable(expected, "the keys "+listOf(unread)+" were not read from /proc/sys")
	}
	if len(different) == 0 {
		observed := expected
		if len(keys) > 1 {
			observed = strconv.Itoa(len(keys)) + " keys at the ordered values"
		}
		return verified(expected, observed)
	}
	observed := listOf(different)
	return unverified(expected, observed, "the kernel reads "+observed)
}

// verifyKernelModule reads whether the module is loaded, or blacklisted in
// the managed configuration.
func verifyKernelModule(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Kernel
	if payload == nil || payload.Module == "" {
		return unreadable("a kernel module state", "the order names no module")
	}
	// The kernel writes a module name with underscores whatever the file
	// calls it.
	name := strings.ReplaceAll(payload.Module, "-", "_")

	if in.action == opspec.ActionKernelModuleBlacklist {
		expected := payload.Module + " " + yesNo(payload.Blacklist, "blacklisted", "not blacklisted")
		if readers.kernel == nil {
			return unreadable(expected, noReader("the kernel configuration"))
		}
		snapshot, err := readers.kernel(ctx)
		if err != nil {
			return unreadable(expected, err.Error())
		}
		if snapshot.UnavailableReason != "" {
			return unreadable(expected, snapshot.UnavailableReason)
		}
		listed := false
		for _, entry := range snapshot.Blacklist {
			if strings.ReplaceAll(entry, "-", "_") == name {
				listed = true
				break
			}
		}
		observed := payload.Module + " " + yesNo(listed, "blacklisted", "not blacklisted")
		if listed == payload.Blacklist {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the managed configuration says "+observed)
	}

	expected := payload.Module + " loaded"
	if readers.modules == nil {
		return unreadable(expected, noReader("the loaded modules"))
	}
	loaded, err := readers.modules()
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if loaded[name] {
		return verified(expected, payload.Module+" loaded")
	}
	return unverified(expected, payload.Module+" not loaded",
		"the kernel does not list the module "+payload.Module+" after the change")
}

// verifySSHDConfig reads the effective sshd configuration and compares it with
// the settings of the order.
func verifySSHDConfig(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.SSH
	if payload == nil || !payload.DescribesChange() {
		return unreadable("an sshd configuration", "the order carries no setting to compare with")
	}
	expected := "the ordered sshd settings in effect"
	if readers.ssh == nil {
		return unreadable(expected, noReader("the sshd configuration"))
	}
	snapshot, err := readers.ssh(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}

	var different []string
	if payload.Port != "" {
		found := false
		for _, port := range snapshot.Ports {
			if port == payload.Port {
				found = true
				break
			}
		}
		if !found {
			different = append(different, "Port "+listOf(snapshot.Ports))
		}
	}
	settings := []struct {
		name    string
		wanted  string
		observe string
	}{
		{"PermitRootLogin", payload.PermitRootLogin, snapshot.PermitRootLogin},
		{"PasswordAuthentication", payload.PasswordAuthentication, snapshot.PasswordAuthentication},
		{"PubkeyAuthentication", payload.PubkeyAuthentication, snapshot.PubkeyAuthentication},
		{"KbdInteractiveAuthentication", payload.KbdInteractive, snapshot.KbdInteractive},
	}
	for _, setting := range settings {
		if setting.wanted == "" {
			continue
		}
		if !strings.EqualFold(setting.wanted, setting.observe) {
			different = append(different, setting.name+" "+firstNonEmpty(setting.observe, "unknown"))
		}
	}
	if payload.MaxAuthTries != "" && payload.MaxAuthTries != strconv.Itoa(snapshot.MaxAuthTries) {
		different = append(different, "MaxAuthTries "+strconv.Itoa(snapshot.MaxAuthTries))
	}
	if len(payload.AllowUsers) > 0 && !sameStrings(payload.AllowUsers, snapshot.AllowUsers) {
		different = append(different, "AllowUsers "+listOf(snapshot.AllowUsers))
	}
	if len(payload.AllowGroups) > 0 && !sameStrings(payload.AllowGroups, snapshot.AllowGroups) {
		different = append(different, "AllowGroups "+listOf(snapshot.AllowGroups))
	}
	if len(payload.DenyUsers) > 0 && !sameStrings(payload.DenyUsers, snapshot.DenyUsers) {
		different = append(different, "DenyUsers "+listOf(snapshot.DenyUsers))
	}

	if len(different) == 0 {
		return verified(expected, "in effect")
	}
	observed := strings.Join(different, ", ")
	return unverified(expected, observed, "the server reports "+observed+" after the change")
}

// verifySSHHostKey reads the host key of the type ordered and compares its
// fingerprint with the one from before the rotation.
func verifySSHHostKey(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	keyType := ""
	if in.payload.SSH != nil {
		keyType = strings.ToLower(in.payload.SSH.KeyType)
	}
	expected := "a new host key"
	if keyType != "" {
		expected = "a new " + keyType + " host key"
	}
	if readers.ssh == nil {
		return unreadable(expected, noReader("the sshd configuration"))
	}
	if in.before == nil || len(in.before.hostKeys) == 0 {
		return unreadable(expected, "the host keys before the rotation were not read")
	}
	snapshot, err := readers.ssh(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}

	var unchanged []string
	rotated := 0
	for _, key := range snapshot.HostKeys {
		found := strings.ToLower(key.Type)
		if keyType != "" && found != keyType {
			continue
		}
		previous, known := in.before.hostKeys[found]
		if !known {
			// A key type that was not there before is a new key by
			// definition.
			rotated++
			continue
		}
		if previous == key.Fingerprint {
			unchanged = append(unchanged, found)
			continue
		}
		rotated++
	}
	if rotated == 0 && len(unchanged) == 0 {
		return unreadable(expected, "the host reports no key of the type "+firstNonEmpty(keyType, "ordered"))
	}
	if len(unchanged) > 0 {
		return unverified(expected, "the key from before the change",
			"the host key of type "+listOf(unchanged)+" has the fingerprint it had before the rotation")
	}
	return verified(expected, strconv.Itoa(rotated)+" rotated")
}

// verifyResolver reads the resolver of the host after the change.
func verifyResolver(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.DNS
	if payload == nil || (len(payload.Servers) == 0 && len(payload.SearchDomains) == 0) {
		return unreadable("a resolver state", "the order names neither servers nor search domains")
	}
	expected := "servers " + listOf(payload.Servers)
	if len(payload.SearchDomains) > 0 {
		expected += ", search " + listOf(payload.SearchDomains)
	}
	if readers.resolver == nil {
		return unreadable(expected, noReader("the resolver"))
	}
	snapshot := readers.resolver(ctx)
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}

	servers := snapshot.Servers
	domains := snapshot.SearchDomains
	if payload.Interface != "" {
		// The resolver belongs to the interface: the file is only what the
		// service computed out of it.
		for _, link := range snapshot.Links {
			if link.Name == payload.Interface {
				servers = link.Servers
				domains = link.Domains
				break
			}
		}
	}
	observed := "servers " + listOf(servers)
	if len(payload.SearchDomains) > 0 {
		observed += ", search " + listOf(domains)
	}

	var missing []string
	for _, server := range payload.Servers {
		if !contains(servers, server) {
			missing = append(missing, server)
		}
	}
	for _, domain := range payload.SearchDomains {
		if !contains(domains, domain) {
			missing = append(missing, domain)
		}
	}
	if len(missing) > 0 {
		return unverified(expected, observed, "the resolver does not name "+listOf(missing)+" after the change")
	}
	if payload.IgnoreAutoDNS && len(payload.Servers) > 0 && len(servers) > len(payload.Servers) {
		return unverified(expected, observed,
			"the resolver names servers beyond the ordered ones although the order rejects the automatic ones")
	}
	return verified(expected, observed)
}

// contains says whether the list carries the value.
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// verifyTimeSource reads the configured time servers after the change.
func verifyTimeSource(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Time
	if payload == nil || len(payload.Servers) == 0 {
		return unreadable("the configured time servers", "the order names no time server")
	}
	expected := "servers " + listOf(payload.Servers)
	if readers.clock == nil {
		return unreadable(expected, noReader("the clock of the host"))
	}
	snapshot := readers.clock(ctx)
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	configured := make([]string, 0, len(snapshot.Configured))
	managed := make([]string, 0, len(snapshot.Configured))
	for _, server := range snapshot.Configured {
		configured = append(configured, server.Address)
		if server.Managed {
			managed = append(managed, server.Address)
		}
	}
	observed := "servers " + listOf(configured)
	var missing []string
	for _, server := range payload.Servers {
		if !contains(configured, server) {
			missing = append(missing, server)
		}
	}
	if len(missing) > 0 {
		return unverified(expected, observed,
			"the time configuration does not name "+listOf(missing)+" after the change")
	}
	if len(managed) > 0 && !sameStrings(managed, payload.Servers) {
		return unverified(expected, "managed servers "+listOf(managed),
			"the file of the panel names "+listOf(managed)+" and not "+listOf(payload.Servers))
	}
	return verified(expected, observed)
}

// verifyTimezone reads the zone of the host after the change.
func verifyTimezone(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Time
	if payload == nil || payload.Timezone == "" {
		return unreadable("a time zone", "the order names no time zone")
	}
	expected := payload.Timezone
	if readers.clock == nil {
		return unreadable(expected, noReader("the clock of the host"))
	}
	snapshot := readers.clock(ctx)
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	if snapshot.Timezone == "" {
		return unreadable(expected, "the host reported no time zone")
	}
	if snapshot.Timezone == payload.Timezone {
		return verified(expected, snapshot.Timezone)
	}
	return unverified(expected, snapshot.Timezone,
		"the host is in the zone "+snapshot.Timezone+" and not in "+payload.Timezone)
}

// verifyNetworkState reads the interface after the change: the MTU or the
// addresses ordered, and the ordered routes in the table.
func verifyNetworkState(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Network
	if payload == nil {
		return unreadable("an interface state", "the order names no interface")
	}
	// A layered order names the layer, not the interface field: a bond
	// being built is what the verifier has to find afterwards.
	subject := payload.Interface
	if payload.Link != nil && payload.Link.Name != "" {
		subject = payload.Link.Name
	}
	if subject == "" {
		return unreadable("an interface state", "the order names no interface")
	}
	expected := "the interface " + subject + " up"
	switch {
	case in.action == opspec.ActionNetworkMTUSet && payload.MTU != "":
		expected = payload.Interface + " mtu " + payload.MTU
	case in.action == opspec.ActionNetworkRouteEnsure:
		expected = strconv.Itoa(len(payload.Routes)) + " routes on " + payload.Interface
	case in.action == opspec.ActionNetworkLinkRemove:
		expected = "no interface " + subject
	case in.action == opspec.ActionNetworkLinkApply && payload.Link != nil:
		expected = payload.Link.Kind + " " + subject + " from " + listOf(payload.Link.Members)
		if payload.Link.Kind == network.LinkVLAN {
			expected = "vlan " + subject + " with the tag " +
				strconv.Itoa(payload.Link.VLANID) + " on " + payload.Link.Parent
		}
	case len(payload.Addresses) > 0 || len(payload.Addresses6) > 0:
		expected = subject + " " + listOf(append(append([]string(nil),
			payload.Addresses...), payload.Addresses6...))
	}
	if readers.network == nil {
		return unreadable(expected, noReader("the network of the host"))
	}
	snapshot := readers.network(ctx)
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	// A removal is the one order whose success is an interface that is not there.
	if in.action == opspec.ActionNetworkLinkRemove {
		if gone := snapshot.InterfaceByName(subject); gone != nil {
			return unverified(expected, "the interface "+subject+" is still there",
				"the host still reports "+subject+" after the removal")
		}
		return verified(expected, "the host no longer reports "+subject)
	}

	link := snapshot.InterfaceByName(subject)
	if link == nil {
		return unverified(expected, "no such interface",
			"the host does not report the interface "+subject+" after the change")
	}

	if in.action == opspec.ActionNetworkLinkApply && payload.Link != nil {
		return verifyNetworkLayer(expected, snapshot, *link, *payload.Link)
	}

	// An order that carries anything about the second family is verified against
	// a host that has it.
	if payload.Method6 != "" || len(payload.Addresses6) > 0 || payload.Gateway6 != "" ||
		payload.AcceptRA != "" || payload.Privacy != "" {
		if link.IPv6 != nil && link.IPv6.Off() {
			return unverified(expected, subject+" has IPv6 switched off",
				"the second family is disabled on "+subject+", so nothing written there takes effect")
		}
		if snapshot.IPv6Disabled != nil && *snapshot.IPv6Disabled {
			return unverified(expected, "the host has IPv6 switched off",
				"this host has the second family disabled for every interface")
		}
		if failed := verifyIPv6Switches(expected, subject, payload, link.IPv6); failed != nil {
			return *failed
		}
	}

	if in.action == opspec.ActionNetworkMTUSet && payload.MTU != "" && payload.MTU != "auto" {
		observed := payload.Interface + " mtu " + strconv.Itoa(link.MTU)
		if strconv.Itoa(link.MTU) == payload.MTU {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the interface "+payload.Interface+" has the MTU "+strconv.Itoa(link.MTU)+" and not "+payload.MTU)
	}

	if in.action == opspec.ActionNetworkRouteEnsure {
		var missing []string
		for _, route := range payload.Routes {
			if !routeInTable(snapshot.Routes, payload.Interface, route) {
				missing = append(missing, route)
			}
		}
		observed := strconv.Itoa(len(snapshot.Routes)) + " routes in the table"
		if len(missing) == 0 {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the routing table does not carry "+listOf(missing)+" on "+payload.Interface)
	}

	// Both families are read back, because both were ordered: an IPv6 address
	// that never landed is as much a failed change as an IPv4 one, and a verifier
	// that looked only at the first family would call it a success.
	if ordered := append(append([]string(nil), payload.Addresses...),
		payload.Addresses6...); len(ordered) > 0 {
		have := make([]string, 0, len(link.Addresses))
		for _, address := range link.Addresses {
			have = append(have, address.Address)
		}
		var missing []string
		for _, address := range ordered {
			if !contains(have, address) {
				missing = append(missing, address)
			}
		}
		observed := subject + " " + listOf(have)
		if len(missing) == 0 {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the interface "+subject+" does not carry "+listOf(missing)+" after the change")
	}

	// A profile applied by DHCP and a rollback promise no single value: what
	// they promise is an interface that is up and addressed.
	observed := subject + " " + firstNonEmpty(link.OperState, "unknown") + ", " +
		strconv.Itoa(len(link.Addresses)) + " addresses"
	if link.OperState == "down" {
		return unverified(expected, observed, "the interface "+subject+" is down after the change")
	}
	if len(link.Addresses) == 0 {
		return unverified(expected, observed,
			"the interface "+subject+" carries no address after the change")
	}
	return verified(expected, observed)
}

// verifyIPv6Switches reads the two switches of the second family back from the
// kernel after they were ordered, and returns a failed observation when the
// host does not have what was asked for.
func verifyIPv6Switches(expected, subject string, payload *opspec.NetworkPayload,
	settings *network.IPv6Settings) *observation {
	if settings == nil {
		return nil
	}
	if payload.AcceptRA != "" && settings.AcceptRA != nil {
		word := network.AcceptRAWord(*settings.AcceptRA)
		wanted := payload.AcceptRA == word ||
			(payload.AcceptRA != network.AcceptRAOff && word != network.AcceptRAOff)
		if !wanted {
			failed := unverified(expected, subject+" accept_ra "+word,
				"the host takes router advertisements on "+subject+" as "+word+
					" and not as "+payload.AcceptRA)
			return &failed
		}
	}
	if payload.Privacy != "" && settings.Privacy != nil {
		word := network.PrivacyWord(*settings.Privacy)
		if word != payload.Privacy {
			failed := unverified(expected, subject+" privacy "+word,
				"the privacy extensions on "+subject+" are "+word+" and not "+payload.Privacy)
			return &failed
		}
	}
	return nil
}

// verifyNetworkLayer reads the layering back after a layered change.
func verifyNetworkLayer(expected string, snapshot network.Snapshot,
	link network.Interface, spec network.LinkSpec) observation {
	state := network.LinkStateOf(snapshot, spec.Name)
	observed := firstNonEmpty(state.Kind, "a plain interface") + " " + spec.Name
	if len(state.Members) > 0 {
		observed += " from " + listOf(state.Members)
	}
	if state.Kind != spec.Kind {
		return unverified(expected, observed,
			"the host reports "+spec.Name+" as "+firstNonEmpty(state.Kind, "a plain interface")+
				" and not as a "+spec.Kind)
	}
	switch spec.Kind {
	case network.LinkVLAN:
		if state.Parent != spec.Parent {
			return unverified(expected, observed+" on "+firstNonEmpty(state.Parent, "nothing"),
				"the VLAN "+spec.Name+" runs on "+firstNonEmpty(state.Parent, "nothing")+
					" and not on "+spec.Parent)
		}
		if state.VLANID != spec.VLANID {
			return unverified(expected, observed+" with the tag "+strconv.Itoa(state.VLANID),
				"the VLAN "+spec.Name+" carries the tag "+strconv.Itoa(state.VLANID)+
					" and not "+strconv.Itoa(spec.VLANID))
		}
	default:
		var missing []string
		for _, member := range spec.Members {
			if !contains(state.Members, member) {
				missing = append(missing, member)
			}
		}
		if len(missing) > 0 {
			return unverified(expected, observed,
				"the "+spec.Kind+" "+spec.Name+" does not hold "+listOf(missing)+" after the change")
		}
	}
	if spec.Kind == network.LinkBond && spec.Mode != "" && state.Mode != spec.Mode {
		return unverified(expected, observed+" in the mode "+firstNonEmpty(state.Mode, "unknown"),
			"the bond "+spec.Name+" runs in the mode "+firstNonEmpty(state.Mode, "unknown")+
				" and not in "+spec.Mode)
	}
	// A layer with members that is down carries nothing, whatever it is made of.
	if link.OperState == "down" && len(state.Members) > 0 {
		return unverified(expected, observed+", down", "the "+spec.Kind+" "+spec.Name+" is down after the change")
	}
	return verified(expected, observed)
}

// routeInTable says whether the routing table carries the ordered route on the
// interface.
func routeInTable(routes []network.Route, device, wanted string) bool {
	fields := strings.Fields(wanted)
	if len(fields) == 0 {
		return false
	}
	destination := fields[0]
	gateway := ""
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "via" {
			gateway = fields[i+1]
		}
	}
	for _, route := range routes {
		if route.Destination != destination {
			continue
		}
		if route.Interface != "" && device != "" && route.Interface != device {
			continue
		}
		if gateway != "" && route.Gateway != gateway {
			continue
		}
		return true
	}
	return false
}

// verifyFirewallRuleset reads the live ruleset after the change: the rule or
// the zone entry there, or gone after a removal; a restore reads the digest of
// the ruleset restored.
func verifyFirewallRuleset(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Firewall
	if payload == nil {
		return unreadable("a firewall ruleset", "the order carries no firewall payload")
	}
	expected := "the ordered state in the live ruleset"
	switch in.action {
	case opspec.ActionFirewallRuleEnsure:
		expected = "rule " + payload.RuleID + " in the ruleset"
	case opspec.ActionFirewallRuleRemove:
		expected = "rule " + payload.RuleID + " gone"
	case opspec.ActionFirewallZonePort:
		expected = "zone " + payload.Zone + " " + yesNo(payload.Enable, "with ", "without ") + listOf(payload.Ports)
	case opspec.ActionFirewallZoneService:
		expected = "zone " + payload.Zone + " " + yesNo(payload.Enable, "with ", "without ") + payload.Service
	case opspec.ActionFirewallRulesetRestore:
		expected = "ruleset " + shortDigest(payload.ExpectedHash)
	}
	if readers.firewall == nil {
		return unreadable(expected, noReader("the firewall"))
	}
	snapshot, err := readers.firewall(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}

	switch in.action {
	case opspec.ActionFirewallRulesetRestore:
		if payload.ExpectedHash == "" {
			return unreadable(expected, "the order names no ruleset digest to compare with")
		}
		if snapshot.Hash == "" {
			return unreadable(expected, "the host reported no ruleset digest")
		}
		observed := "ruleset " + shortDigest(snapshot.Hash)
		if snapshot.Hash == payload.ExpectedHash {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the live ruleset has the digest "+shortDigest(snapshot.Hash)+
			" and not the one of the restored plan")

	case opspec.ActionFirewallRuleEnsure, opspec.ActionFirewallRuleRemove:
		if payload.RuleID == "" {
			return unreadable(expected, "the order names no rule")
		}
		// The comment is the only durable ownership marker: the handle is
		// assigned by the kernel and changes at every reload.
		marker := firewall.CommentPrefix + " " + payload.RuleID
		present := false
		for _, rule := range snapshot.Rules {
			if strings.Contains(rule.Comment, marker) || strings.Contains(rule.Text, marker) {
				present = true
				break
			}
		}
		observed := yesNo(present, "in the ruleset", "absent")
		if (in.action == opspec.ActionFirewallRuleEnsure) == present {
			return verified(expected, observed)
		}
		if present {
			return unverified(expected, observed, "the rule "+payload.RuleID+" is still in the live ruleset")
		}
		return unverified(expected, observed, "the rule "+payload.RuleID+" is not in the live ruleset")
	}

	// A zone entry on a host with firewalld.
	if payload.Zone == "" {
		return unreadable(expected, "the order names no zone")
	}
	var entries []string
	found := false
	for _, candidate := range snapshot.Zones {
		if candidate.Name != payload.Zone {
			continue
		}
		found = true
		if in.action == opspec.ActionFirewallZoneService {
			entries = candidate.Services
		} else {
			entries = candidate.Ports
		}
		break
	}
	if !found {
		return unreadable(expected, "the host does not report the zone "+payload.Zone)
	}

	var wanted []string
	if in.action == opspec.ActionFirewallZoneService {
		wanted = []string{payload.Service}
	} else {
		for _, port := range payload.Ports {
			entry := port
			if payload.Protocol != "" {
				entry = port + "/" + payload.Protocol
			}
			wanted = append(wanted, entry)
		}
	}
	var wrong []string
	for _, entry := range wanted {
		if entry == "" {
			continue
		}
		if contains(entries, entry) != payload.Enable {
			wrong = append(wrong, entry)
		}
	}
	observed := "zone " + payload.Zone + " " + listOf(entries)
	if len(wrong) == 0 {
		return verified(expected, observed)
	}
	return unverified(expected, observed, "the zone "+payload.Zone+" "+
		yesNo(payload.Enable, "does not carry ", "still carries ")+listOf(wrong))
}

// verifyMACMode reads the mode the mandatory access control reports.
func verifyMACMode(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Security
	if payload == nil || payload.Mode == "" {
		return unreadable("a mandatory access control mode", "the order names no mode")
	}
	expected := payload.Mode
	if readers.security == nil {
		return unreadable(expected, noReader("the protective state of the host"))
	}
	snapshot, err := readers.security(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	if snapshot.MAC.Mode == "" {
		return unreadable(expected, firstNonEmpty(snapshot.MAC.Reason, "the host reported no mode"))
	}
	if snapshot.MAC.Mode == payload.Mode {
		return verified(expected, snapshot.MAC.Mode)
	}
	return unverified(expected, snapshot.MAC.Mode,
		"the host runs in "+snapshot.MAC.Mode+" and not in "+payload.Mode)
}

// verifyAuditRules reads whether the audit subsystem carries loaded rules
// after the reload.
func verifyAuditRules(ctx context.Context, readers *hostReaders) observation {
	expected := "loaded audit rules"
	if readers.security == nil {
		return unreadable(expected, noReader("the protective state of the host"))
	}
	snapshot, err := readers.security(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	loaded := snapshot.Audit.RulesLoaded
	if loaded == nil {
		return unreadable(expected, firstNonEmpty(snapshot.Audit.Reason,
			"the host did not say how many rules the kernel knows"))
	}
	observed := strconv.Itoa(*loaded) + " rules loaded"
	if *loaded > 0 {
		return verified(expected, observed)
	}
	configured := 0
	if snapshot.Audit.RulesConfigured != nil {
		configured = *snapshot.Audit.RulesConfigured
	}
	return unverified(expected, observed, "the kernel knows no audit rule after the reload, "+
		strconv.Itoa(configured)+" are written in the files")
}

// verifyTrustAnchor reads the trust store of the host after the change.
func verifyTrustAnchor(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Certificate
	if payload == nil || payload.AnchorID == "" {
		return unreadable("a trust anchor", "the order names no anchor")
	}
	removal := in.action == opspec.ActionCertificateTrustRemove
	expected := "anchor " + payload.AnchorID + " " + yesNo(removal, "gone", "in the trust store")
	if readers.certificates == nil {
		return unreadable(expected, noReader("the certificates of the host"))
	}
	snapshot, err := readers.certificates(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.Trust == nil {
		return unreadable(expected, "the host did not read its trust store")
	}
	if snapshot.Trust.UnavailableReason != "" {
		return unreadable(expected, snapshot.Trust.UnavailableReason)
	}
	anchor := snapshot.Trust.Anchor(payload.AnchorID)
	if removal {
		if anchor == nil {
			return verified(expected, "gone")
		}
		return unverified(expected, "in the trust store",
			"the trust store still lists the anchor "+payload.AnchorID)
	}
	if anchor == nil {
		return unverified(expected, "absent",
			"the trust store does not list the anchor "+payload.AnchorID)
	}
	return verified(expected, "in the trust store, sha256:"+shortDigest(anchor.FingerprintSHA256))
}

// verifyCertificate reads the certificate at the path of the order: the
// fingerprint deployed, or, after a renewal, another certificate than the one
// from before.
func verifyCertificate(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Certificate
	if payload == nil || payload.Path == "" {
		return unreadable("a certificate", "the order names no certificate path")
	}
	wanted := ""
	if payload.Certificate != "" {
		if parsed, err := certificates.ParsePEM([]byte(payload.Certificate)); err == nil && len(parsed) > 0 {
			wanted = certificates.Fingerprint(parsed[0])
		}
	}
	if wanted == "" && in.action == opspec.ActionCertificateDeploy {
		wanted = in.result.GetCertificateResult().GetFingerprintSha256()
	}
	expected := "a certificate newer than the one before"
	if wanted != "" {
		expected = "sha256:" + shortDigest(wanted)
	}
	if readers.certificates == nil {
		return unreadable(expected, noReader("the certificates of the host"))
	}
	snapshot, err := readers.certificates(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.UnavailableReason != "" {
		return unreadable(expected, snapshot.UnavailableReason)
	}
	var found *certificates.Certificate
	for i := range snapshot.Certificates {
		if snapshot.Certificates[i].Path == payload.Path {
			found = &snapshot.Certificates[i]
			break
		}
	}
	if found == nil || found.FingerprintSHA256 == "" {
		return unreadable(expected, "the host did not read a certificate at "+payload.Path)
	}
	observed := "sha256:" + shortDigest(found.FingerprintSHA256)

	if wanted != "" {
		if found.FingerprintSHA256 == wanted {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the file "+payload.Path+" carries another certificate than the one deployed")
	}

	// A renewal promises no fingerprint of its own: what it promises is
	// that the file no longer carries the certificate it carried before.
	if in.before == nil || len(in.before.certificates) == 0 {
		return unreadable(expected, "the certificate before the renewal was not read")
	}
	previous, known := in.before.certificates[payload.Path]
	if !known {
		return unreadable(expected, "the certificate at "+payload.Path+" before the renewal was not read")
	}
	if found.FingerprintSHA256 != previous.fingerprint {
		return verified(expected, observed)
	}
	if found.NotAfter != nil && found.NotAfter.After(previous.notAfter) {
		return verified(expected, observed+" valid to "+found.NotAfter.Format("2006-01-02"))
	}
	return unverified(expected, observed,
		"the file "+payload.Path+" carries the certificate it carried before the renewal")
}

// verifyLocalAccount reads the account after the change: there with the shell,
// the groups, the expiry, the lock state or the keys ordered, or gone after a
// deletion.
func verifyLocalAccount(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.LocalUser
	if payload == nil || payload.Name == "" {
		return unreadable("a local account", "the order names no account")
	}
	name := payload.Name
	expected := "the account " + name + " as ordered"
	switch in.action {
	case opspec.ActionLocalUserDelete:
		expected = "the account " + name + " gone"
	case opspec.ActionLocalUserLock:
		expected = name + " locked"
	case opspec.ActionLocalUserUnlock:
		expected = name + " unlocked"
	case opspec.ActionLocalUserExpirySet:
		expected = name + " expiring " + firstNonEmpty(payload.ExpiresAt, "never")
	case opspec.ActionLocalUserGroupsSet:
		expected = name + " in " + listOf(payload.Groups)
	case opspec.ActionLocalSSHKeysAdd, opspec.ActionLocalSSHKeysRemove,
		opspec.ActionLocalSSHKeysReplaceAll, opspec.ActionLocalSSHKeysSet:
		expected = "the keys of " + name + " as ordered"
	}
	if readers.account == nil {
		return unreadable(expected, noReader("local accounts"))
	}
	account := readers.account(ctx, name)

	if in.action == opspec.ActionLocalUserDelete {
		if account == nil {
			return verified(expected, "gone")
		}
		return unverified(expected, "present", "the account "+name+" is still on the host after the deletion")
	}
	if account == nil {
		return unverified(expected, "absent", "the account "+name+" is not on the host after the change")
	}

	switch in.action {
	case opspec.ActionLocalUserLock, opspec.ActionLocalUserUnlock:
		if account.Locked == nil {
			return unreadable(expected, firstNonEmpty(account.UnavailableReason,
				"the lock state of "+name+" was not read"))
		}
		locked := *account.Locked
		observed := name + " " + yesNo(locked, "locked", "unlocked")
		if locked == (in.action == opspec.ActionLocalUserLock) {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the account "+name+" is "+observed+" after the change")

	case opspec.ActionLocalUserExpirySet:
		observed := name + " expiring " + firstNonEmpty(account.ExpiresAt, "never")
		if account.UnavailableReason != "" {
			return unreadable(expected, account.UnavailableReason)
		}
		if account.ExpiresAt == payload.ExpiresAt {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the account "+name+" expires "+
			firstNonEmpty(account.ExpiresAt, "never")+" and not "+firstNonEmpty(payload.ExpiresAt, "never"))

	case opspec.ActionLocalUserGroupsSet:
		var missing []string
		for _, group := range payload.Groups {
			if !contains(account.Groups, group) {
				missing = append(missing, group)
			}
		}
		observed := name + " in " + listOf(account.Groups)
		if len(missing) == 0 {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the account "+name+" is not in "+listOf(missing))

	case opspec.ActionLocalSSHKeysAdd, opspec.ActionLocalSSHKeysRemove,
		opspec.ActionLocalSSHKeysReplaceAll, opspec.ActionLocalSSHKeysSet:
		return verifyAccountKeys(in, account, expected)
	}

	// A create: the account with the shell, the groups and the keys of the
	// order.
	observed := name + " present"
	if payload.Shell != "" && account.Shell != "" && account.Shell != payload.Shell {
		return unverified(expected, name+" with the shell "+account.Shell,
			"the account "+name+" has the shell "+account.Shell+" and not "+payload.Shell)
	}
	var missing []string
	for _, group := range payload.Groups {
		if !contains(account.Groups, group) {
			missing = append(missing, group)
		}
	}
	if len(missing) > 0 {
		return unverified(expected, name+" in "+listOf(account.Groups),
			"the account "+name+" is not in "+listOf(missing))
	}
	if len(payload.SSHKeys) > 0 {
		return verifyAccountKeys(in, account, expected)
	}
	return verified(expected, observed)
}

// verifyAccountKeys compares the fingerprints the account carries with the
// keys of the order.
func verifyAccountKeys(in verifyInput, account *LocalAccount, expected string) observation {
	payload := in.payload.LocalUser
	if account.UnavailableReason != "" {
		return unreadable(expected, account.UnavailableReason)
	}
	have := fingerprintsOf(account)

	switch in.action {
	case opspec.ActionLocalSSHKeysRemove:
		var left []string
		for _, fingerprint := range payload.Fingerprints {
			if contains(have, strings.TrimSpace(fingerprint)) {
				left = append(left, shortDigest(strings.TrimSpace(fingerprint)))
			}
		}
		observed := strconv.Itoa(len(have)) + " keys"
		if len(left) == 0 {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the account "+payload.Name+" still carries the keys "+listOf(left))

	case opspec.ActionLocalSSHKeysAdd:
		wanted, err := keyFingerprints(payload.Keys)
		if err != nil {
			return unreadable(expected, "the keys of the order were not read: "+err.Error())
		}
		var missing []string
		for _, fingerprint := range wanted {
			if !contains(have, fingerprint) {
				missing = append(missing, shortDigest(fingerprint))
			}
		}
		observed := strconv.Itoa(len(have)) + " keys"
		if len(missing) == 0 {
			return verified(expected, observed)
		}
		return unverified(expected, observed,
			"the account "+payload.Name+" does not carry the added keys "+listOf(missing))
	}

	// A replace: the account carries exactly the keys of the order.
	wanted, err := keyFingerprints(keyInputsOf(payload.SSHKeys))
	if err != nil {
		return unreadable(expected, "the keys of the order were not read: "+err.Error())
	}
	observed := strconv.Itoa(len(have)) + " keys"
	if sameStrings(have, wanted) {
		return verified(expected, observed)
	}
	return unverified(expected, observed, "the account "+payload.Name+" carries "+
		strconv.Itoa(len(have))+" keys and the order named "+strconv.Itoa(len(wanted)))
}

// keyInputsOf turns the full key list of an order into the form the key
// parser takes.
func keyInputsOf(keys []string) []opspec.SSHKeyInput {
	inputs := make([]opspec.SSHKeyInput, 0, len(keys))
	for _, key := range keys {
		inputs = append(inputs, opspec.SSHKeyInput{PublicKey: key})
	}
	return inputs
}

// keyFingerprints computes the fingerprints of the keys of an order. The
// public keys themselves go no further than this function.
func keyFingerprints(keys []opspec.SSHKeyInput) ([]string, error) {
	fingerprints := make([]string, 0, len(keys))
	for _, key := range keys {
		line, err := accounts.ParseKey(accounts.KeyInput{PublicKey: key.PublicKey, Comment: key.Comment})
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, line.Fingerprint)
	}
	return fingerprints, nil
}

// verifyContainerState reads the container after the change: running,
// stopped or gone as the verb asked.
func verifyContainerState(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.DockerContainer
	if payload == nil || payload.ContainerID == "" {
		return unreadable("a container state", "the order names no container")
	}
	short := shortDigest(payload.ContainerID)
	expected := "container " + short + " running"
	switch in.action {
	case opspec.ActionDockerStop:
		expected = "container " + short + " stopped"
	case opspec.ActionDockerRemove:
		expected = "container " + short + " gone"
	}
	if readers.docker == nil {
		return unreadable(expected, noReader("the container engine"))
	}
	snapshot, err := readers.docker(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.Summary.UnavailableReason != "" {
		return unreadable(expected, snapshot.Summary.UnavailableReason)
	}
	state := ""
	found := false
	for i := range snapshot.Containers {
		if snapshot.Containers[i].ID != payload.ContainerID {
			continue
		}
		found = true
		state = snapshot.Containers[i].State
		break
	}

	if in.action == opspec.ActionDockerRemove {
		if !found {
			return verified(expected, "gone")
		}
		return unverified(expected, firstNonEmpty(state, "present"),
			"the engine still lists the container "+short+" after the removal")
	}
	if !found {
		return unverified(expected, "gone",
			"the engine does not list the container "+short+" after the change")
	}
	observed := "container " + short + " " + firstNonEmpty(state, "unknown")
	running := state == "running" || state == "restarting"
	if (in.action == opspec.ActionDockerStop) == !running {
		return verified(expected, observed)
	}
	return unverified(expected, observed, "the container "+short+" is "+
		firstNonEmpty(state, "unknown")+" after the change")
}

// verifyImagePresent reads whether the engine lists the image pulled.
func verifyImagePresent(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.DockerImage
	if payload == nil || payload.Reference == "" {
		return unreadable("an image", "the order names no image")
	}
	expected := "image " + payload.Reference + " on the host"
	if readers.docker == nil {
		return unreadable(expected, noReader("the container engine"))
	}
	snapshot, err := readers.docker(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.Summary.UnavailableReason != "" {
		return unreadable(expected, snapshot.Summary.UnavailableReason)
	}
	pulled := in.result.GetDockerActionResult().GetImageDigest()
	for i := range snapshot.Images {
		image := snapshot.Images[i]
		for _, tag := range image.Tags {
			if tag == payload.Reference || strings.HasSuffix(tag, "/"+payload.Reference) {
				return verified(expected, "on the host, "+shortDigest(image.ID))
			}
		}
		if pulled == "" {
			continue
		}
		for _, digest := range image.Digests {
			if strings.Contains(digest, pulled) {
				return verified(expected, "on the host, "+shortDigest(pulled))
			}
		}
	}
	return unverified(expected, "absent",
		"the engine does not list the image "+payload.Reference+" after the pull")
}

// verifyComposeServices reads the project after the deployment: every
// service of the plan runs, and from the image digest the plan bound.
func verifyComposeServices(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Compose
	if payload == nil || payload.Project == "" {
		return unreadable("a Compose project", "the order names no project")
	}
	expected := "the services of " + payload.Project + " running"
	if len(payload.ImageDigests) > 0 {
		expected = strconv.Itoa(len(payload.ImageDigests)) + " services of " +
			payload.Project + " running from the bound digests"
	}
	if readers.docker == nil {
		return unreadable(expected, noReader("the container engine"))
	}
	snapshot, err := readers.docker(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.Summary.UnavailableReason != "" {
		return unreadable(expected, snapshot.Summary.UnavailableReason)
	}

	running := map[string]bool{}
	images := map[string]string{}
	digests := map[string]string{}
	for i := range snapshot.Containers {
		container := snapshot.Containers[i]
		if container.Compose == nil || container.Compose.Project != payload.Project {
			continue
		}
		service := container.Compose.Service
		if container.State == "running" || container.State == "restarting" {
			running[service] = true
		} else if _, seen := running[service]; !seen {
			running[service] = false
		}
		images[service] = container.Image
		digests[service] = container.ImageDigest
	}
	if len(running) == 0 {
		return unverified(expected, "no container of the project",
			"the engine lists no container of the project "+payload.Project+" after the deployment")
	}

	var down, other []string
	if len(payload.ImageDigests) > 0 {
		for service, digest := range payload.ImageDigests {
			if !running[service] {
				down = append(down, service)
				continue
			}
			if digest == "" {
				continue
			}
			if !strings.Contains(images[service], digest) && !strings.Contains(digests[service], digest) {
				other = append(other, service)
			}
		}
	} else {
		for service, up := range running {
			if !up {
				down = append(down, service)
			}
		}
	}
	observed := strconv.Itoa(len(running)) + " services, " + strconv.Itoa(len(down)) + " not running"
	if len(down) == 0 && len(other) == 0 {
		return verified(expected, strconv.Itoa(len(running))+" services running")
	}
	if len(down) > 0 {
		return unverified(expected, observed,
			"the services "+listOf(down)+" of the project "+payload.Project+" are not running")
	}
	return unverified(expected, observed,
		"the services "+listOf(other)+" run from another image than the digest the plan bound")
}

// verifyContainerSpec reads the container of a declaration back.
func verifyContainerSpec(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.DockerEnsure
	if payload == nil || payload.Container == nil {
		return unreadable("a declared container", "the order carries no container description")
	}
	name := payload.Container.Name
	spec, err := payload.SpecWithSecrets()
	if err != nil {
		return unreadable("the container "+name+" as declared", err.Error())
	}
	// The digest of the image is what the plan bound on the host, not what the
	// order wrote: the order names a tag, the plan says what that tag meant at
	// that moment, and the container was created from that.
	outcome := declarationOutcome(in.result)
	if outcome.Plan.ImageDigest == "" {
		// Without the digest the plan bound there is nothing to compare the
		// container's mark against, and a comparison against a description with no
		// image would read as a mismatch that is not one.
		return unreadable("the container "+name+" as declared",
			"the host sent back no plan, so the image the container was to run is not known here")
	}
	spec.ImageDigest = outcome.Plan.ImageDigest
	wanted := docker.SpecDigest(spec)

	expected := "the container " + name + " running as declared"
	if spec.Stopped {
		expected = "the container " + name + " stopped as declared"
	}
	if readers.docker == nil {
		return unreadable(expected, noReader("the container engine"))
	}
	snapshot, err := readers.docker(ctx)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if snapshot.Summary.UnavailableReason != "" {
		return unreadable(expected, snapshot.Summary.UnavailableReason)
	}

	var found *docker.Container
	for i := range snapshot.Containers {
		if snapshot.Containers[i].Name == name {
			found = &snapshot.Containers[i]
			break
		}
	}
	if found == nil {
		return unverified(expected, "absent",
			"the engine does not list a container called "+name+" after the change")
	}
	if recorded := found.Labels[docker.LabelSpecDigest]; recorded != wanted {
		return unverified(expected, "container "+shortDigest(found.ID)+", description "+
			firstNonEmpty(shortDigest(recorded), "not declared here"),
			"the container "+name+" was not created from the description that was approved")
	}
	running := found.State == "running" || found.State == "restarting"
	observed := "the container " + name + " " + firstNonEmpty(found.State, "unknown")
	if running == !spec.Stopped {
		return verified(expected, observed)
	}
	return unverified(expected, observed,
		"the container "+name+" is "+firstNonEmpty(found.State, "unknown")+" after the change")
}

// verifyDockerNetwork reads the declared network back: it stands with the
// driver and the address range declared, or it is gone after a removal.
func verifyDockerNetwork(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.DockerEnsure
	name := payload.ObjectName()
	if name == "" {
		return unreadable("a declared network", "the order names no network")
	}
	removal := in.action == opspec.ActionDockerNetworkRemove
	expected := "the network " + name + " as declared"
	if removal {
		expected = "the network " + name + " gone"
	}
	snapshot, problem := readEngine(ctx, readers, expected)
	if problem != nil {
		return *problem
	}

	var found *docker.Network
	for i := range snapshot.Networks {
		if snapshot.Networks[i].Name == name {
			found = &snapshot.Networks[i]
			break
		}
	}
	if removal {
		if found == nil {
			return verified(expected, "gone")
		}
		return unverified(expected, "still on the host",
			"the engine still lists the network "+name+" after the removal")
	}
	if found == nil {
		return unverified(expected, "absent",
			"the engine does not list the network "+name+" after the change")
	}
	declared := payload.Network
	if declared == nil {
		return verified(expected, "on the host, "+shortDigest(found.ID))
	}
	wanted := declared.Normalized()
	observed := found.Driver + ", " + firstNonEmpty(strings.Join(found.Subnets, " "), "no range of its own")
	if found.Driver != wanted.Driver {
		return unverified(expected, observed,
			"the network "+name+" has the driver "+found.Driver+" and not "+wanted.Driver)
	}
	if wanted.Subnet != "" && !containsText(found.Subnets, wanted.Subnet) {
		return unverified(expected, observed,
			"the network "+name+" does not carry the address range "+wanted.Subnet)
	}
	if wanted.IPv6Subnet != "" && !containsText(found.Subnets, wanted.IPv6Subnet) {
		return unverified(expected, observed,
			"the network "+name+" does not carry the address range "+wanted.IPv6Subnet)
	}
	return verified(expected, observed)
}

// verifyDockerVolume reads the declared volume back: it stands with the
// driver declared, or it is gone after a removal.
func verifyDockerVolume(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.DockerEnsure
	name := payload.ObjectName()
	if name == "" {
		return unreadable("a declared volume", "the order names no volume")
	}
	removal := in.action == opspec.ActionDockerVolumeRemove
	expected := "the volume " + name + " as declared"
	if removal {
		expected = "the volume " + name + " gone"
	}
	snapshot, problem := readEngine(ctx, readers, expected)
	if problem != nil {
		return *problem
	}

	var found *docker.Volume
	for i := range snapshot.Volumes {
		if snapshot.Volumes[i].Name == name {
			found = &snapshot.Volumes[i]
			break
		}
	}
	if removal {
		if found == nil {
			return verified(expected, "gone")
		}
		return unverified(expected, "still on the host",
			"the engine still lists the volume "+name+" after the removal")
	}
	if found == nil {
		return unverified(expected, "absent",
			"the engine does not list the volume "+name+" after the change")
	}
	declared := payload.Volume
	if declared == nil {
		return verified(expected, "on the host")
	}
	wanted := declared.Normalized()
	if found.Driver != wanted.Driver {
		return unverified(expected, found.Driver,
			"the volume "+name+" has the driver "+found.Driver+" and not "+wanted.Driver)
	}
	return verified(expected, found.Driver)
}

// readEngine reads the engine state for a verifier, or says why it could not.
func readEngine(ctx context.Context, readers *hostReaders, expected string) (docker.Snapshot, *observation) {
	if readers.docker == nil {
		problem := unreadable(expected, noReader("the container engine"))
		return docker.Snapshot{}, &problem
	}
	snapshot, err := readers.docker(ctx)
	if err != nil {
		problem := unreadable(expected, err.Error())
		return docker.Snapshot{}, &problem
	}
	if snapshot.Summary.UnavailableReason != "" {
		problem := unreadable(expected, snapshot.Summary.UnavailableReason)
		return docker.Snapshot{}, &problem
	}
	return snapshot, nil
}

// declarationOutcome reads what the host reported about the change.
func declarationOutcome(result *agentv1.TaskResult) docker.EnsureResult {
	outcome := docker.EnsureResult{}
	raw := result.GetDockerEnsureResult().GetPayload()
	if len(raw) == 0 {
		return outcome
	}
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return docker.EnsureResult{}
	}
	return outcome
}

// containsText says whether a list carries a value. The engine reports the
// address ranges of a network as a list, and a network may have several.
func containsText(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// verifyBackupRun reads the repository after the run: it has to list a
// snapshot it did not list before.
func verifyBackupRun(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Backup
	expected := "a new snapshot in the repository"
	if payload == nil {
		return unreadable(expected, "the order carries no backup payload")
	}
	if readers.backupState == nil {
		return unreadable(expected, noReader("the backup repository"))
	}
	if in.before == nil || in.before.snapshots == nil {
		reason := "the snapshots before the run were not read"
		if in.before != nil && in.before.snapshotsReason != "" {
			reason += ": " + in.before.snapshotsReason
		}
		return unreadable(expected, reason)
	}
	state, err := readers.backupState(ctx, in.task, payload)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	fresh := 0
	newest := ""
	for _, id := range state.snapshotIDs {
		if !in.before.snapshots[id] {
			fresh++
			newest = id
		}
	}
	observed := strconv.Itoa(len(state.snapshotIDs)) + " snapshots, " + strconv.Itoa(fresh) + " new"
	if fresh > 0 {
		return verified(expected, observed+", newest "+shortDigest(newest))
	}
	return unverified(expected, observed,
		"the repository lists no snapshot the run added: "+observed)
}

// verifyRestoreTarget reads the directory the restore wrote into. It needs
// no context: the read is a directory listing.
func verifyRestoreTarget(readers *hostReaders, in verifyInput) observation {
	payload := in.payload.Backup
	if payload == nil || payload.Target == "" {
		return unreadable("a restore target", "the order names no restore target")
	}
	expected := "files under " + payload.Target
	if readers.directory == nil {
		return unreadable(expected, noReader("directories"))
	}
	exists, entries, err := readers.directory(payload.Target)
	if err != nil {
		// A restore writes as root, often into a directory the agent may not open.
		if counted := in.result.GetBackupResult(); counted.GetTargetRead() {
			exists, entries, err = true, int(counted.GetTargetEntries()), nil
		} else {
			return unreadable(expected, err.Error())
		}
	}
	if !exists {
		return unverified(expected, "no such directory",
			"the restore target "+payload.Target+" is not on the host after the restore")
	}
	observed := strconv.Itoa(entries) + " entries under " + payload.Target
	if entries > 0 {
		return verified(expected, observed)
	}
	return unverified(expected, observed,
		"the restore target "+payload.Target+" is empty after the restore")
}

// verifyDomainMembership reads the host's own configuration and keytab: the
// host is joined to the domain, or has left it.
func verifyDomainMembership(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	domain := ""
	switch {
	case in.payload.DomainEnroll != nil:
		domain = in.payload.DomainEnroll.Domain
	case in.payload.DomainLeave != nil:
		domain = in.payload.DomainLeave.Domain
	}
	leaving := in.action == opspec.ActionDomainLeave
	expected := "joined to " + firstNonEmpty(domain, "the domain")
	if leaving {
		expected = "out of " + firstNonEmpty(domain, "the domain")
	}
	if readers.identity == nil {
		return unreadable(expected, noReader("the identity state of the host"))
	}
	state := readers.identity(ctx)
	if state.UnavailableReason != "" {
		return unreadable(expected, state.UnavailableReason)
	}
	observed := yesNo(state.Enrolled, "joined to "+firstNonEmpty(state.Domain, "a domain"), "not joined")
	if leaving {
		if !state.Enrolled || (domain != "" && !strings.EqualFold(state.Domain, domain)) {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the host is still joined to "+state.Domain)
	}
	if !state.Enrolled {
		return unverified(expected, observed, "the host is not joined to a domain after the enrolment")
	}
	if domain != "" && !strings.EqualFold(state.Domain, domain) {
		return unverified(expected, observed,
			"the host is joined to "+state.Domain+" and not to "+domain)
	}
	// The keytab is root's file, so the agent's own read never sees it: a missing
	// key version here says nothing about the host.
	kvno := state.KeytabKVNO
	if kvno == nil {
		if readers.keytabKVNO == nil {
			return unreadable(expected, noReader("the host keytab"))
		}
		read, err := readers.keytabKVNO(ctx, firstNonEmpty(domain, state.Domain))
		if err != nil {
			return unreadable(expected, "the host keytab was not read: "+err.Error())
		}
		kvno = read
	}
	if kvno == nil {
		return unverified(expected, observed+", no keytab",
			"the host is joined to "+state.Domain+" and carries no host keytab")
	}
	return verified(expected, observed)
}

// verifyKeytab reads the key version number of the host principal: a
// renewal that changed nothing leaves it where it was.
func verifyKeytab(ctx context.Context, readers *hostReaders, in verifyInput) observation {
	expected := "a key version higher than before"
	renewed := in.result.GetKeytabRenewResult()
	if readers.keytabKVNO == nil {
		return unreadable(expected, noReader("the keytab of the host"))
	}
	domain := ""
	if readers.identity != nil {
		domain = readers.identity(ctx).Domain
	}
	if domain == "" && in.payload.Keytab != nil {
		if _, realm, found := strings.Cut(in.payload.Keytab.Principal, "@"); found {
			domain = strings.ToLower(realm)
		}
	}
	if domain == "" {
		return unreadable(expected, "the host did not say which domain it belongs to")
	}
	kvno, err := readers.keytabKVNO(ctx, domain)
	if err != nil {
		return unreadable(expected, err.Error())
	}
	if kvno == nil {
		return unreadable(expected, "the host did not report a key version")
	}
	observed := "kvno " + strconv.FormatUint(uint64(*kvno), 10)
	if after := renewed.GetKvnoAfter(); after > 0 {
		expected = "kvno " + strconv.FormatUint(uint64(after), 10)
		if *kvno == after {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the keytab carries "+observed+" and the renewal reported "+expected)
	}
	if renewed.GetKvnoBeforeKnown() {
		expected = "kvno above " + strconv.FormatUint(uint64(renewed.GetKvnoBefore()), 10)
		if *kvno > renewed.GetKvnoBefore() {
			return verified(expected, observed)
		}
		return unverified(expected, observed, "the keytab still carries "+observed+" after the renewal")
	}
	return unreadable(expected, "the key version before the renewal was not read")
}
