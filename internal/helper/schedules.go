package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/schedules"
)

// The places a managed entry lives in. They are variables so a test can
// point them at a temporary directory; the helper never changes them while
// it runs.
var (
	cronDir = schedules.CronDDir
	unitDir = schedules.SystemdUnitDir
	// systemdMarker exists only under a running systemd. It is the same
	// fact the agent's capability detection reports, so the host writes
	// timers exactly where it announced it could.
	systemdMarker = "/run/systemd/system"
)

// Refusals of a schedule order. They are part of the contract: the panel
// shows the code and the guide says what to do next.
const (
	// ErrorUserRequired means an entry that names no account. Root is not a
	// default here: it is the account that needs a grant of its own.
	ErrorUserRequired = "user_required"
	// ErrorUnknownUser means an account the host does not have, or a name
	// that would not stay in the user field of a cron line.
	ErrorUnknownUser = "unknown_user"
	// ErrorRootGrantRequired means an entry for root ordered without the
	// grant that allows it.
	ErrorRootGrantRequired = "root_grant_required"
	// ErrorUnitNotManaged means a unit file under the name of a managed
	// timer that does not carry the panel's marker. It belongs to the host
	// administrator and the panel neither rewrites nor removes it.
	ErrorUnitNotManaged = "unit_not_managed"
	// ErrorCalendarUnsupported means an expression that cannot become a
	// timer, because cron and systemd disagree on what it means.
	ErrorCalendarUnsupported = "timer_calendar_unsupported"
)

// PermissionScheduleRootExec is the grant a root entry needs on top of the
// right to write schedules. The name repeats the panel's permission: the
// grant travels in the capability under the same name it has in the role.
const PermissionScheduleRootExec = "schedule.root.exec"

// grantsOf returns the grants the capability of a request carries, or nil
// when the request has no capability. A capability without grants is an
// empty list, not nil: it is present and it grants nothing, and a request
// with a capability is judged by what the capability says. The grants are
// under the panel's signature, which the server verified before any
// handler ran, so they are the panel's word and not the agent's.
func grantsOf(request *helperv1.HelperRequest) []string {
	capability := request.GetCapability()
	if capability == nil {
		return nil
	}
	grants := capability.GetGrants()
	if grants == nil {
		return []string{}
	}
	return grants
}

// hasGrant says whether the list names the grant.
func hasGrant(grants []string, wanted string) bool {
	for _, grant := range grants {
		if grant == wanted {
			return true
		}
	}
	return false
}

// checkScheduleUser judges the account an entry is to run as.
//
// This is the ValidateSchedule of the remediation document: the name has to
// fit the user field of a cron line, the account has to exist on this host
// under exactly that name, and root needs its grant. The lookup result is
// compared with the name asked for, because a resolver may answer a lookup
// of one spelling with an account of another - and the line would carry
// the spelling, not the account.
func checkScheduleUser(name string, grants []string) *helperv1.HelperResponse {
	if name == "" {
		return reject(ErrorUserRequired, "the entry names no user; the account it runs as has to be named, root is not a default")
	}
	if !schedules.ValidUser(name) {
		return reject(ErrorUnknownUser, fmt.Sprintf("the user %q is not a valid account name for a scheduled entry", name))
	}
	account, err := user.Lookup(name)
	if err != nil || account.Username != name {
		return reject(ErrorUnknownUser, fmt.Sprintf("the user %q does not exist on this host", name))
	}
	// A request without a capability is judged by the panel alone, as before
	// the capability existed; one with a capability has to carry the grant.
	if name == "root" && grants != nil && !hasGrant(grants, PermissionScheduleRootExec) {
		return reject(ErrorRootGrantRequired, "an entry for root needs the grant "+PermissionScheduleRootExec)
	}
	return nil
}

// checkScheduleCommand refuses what the line composer would not catch: a
// zero byte ends the string for the tools that will read the line.
func checkScheduleCommand(command []string) *helperv1.HelperResponse {
	if len(command) == 0 {
		return reject(ErrorMalformed, "the entry has no command")
	}
	if !filepath.IsAbs(command[0]) {
		return reject(ErrorMalformed, fmt.Sprintf("the command must be an absolute path, is %q", command[0]))
	}
	for _, argument := range command {
		if strings.ContainsRune(argument, 0) {
			return reject(ErrorMalformed, "a command argument contains a zero byte")
		}
	}
	return nil
}

// applySchedule handles recurring jobs.
//
// Managed entries have their own files in /etc/cron.d and stable identifiers.
// An entry found on the host belongs to the host administrator: the panel sees
// it but does not overwrite it without an explicit adoption - otherwise the
// first operation from the panel would erase work nobody entered into the
// panel.
func (s *Server) applySchedule(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	// Cron entries and systemd units share the same host resource: a concurrent
	// write of two entries can leave the directory in an intermediate state. A
	// read takes no guard.
	guard := GuardUnits
	if action.GetOperation() == helperv1.ScheduleRequest_OPERATION_READ {
		guard = ""
	}
	release, busy := s.hold(guard, request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 5*time.Minute, 30*time.Minute)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.ScheduleRequest_OPERATION_READ:
		return scheduleResponse(s.readSchedules(actionCtx), "")

	case helperv1.ScheduleRequest_OPERATION_ENSURE:
		return s.ensureEntry(actionCtx, request, action)

	case helperv1.ScheduleRequest_OPERATION_DISABLE:
		return s.toggleEntry(actionCtx, action)

	case helperv1.ScheduleRequest_OPERATION_REMOVE:
		return s.removeEntry(actionCtx, action.GetId())

	case helperv1.ScheduleRequest_OPERATION_RUN_NOW:
		return s.runNow(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown schedule operation")
}

// ensureEntry creates or updates a managed entry.
//
// The mechanism is decided first, because the rest of the work differs: a
// cron entry is one file in a directory cron reads, a timer is a pair of
// unit files and a word with systemd. Everything before that decision -
// the account, the command - is judged the same way for both, because the
// operator writes the same order either way.
func (s *Server) ensureEntry(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	// The account and the command are judged before anything on the host is
	// read: an order the line composer would turn into something else is
	// refused with its own code, not with a write error.
	if refusal := checkScheduleUser(action.GetUser(), grantsOf(request)); refusal != nil {
		return refusal
	}
	if refusal := checkScheduleCommand(action.GetCommand()); refusal != nil {
		return refusal
	}
	if !schedules.ValidIdentifier(action.GetId()) {
		return reject(ErrorMalformed, fmt.Sprintf("invalid entry identifier %q", action.GetId()))
	}
	mechanism, refusal := chooseMechanism(action.GetKind())
	if refusal != nil {
		return refusal
	}
	entry := schedules.Schedule{
		ID:         action.GetId(),
		Kind:       mechanism,
		Expression: action.GetExpression(),
		Command:    action.GetCommand(),
		User:       action.GetUser(),
		Comment:    action.GetComment(),
		Enabled:    true,
	}
	if mechanism == schedules.KindTimer {
		return s.ensureTimer(ctx, entry)
	}
	return s.ensureCron(ctx, action, entry)
}

// chooseMechanism decides which mechanism a managed entry is written with.
//
// The decision is the one the agent already announces: the module is
// available where the host has /etc/cron.d or systemd, and each of the two
// carries its own kind of entry. An order that names a kind gets that kind
// or a refusal - never the other one quietly - and an order that leaves the
// choice to the host takes cron first, because there one entry is one file
// and nothing has to be reloaded. The chosen mechanism travels back in the
// message, so the operator reads what was written and not merely that
// something was.
func chooseMechanism(kind string) (string, *helperv1.HelperResponse) {
	cron := isDirectory(cronDir)
	timers := isDirectory(systemdMarker)
	switch kind {
	case schedules.KindTimer:
		if !timers {
			return "", reject(ErrorUnsupported,
				"this host does not run systemd, so a managed timer has nowhere to be written")
		}
		return schedules.KindTimer, nil
	case "", schedules.KindCron:
		// An order without a kind is a cron entry, which is what every
		// order meant before timers could be written. A host without the
		// directory is told what it does have.
		if !cron {
			message := "this host has no " + cronDir + " directory, so a managed entry has nowhere to be written"
			if timers {
				message += "; order the entry as a timer, which this host can carry"
			}
			return "", reject(ErrorUnsupported, message)
		}
		return schedules.KindCron, nil
	case schedules.KindAny:
		switch {
		case cron:
			return schedules.KindCron, nil
		case timers:
			return schedules.KindTimer, nil
		}
		return "", reject(ErrorUnsupported,
			"this host has neither "+cronDir+" nor systemd, so a managed entry has nowhere to be written")
	}
	return "", reject(ErrorMalformed, fmt.Sprintf("unknown schedule kind %q", kind))
}

// isDirectory says whether the path is a directory on this host.
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// ensureTimer writes the pair of unit files of a managed timer and tells
// systemd about them.
//
// A timer the panel did not write is never changed: the marker in the file
// decides, exactly as the file name in /etc/cron.d decides there. An order
// that would change nothing changes nothing - the units are not rewritten
// and systemd is not reloaded - so ordering the same entry twice is one
// entry and one reload.
func (s *Server) ensureTimer(ctx context.Context, entry schedules.Schedule) *helperv1.HelperResponse {
	// One entry is one job. An identifier already held by the other
	// mechanism is not quietly moved: the two files would both run the
	// command, and the operator ordered it once.
	if _, err := os.Stat(schedules.EntryPath(cronDir, entry.ID)); err == nil {
		return reject(ErrorUnsupported, "the entry "+entry.ID+" exists on this host as a cron entry ("+
			schedules.EntryPath(cronDir, entry.ID)+"); remove it before writing it as a timer")
	}
	plan, err := schedules.PlanTimer(unitDir, entry)
	switch {
	case errors.Is(err, schedules.ErrTimerNotManaged):
		return reject(ErrorUnitNotManaged, err.Error()+
			"; the panel changes only the timers it wrote, remove that unit by hand to take the name over")
	case errors.Is(err, schedules.ErrCalendarUnsupported):
		return reject(ErrorCalendarUnsupported, err.Error())
	case err != nil:
		return reject(ErrorMalformed, err.Error())
	}

	unit := schedules.TimerUnitName(entry.ID)
	if !plan.Changed && s.unitFileState(ctx, unit) == "enabled" {
		return scheduleResponse(s.readSchedules(ctx),
			"the timer "+entry.ID+" already runs on "+plan.Calendar+"; nothing was written")
	}
	if err := writeUnitPair(plan); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	// systemd reads unit files when it is told to, not when they change: a
	// timer enabled before the reload would be the previous content of the
	// file.
	if output, err := toolOutput(ctx, systemctlPath, "daemon-reload"); err != nil {
		return reject(ErrorExecFailed, "reloading systemd: "+toolFailure(err, output))
	}
	if output, err := toolOutput(ctx, systemctlPath, "enable", "--now", unit); err != nil {
		return reject(ErrorExecFailed, "enabling "+unit+": "+toolFailure(err, output))
	}
	return scheduleResponse(s.readSchedules(ctx),
		"the entry "+entry.ID+" was written as the timer "+unit+" running on "+plan.Calendar)
}

// ensureCron writes a managed entry as a file in /etc/cron.d.
func (s *Server) ensureCron(ctx context.Context, action *helperv1.ScheduleRequest,
	entry schedules.Schedule) *helperv1.HelperResponse {
	// The same rule as the other way round: an identifier already held by
	// a timer of ours is not quietly turned into a cron entry, because for
	// a while both would run the command.
	if present, owned, path := schedules.TimerOwnership(unitDir, entry.ID); present && owned {
		return reject(ErrorUnsupported, "the entry "+entry.ID+" exists on this host as a timer ("+path+
			"); remove it before writing it as a cron entry")
	}
	// An entry with the same identifier may already exist as a found one.
	// Overwriting it without operator consent would erase somebody else's work.
	collision := s.foundEntry(ctx, action.GetId())
	if collision != nil && !action.GetAdopt() {
		return reject(ErrorUnsupported, fmt.Sprintf(
			"an entry with this name already exists on the host (%s, line %d) and does not belong to the panel; "+
				"adopting it needs explicit consent", collision.Path, collision.Line))
	}
	// The adoption has to remove the entry found. Left next to the panel entry
	// it would run the same job a second time - and the operator asked for one.
	if collision != nil && filepath.Dir(collision.Path) != cronDir {
		return reject(ErrorUnsupported, fmt.Sprintf(
			"the entry lies in %s (line %d); the panel does not rewrite that file, "+
				"remove the line there by hand before adopting it", collision.Path, collision.Line))
	}

	if err := schedules.WriteEntry(cronDir, entry); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the entry " + entry.ID + " was written to " + schedules.EntryPath(cronDir, entry.ID)
	if collision != nil {
		if err := os.Remove(collision.Path); err != nil {
			return reject(ErrorExecFailed, "the entry was written, but the adopted "+
				collision.Path+" was not removed: "+err.Error())
		}
		message += "; " + collision.Path + " was adopted and removed"
	}
	return scheduleResponse(s.readSchedules(ctx), message)
}

// toggleEntry enables or disables a managed entry. Disabling leaves the content
// on the host: disabling is not removing.
func (s *Server) toggleEntry(ctx context.Context, action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	current := s.managedEntry(ctx, action.GetId())
	if current == nil {
		return reject(ErrorUnsupported, "the entry "+action.GetId()+" does not belong to the panel")
	}
	current.Enabled = action.GetEnabled()
	state := "disabled"
	if current.Enabled {
		state = "enabled"
	}
	if current.Kind == schedules.KindTimer {
		// A timer is switched off with systemd and not by rewriting its
		// file: the units stay exactly as they are, which is what makes
		// switching it back on the same entry and not a new one.
		unit := schedules.TimerUnitName(current.ID)
		verb := "disable"
		if current.Enabled {
			verb = "enable"
		}
		if output, err := toolOutput(ctx, systemctlPath, verb, "--now", unit); err != nil {
			return reject(ErrorExecFailed, verb+" "+unit+": "+toolFailure(err, output))
		}
		return scheduleResponse(s.readSchedules(ctx), "the timer "+current.ID+" was "+state)
	}
	if err := schedules.WriteEntry(cronDir, *current); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return scheduleResponse(s.readSchedules(ctx), "the entry "+current.ID+" was "+state)
}

// removeEntry takes a managed entry off the host, whichever mechanism it
// was written with.
//
// The order names the entry, not the way it was written, so both places
// are handled: the cron file is deleted, and a unit pair of ours is
// stopped, deleted and forgotten by systemd. A unit without our marker is
// left alone and named in the refusal - the panel removes only what it
// wrote.
func (s *Server) removeEntry(ctx context.Context, id string) *helperv1.HelperResponse {
	if !schedules.ValidIdentifier(id) {
		return reject(ErrorMalformed, fmt.Sprintf("invalid entry identifier %q", id))
	}
	message := "the entry " + id + " was removed"
	present, owned, path := schedules.TimerOwnership(unitDir, id)
	if present && !owned {
		return reject(ErrorUnitNotManaged, "the unit "+path+
			" does not carry the marker of the panel; the panel removes only the timers it wrote")
	}
	if present {
		unit := schedules.TimerUnitName(id)
		// Stopping comes before deleting: a timer whose file is gone while
		// systemd still holds it would keep firing until the next reload.
		if output, err := toolOutput(ctx, systemctlPath, "disable", "--now", unit); err != nil {
			return reject(ErrorExecFailed, "stopping "+unit+": "+toolFailure(err, output))
		}
		if err := schedules.RemoveTimer(unitDir, id); err != nil {
			if errors.Is(err, schedules.ErrTimerNotManaged) {
				return reject(ErrorUnitNotManaged, err.Error())
			}
			return reject(ErrorExecFailed, err.Error())
		}
		if output, err := toolOutput(ctx, systemctlPath, "daemon-reload"); err != nil {
			return reject(ErrorExecFailed, "reloading systemd: "+toolFailure(err, output))
		}
		message += " together with its units"
	}
	if err := schedules.RemoveEntry(cronDir, id); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return scheduleResponse(s.readSchedules(ctx), message)
}

// writeUnitPair puts the two unit files of a managed timer in place.
//
// The write goes the way the files module writes a managed file: into an
// already-opened directory, under a name that cannot be a symlink somebody
// planted in advance, and into place with a rename that either happened or
// did not. systemd reads the directory whenever it is told to, so a file
// written in place could be read half-way - with a timer nobody ordered.
func writeUnitPair(plan schedules.TimerPlan) error {
	dir := filepath.Dir(plan.Timer.Path)
	dirfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dir, err)
	}
	defer unix.Close(dirfd)
	for _, file := range plan.Files {
		if err := writeUnitFile(dirfd, filepath.Base(file.Path), []byte(file.Content)); err != nil {
			return err
		}
	}
	// The directory entries themselves have to survive a power cut: a unit
	// file that is empty after a reboot is a job that quietly stopped
	// running.
	_ = unix.Fsync(dirfd)
	return nil
}

// writeUnitFile stages one file in the opened directory and renames it onto
// its name.
func writeUnitFile(dirfd int, name string, content []byte) error {
	// The staging name carries no unit suffix, so systemd ignores it even
	// if the rename never happens.
	temporary, err := randomStagingName("")
	if err != nil {
		return err
	}
	staged, err := stageNamed(dirfd, temporary, content, 0o644)
	if err != nil {
		return err
	}
	if err := staged.File.Close(); err != nil {
		_ = unix.Unlinkat(dirfd, temporary, 0)
		return err
	}
	if err := unix.Renameat(dirfd, temporary, dirfd, name); err != nil {
		_ = unix.Unlinkat(dirfd, temporary, 0)
		return fmt.Errorf("putting %s in place: %w", name, err)
	}
	return nil
}

// toolFailure joins the error of a tool with what it printed. The exit code
// alone says nothing an operator can act on.
func toolFailure(err error, output string) string {
	if text := strings.TrimSpace(output); text != "" {
		return err.Error() + ": " + text
	}
	return err.Error()
}

// runNow executes the command of an entry outside its schedule.
//
// Only the command of a managed entry is run: an entry found on the host is
// sometimes a shell line the panel does not split into arguments, and running
// it through a shell would be exactly what this module avoids.
func (s *Server) runNow(ctx context.Context, action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	entry := s.managedEntry(ctx, action.GetId())
	if entry == nil {
		return reject(ErrorUnsupported, "the entry "+action.GetId()+" does not belong to the panel")
	}
	if len(entry.Command) == 0 {
		return reject(ErrorMalformed, "the entry has no command")
	}

	cmd := entryCommand(ctx, entry)
	output, err := cmd.CombinedOutput()
	message := strings.TrimSpace(string(output))
	if len(message) > 4000 {
		message = message[len(message)-4000:]
	}
	if err != nil {
		response := reject(ErrorExecFailed, err.Error())
		response.ScheduleResult = &helperv1.ScheduleResult{Message: message}
		return response
	}
	return scheduleResponse(s.readSchedules(ctx),
		"the entry "+entry.ID+" was run; "+message)
}

// entryCommand assembles the execution of the entry's command.
//
// Running it by hand is to give the same result as running it from the
// schedule. The helper runs with PrivateTmp=yes, so a command started as its
// child process sees a different /tmp than the same command started by cron -
// and then "Run now" would check something other than what happens at night. A
// transient systemd unit goes back to the host namespaces and, on the way,
// gives the execution its own control group and a trace in the journal.
func entryCommand(ctx context.Context, entry *schedules.Schedule) *exec.Cmd {
	environment := []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	systemdRunPath, err := exec.LookPath("systemd-run")
	if err != nil {
		// A host without systemd has no PrivateTmp for the helper either, so a
		// direct execution is equivalent here.
		cmd := exec.CommandContext(ctx, entry.Command[0], entry.Command[1:]...)
		cmd.Env = environment
		return cmd
	}
	arguments := []string{"--collect", "--wait", "--pipe", "--quiet",
		"--unit=flotestro-schedule-" + entry.ID,
		"--description=Flotestro: " + entry.ID}
	if entry.User != "" {
		arguments = append(arguments, "--uid="+entry.User)
	}
	arguments = append(arguments, "--")
	arguments = append(arguments, entry.Command...)
	cmd := exec.CommandContext(ctx, systemdRunPath, arguments...)
	cmd.Env = environment
	return cmd
}

// readSchedules assembles the picture of the recurring jobs of the host.
func (s *Server) readSchedules(ctx context.Context) schedules.Snapshot {
	now := time.Now()
	snapshot := schedules.Snapshot{
		Schedules: schedules.ReadCron(schedules.CrontabPath, cronDir, now),
		// The zone comes from the host configuration and not from the name
		// time.Local: the latter is always "Local" and tells the operator
		// nothing.
		Timezone: schedules.HostTimezone(),
	}
	timers := schedules.ReadTimers(
		systemctlOutput(ctx, "list-timers", "--all", "--no-pager", "--no-legend"),
		systemctlOutput(ctx, "list-units", "--type=timer", "--all", "--no-pager", "--no-legend", "--plain"),
		systemctlOutput(ctx, "show", "--property=Id", "--property=TimersCalendar", "*.timer"))
	// The timers the panel wrote are read from their files: they say which
	// entry a unit is, what it runs and as whom, which systemd's lists do
	// not. systemd is still asked whether they are installed, because that
	// is its answer to give.
	managed := schedules.ReadManagedTimers(unitDir)
	timers = schedules.MergeManagedTimers(timers, managed, s.unitFileStates(ctx, managed))
	attachTimerRuns(ctx, timers)
	snapshot.Schedules = append(snapshot.Schedules, timers...)
	return snapshot
}

// unitFileStates asks systemd whether the timers of the panel are
// installed.
//
// The units are named one by one rather than by a pattern: a pattern
// matches what systemd has loaded, and a disabled timer usually is not
// loaded - it would disappear from the list exactly when the operator
// wants to switch it back on.
func (s *Server) unitFileStates(ctx context.Context, entries []schedules.Schedule) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	arguments := []string{"show", "--property=Id", "--property=UnitFileState"}
	for _, entry := range entries {
		arguments = append(arguments, schedules.TimerUnitName(entry.ID))
	}
	return parseUnitFileStates(systemctlOutput(ctx, arguments...))
}

// unitFileState asks about one unit. An unknown state is an empty string:
// a unit systemd could not answer for is not an enabled one, and it is not
// a disabled one either.
func (s *Server) unitFileState(ctx context.Context, unit string) string {
	return parseUnitFileStates(systemctlOutput(ctx,
		"show", "--property=Id", "--property=UnitFileState", unit))[unit]
}

// parseUnitFileStates reads the records of "systemctl show". Records are
// separated by an empty line and the order of the properties inside a
// record is not the order they were asked in, so a record is read whole
// before it is filed.
func parseUnitFileStates(output string) map[string]string {
	states := map[string]string{}
	for _, record := range strings.Split(output, "\n\n") {
		name, state := "", ""
		for _, line := range strings.Split(record, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "Id="):
				name = strings.TrimPrefix(line, "Id=")
			case strings.HasPrefix(line, "UnitFileState="):
				state = strings.TrimPrefix(line, "UnitFileState=")
			}
		}
		if name != "" && state != "" {
			states[name] = state
		}
	}
	return states
}

// attachTimerRuns adds the coming runs of the timers with a calendar
// expression.
//
// systemd computes them itself: its calendar language is richer than
// cron's and the module does not reimplement it. One call covers every
// expression, so a host with many timers does not start a process for
// each; a timer whose expression the tool refuses simply keeps the single
// date the timer list gave it.
func attachTimerRuns(ctx context.Context, timers []schedules.Schedule) {
	var specs []string
	seen := map[string]bool{}
	for _, timer := range timers {
		spec := timerCalendar(timer)
		if spec == "" || !timer.Enabled || seen[spec] {
			continue
		}
		seen[spec] = true
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		return
	}
	runs := calendarRuns(ctx, specs)
	if len(runs) < len(specs) {
		// The tool stops at the first specification it refuses and the ones
		// after it go unanswered. They are asked one by one, so a single
		// odd timer does not hide the runs of every timer listed behind it.
		for _, spec := range specs {
			if _, answered := runs[spec]; answered {
				continue
			}
			for key, dates := range calendarRuns(ctx, []string{spec}) {
				runs[key] = dates
			}
		}
	}
	for i := range timers {
		// A disabled timer has no next run and must not be given one, even
		// when an enabled timer elsewhere runs on the same expression.
		if !timers[i].Enabled {
			continue
		}
		dates := runs[timerCalendar(timers[i])]
		if len(dates) == 0 {
			continue
		}
		timers[i].NextRuns = dates
		if timers[i].NextRun == nil {
			// A timer systemd has not loaded is missing from the timer
			// list and so has no elapse time there; its calendar still
			// says when it fires.
			first := dates[0]
			timers[i].NextRun = &first
		}
	}
}

// timerCalendar is the expression systemd computes the runs from. A timer
// the panel wrote carries the cron expression it was ordered with as well,
// and systemd knows nothing of that language.
func timerCalendar(entry schedules.Schedule) string {
	if entry.Calendar != "" {
		return entry.Calendar
	}
	return entry.Expression
}

// calendarRuns asks systemd for the coming runs of the given
// specifications. A bad specification makes the tool exit non-zero after
// printing the good ones before it; the output is read either way.
func calendarRuns(ctx context.Context, specs []string) map[string][]time.Time {
	arguments := append([]string{"calendar", "--iterations=" + strconv.Itoa(schedules.PreviewRuns)}, specs...)
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-analyze", arguments...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, _ := cmd.Output()
	return schedules.ParseCalendarPreview(string(output), time.Local)
}

func (s *Server) managedEntry(ctx context.Context, id string) *schedules.Schedule {
	for _, entry := range s.readSchedules(ctx).Schedules {
		if entry.Source == schedules.SourceManaged && entry.ID == id {
			found := entry
			return &found
		}
	}
	return nil
}

func (s *Server) foundEntry(ctx context.Context, id string) *schedules.Schedule {
	for _, entry := range s.readSchedules(ctx).Schedules {
		// A collision is a file with exactly this name in /etc/cron.d or an
		// entry in /etc/crontab with the same name. A comparison by a fragment
		// of the path would take "backup" for a collision with "db-backup-old".
		if entry.Source != schedules.SourceManaged && entry.Kind == schedules.KindCron &&
			filepath.Base(entry.Path) == id {
			found := entry
			return &found
		}
	}
	return nil
}

// systemctlOutput runs systemctl with a fixed set of arguments.
func systemctlOutput(ctx context.Context, args ...string) string {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func scheduleResponse(snapshot schedules.Snapshot, message string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		ScheduleResult: &helperv1.ScheduleResult{Snapshot: encoded, Message: message},
	}
}
