package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/schedules"
)

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
	// write of two entries can leave the directory in an intermediate state.
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "another unit operation is in flight")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.ScheduleRequest_OPERATION_READ:
		return scheduleResponse(s.readSchedules(actionCtx), "")

	case helperv1.ScheduleRequest_OPERATION_ENSURE:
		return s.ensureEntry(actionCtx, action)

	case helperv1.ScheduleRequest_OPERATION_DISABLE:
		return s.toggleEntry(actionCtx, action)

	case helperv1.ScheduleRequest_OPERATION_REMOVE:
		if err := schedules.UsunWpis(schedules.KatalogCronD, action.GetId()); err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		return scheduleResponse(s.readSchedules(actionCtx),
			"the entry "+action.GetId()+" was removed")

	case helperv1.ScheduleRequest_OPERATION_RUN_NOW:
		return s.runNow(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown schedule operation")
}

// ensureEntry creates or updates a managed entry.
func (s *Server) ensureEntry(ctx context.Context, action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
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
	if collision != nil && filepath.Dir(collision.Path) != schedules.KatalogCronD {
		return reject(ErrorUnsupported, fmt.Sprintf(
			"the entry lies in %s (line %d); the panel does not rewrite that file, "+
				"remove the line there by hand before adopting it", collision.Path, collision.Line))
	}

	entry := schedules.Schedule{
		ID:         action.GetId(),
		Expression: action.GetExpression(),
		Command:    action.GetCommand(),
		User:       action.GetUser(),
		Comment:    action.GetComment(),
		Enabled:    true,
	}
	if err := schedules.ZapiszWpis(schedules.KatalogCronD, entry); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the entry " + entry.ID + " was written"
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
	if err := schedules.ZapiszWpis(schedules.KatalogCronD, *current); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	state := "disabled"
	if current.Enabled {
		state = "enabled"
	}
	return scheduleResponse(s.readSchedules(ctx), "the entry "+current.ID+" was "+state)
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
		Schedules: schedules.CzytajCron(schedules.SciezkaCrontabu, schedules.KatalogCronD, now),
		// The zone comes from the host configuration and not from the name
		// time.Local: the latter is always "Local" and tells the operator
		// nothing.
		Timezone: schedules.StrefaHosta(),
	}
	snapshot.Schedules = append(snapshot.Schedules,
		schedules.CzytajTimery(
			systemctlOutput(ctx, "list-timers", "--all", "--no-pager", "--no-legend"),
			systemctlOutput(ctx, "list-units", "--type=timer", "--all", "--no-pager", "--no-legend", "--plain"),
			systemctlOutput(ctx, "show", "--property=Id", "--property=TimersCalendar", "*.timer"))...)
	return snapshot
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
