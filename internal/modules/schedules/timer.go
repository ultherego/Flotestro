package schedules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The unit directory of a managed timer and the markers that make a unit
// pair ours.
//
// A managed timer is two files: the timer that says when, and the service
// that says what. They carry the same header as a managed cron file, so
// ownership is read from the content and not from the name alone - a host
// administrator may write a file called flotestro-something too, and the
// panel must not take that for its own work.
const (
	SystemdUnitDir = "/etc/systemd/system"
	// MarkerEntry repeats the identifier inside the file, so a pair that
	// was renamed by hand is still recognisable as ours.
	MarkerEntry = "# Flotestro-Entry: "
	// MarkerCron holds the expression the operator ordered. The unit runs
	// on the calendar expression below it; the cron line is what the panel
	// was asked for, and the entry comes back described in the language it
	// was written in.
	MarkerCron = "# Flotestro-Cron: "
	// MarkerComment carries the operator's note: a unit file has no field
	// for it that survives a rewrite.
	MarkerComment = "# Flotestro-Comment: "
)

// ErrTimerNotManaged says that a unit file with the name of a managed timer
// exists on the host without the panel's marker. It belongs to the host
// administrator and the panel neither rewrites nor removes it.
var ErrTimerNotManaged = errors.New("the unit file does not carry the marker of the panel")

// ErrCalendarUnsupported says that a cron expression has no equivalent
// timer. Cron runs a job when the day of the month or the day of the week
// matches; systemd runs it only when both do. An expression that restricts
// both means two different things on the two mechanisms, so it is written
// as neither by accident.
var ErrCalendarUnsupported = errors.New("the expression cannot be written as a timer")

// TimerUnitName and ServiceUnitName are the two units of a managed entry.
func TimerUnitName(id string) string   { return FilePrefix + id + ".timer" }
func ServiceUnitName(id string) string { return FilePrefix + id + ".service" }

// TimerUnitPath and ServiceUnitPath place those units in a directory.
func TimerUnitPath(dir, id string) string   { return filepath.Join(dir, TimerUnitName(id)) }
func ServiceUnitPath(dir, id string) string { return filepath.Join(dir, ServiceUnitName(id)) }

// UnitFile is one file of the pair: where it goes and what is in it. The
// plan shows both before anything is written.
type UnitFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// TimerPlan is what a managed timer would be on the host.
//
// The plan is computed from the order alone, so the panel can show it
// before the operation runs; the helper computes the same plan once more
// under the resource guard and compares it with the files on the host.
type TimerPlan struct {
	ID string `json:"id"`
	// Calendar is the OnCalendar expression systemd will run by, derived
	// from the cron expression the operator wrote.
	Calendar string `json:"calendar"`
	// Expression is that cron expression, kept so the entry reads back in
	// the language it was ordered in.
	Expression string     `json:"expression"`
	Timer      UnitFile   `json:"timer"`
	Service    UnitFile   `json:"service"`
	Files      []UnitFile `json:"files"`
	// Present says whether the pair is already on the host, Changed
	// whether writing it would change anything. Both are filled only by
	// the plan computed on the host; a plan made without reading the disk
	// leaves them false and says so by Read being false.
	Present bool `json:"present"`
	Changed bool `json:"changed"`
	Read    bool `json:"read"`
}

// RenderTimer turns an entry into the pair of unit files, without touching
// the host.
//
// The command goes through the same composer a cron line goes through:
// systemd reads quotes and percent specifiers of its own, so an argument
// that would not be one argument in a cron line is not one here either.
// The rules being identical means an entry can be ordered as either
// mechanism without the operator learning a second grammar.
func RenderTimer(dir string, entry Schedule) (TimerPlan, error) {
	if !ValidIdentifier(entry.ID) {
		return TimerPlan{}, fmt.Errorf("invalid entry identifier %q", entry.ID)
	}
	calendar, err := CalendarFromCron(entry.Expression)
	if err != nil {
		return TimerPlan{}, err
	}
	command, err := ComposeCommand(entry.Command)
	if err != nil {
		return TimerPlan{}, err
	}
	if entry.User == "" {
		return TimerPlan{}, fmt.Errorf("the entry has no user; the account it runs as has to be named")
	}
	if !ValidUser(entry.User) {
		return TimerPlan{}, fmt.Errorf("invalid user name %q", entry.User)
	}
	comment := singleLine(entry.Comment)
	expression := strings.TrimSpace(entry.Expression)

	header := FileHeader + "\n" + MarkerEntry + entry.ID + "\n"
	timer := header + MarkerCron + expression + "\n"
	service := header
	if comment != "" {
		timer += MarkerComment + comment + "\n"
		service += MarkerComment + comment + "\n"
	}
	description := "Description=Flotestro schedule " + entry.ID
	if comment != "" {
		description += " - " + comment
	}
	timer += "\n[Unit]\n" + description + "\n\n[Timer]\n" +
		"OnCalendar=" + calendar + "\n" +
		// The unit is named in full rather than left to the implicit
		// pairing by file name: a rename by hand then fails loudly instead
		// of quietly starting something else.
		"Unit=" + ServiceUnitName(entry.ID) + "\n\n" +
		"[Install]\nWantedBy=timers.target\n"
	service += "\n[Unit]\n" + description + "\n\n[Service]\nType=oneshot\n" +
		"User=" + entry.User + "\n" +
		"ExecStart=" + command + "\n"

	plan := TimerPlan{
		ID:         entry.ID,
		Calendar:   calendar,
		Expression: expression,
		Timer:      UnitFile{Path: TimerUnitPath(dir, entry.ID), Content: timer},
		Service:    UnitFile{Path: ServiceUnitPath(dir, entry.ID), Content: service},
	}
	plan.Files = []UnitFile{plan.Timer, plan.Service}
	return plan, nil
}

// PlanTimer renders the pair and compares it with what lies on the host.
//
// A file already there without our marker stops the plan: it is somebody
// else's unit under a name we would use, and the panel does not rewrite
// work nobody entered into it.
func PlanTimer(dir string, entry Schedule) (TimerPlan, error) {
	plan, err := RenderTimer(dir, entry)
	if err != nil {
		return TimerPlan{}, err
	}
	plan.Read = true
	for _, file := range plan.Files {
		current, err := os.ReadFile(file.Path)
		switch {
		case os.IsNotExist(err):
			plan.Changed = true
			continue
		case err != nil:
			return TimerPlan{}, err
		}
		if !ours(string(current)) {
			return TimerPlan{}, fmt.Errorf("%w: %s", ErrTimerNotManaged, file.Path)
		}
		plan.Present = true
		if string(current) != file.Content {
			plan.Changed = true
		}
	}
	return plan, nil
}

// RemoveTimer deletes the pair of a managed timer. A file without our
// marker is left where it is, and the removal says so rather than deleting
// somebody else's unit.
func RemoveTimer(dir, id string) error {
	if !ValidIdentifier(id) {
		return fmt.Errorf("invalid entry identifier %q", id)
	}
	for _, path := range []string{TimerUnitPath(dir, id), ServiceUnitPath(dir, id)} {
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			// A file that is not there is the target state of a removal.
			continue
		}
		if err != nil {
			return err
		}
		if !ours(string(content)) {
			return fmt.Errorf("%w: %s", ErrTimerNotManaged, path)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// TimerOwnership says whether a unit pair under the name of a managed entry
// exists on the host and whether it is ours. A pair that is not ours is
// reported as present and not owned, so the refusal can name it.
func TimerOwnership(dir, id string) (present, owned bool, path string) {
	owned = true
	for _, candidate := range []string{TimerUnitPath(dir, id), ServiceUnitPath(dir, id)} {
		content, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		present = true
		if !ours(string(content)) {
			return true, false, candidate
		}
		if path == "" {
			path = candidate
		}
	}
	return present, present && owned, path
}

// ReadManagedTimers reads the entries the panel keeps as systemd timers.
//
// The state of the units - enabled, next run - is not here: that is a fact
// of systemd and the caller asks systemd for it. This is what the files
// say: which entry, on what expression, running what, as whom.
func ReadManagedTimers(dir string) []Schedule {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		name := file.Name()
		if file.IsDir() || !strings.HasPrefix(name, FilePrefix) || !strings.HasSuffix(name, ".timer") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var entries []Schedule
	for _, name := range names {
		id := strings.TrimSuffix(strings.TrimPrefix(name, FilePrefix), ".timer")
		if !ValidIdentifier(id) {
			continue
		}
		timer, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !ours(string(timer)) {
			// A unit that does not carry our marker belongs to the host
			// administrator; it is read with the other timers, from
			// systemd, as a found entry.
			continue
		}
		entry := Schedule{
			ID:       id,
			Kind:     KindTimer,
			Source:   SourceManaged,
			Calendar: settingOf(string(timer), "OnCalendar"),
			Comment:  markerOf(string(timer), MarkerComment),
			Path:     TimerUnitPath(dir, id),
		}
		// The entry reads back in the language it was ordered in. A pair
		// written by a version that did not keep the cron line shows the
		// calendar expression instead of inventing one.
		entry.Expression = markerOf(string(timer), MarkerCron)
		if entry.Expression == "" {
			entry.Expression = entry.Calendar
		}
		service, err := os.ReadFile(ServiceUnitPath(dir, id))
		if err != nil || !ours(string(service)) {
			// A timer without its service runs nothing. It is still ours
			// and still shown: the operator has to see the half a removal
			// left behind, not an entry that looks complete.
			entry.CommandLine = ""
		} else {
			entry.CommandLine = settingOf(string(service), "ExecStart")
			entry.Command = strings.Fields(entry.CommandLine)
			entry.User = settingOf(string(service), "User")
		}
		entries = append(entries, entry)
	}
	return entries
}

// MergeManagedTimers puts the entries the panel wrote into the list read
// from systemd.
//
// The two readings say different things about one timer: the files say
// which entry it is, what it runs and as whom, systemd says whether it is
// enabled and when it fires next. The merge takes each from the side that
// knows it. A managed timer systemd has not loaded - a disabled one, most
// of the time - is still in the result: an entry that disappears from the
// list when it is switched off cannot be switched back on.
//
// fileStates maps a unit name to its UnitFileState as systemctl reports it;
// a unit missing from it keeps whatever the timer list said about it.
func MergeManagedTimers(found, managed []Schedule, fileStates map[string]string) []Schedule {
	if len(managed) == 0 {
		return found
	}
	byUnit := map[string]int{}
	for i, entry := range found {
		if entry.Kind == KindTimer {
			byUnit[entry.ID] = i
		}
	}
	taken := map[int]bool{}
	merged := make([]Schedule, 0, len(found)+len(managed))
	for _, entry := range managed {
		unit := TimerUnitName(entry.ID)
		if index, ok := byUnit[unit]; ok {
			taken[index] = true
			entry.Enabled = found[index].Enabled
			entry.NextRun = found[index].NextRun
			entry.NextRuns = found[index].NextRuns
		}
		// The unit file state is the durable answer: a timer is enabled
		// when it is installed, whether or not it happens to be loaded at
		// this moment.
		if state, ok := fileStates[unit]; ok {
			entry.Enabled = state == "enabled"
		}
		merged = append(merged, entry)
	}
	for i, entry := range found {
		if !taken[i] {
			merged = append(merged, entry)
		}
	}
	return merged
}

// ours says whether a unit file carries the panel's header.
func ours(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == FileHeader {
			return true
		}
	}
	return false
}

// markerOf reads the value of one of our comment markers.
func markerOf(content, marker string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, marker) {
			return strings.TrimSpace(strings.TrimPrefix(line, marker))
		}
	}
	return ""
}

// settingOf reads a unit setting. The first assignment wins, as in a file
// the panel wrote itself; a file with several of them is not one of ours.
func settingOf(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		}
	}
	return ""
}

// singleLine folds a comment into one line: a newline would end the marker
// and start something the file never meant to say.
func singleLine(text string) string {
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	return strings.TrimSpace(text)
}

// weekdayNames are the day names systemd reads, in the order cron numbers
// them.
var weekdayNames = [7]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// CalendarFromCron turns a cron expression into the OnCalendar expression
// of a timer.
//
// The panel keeps one schedule language: the operator writes cron, the
// preview and the next runs are computed from it, and a timer is written
// from the same text. Translating is not always possible - cron runs a job
// when the day of month OR the day of week matches, systemd when both do -
// so an expression that restricts both is refused here rather than written
// as a timer that runs on other days than the operator read.
func CalendarFromCron(expression string) (string, error) {
	parsed, err := ParseExpression(expression)
	if err != nil {
		return "", err
	}
	return parsed.Calendar()
}

// Calendar renders the parsed expression as OnCalendar.
func (e Expression) Calendar() (string, error) {
	if !e.dayOfMonthStar && !e.dayOfWeekStar {
		return "", fmt.Errorf("%w: it names both a day of the month and a day of the week, "+
			"which cron reads as either and a timer as both", ErrCalendarUnsupported)
	}
	minute := component(e.values(0), ranges[0].min, ranges[0].max)
	hour := component(e.values(1), ranges[1].min, ranges[1].max)
	day := component(e.values(2), ranges[2].min, ranges[2].max)
	month := component(e.values(3), ranges[3].min, ranges[3].max)

	calendar := "*-" + month + "-" + day + " " + hour + ":" + minute + ":00"
	if e.dayOfWeekStar {
		return calendar, nil
	}
	var days []string
	seen := [7]bool{}
	for _, value := range e.values(4) {
		// Sunday has two numbers in cron and one name in systemd.
		day := value % 7
		if seen[day] {
			continue
		}
		seen[day] = true
		days = append(days, weekdayNames[day])
	}
	if len(days) == 0 || len(days) == 7 {
		return calendar, nil
	}
	return strings.Join(days, ",") + " " + calendar, nil
}

// values returns the allowed values of a field, in order.
func (e Expression) values(field int) []int {
	list := make([]int, 0, len(e.allowed[field]))
	for value := range e.allowed[field] {
		list = append(list, value)
	}
	sort.Ints(list)
	return list
}

// component renders one component of the calendar expression: an asterisk
// when every value is allowed, otherwise the values themselves. A list is
// written out rather than turned back into a step, because systemd's step
// counts from the start of the range and cron's from the first value - the
// two do not always mean the same set.
func component(values []int, min, max int) string {
	if len(values) >= max-min+1 {
		return "*"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%02d", value))
	}
	return strings.Join(parts, ",")
}
