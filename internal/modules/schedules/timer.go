package schedules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The unit directory of a managed timer and the markers that make a unit pair
// ours.
const (
	SystemdUnitDir = "/etc/systemd/system"
	// MarkerEntry repeats the identifier inside the file, so a pair that
	// was renamed by hand is still recognisable as ours.
	MarkerEntry = "# Flotestro-Entry: "
	// MarkerCron holds the expression the operator ordered.
	MarkerCron = "# Flotestro-Cron: "
	// MarkerComment carries the operator's note: a unit file has no field
	// for it that survives a rewrite.
	MarkerComment = "# Flotestro-Comment: "
)

// ErrTimerNotManaged says that a unit file with the name of a managed timer
// exists on the host without the panel's marker.
var ErrTimerNotManaged = errors.New("the unit file does not carry the marker of the panel")

// ErrCalendarUnsupported says that a cron expression has no equivalent timer.
var ErrCalendarUnsupported = errors.New("the expression cannot be written as a timer")

// UnitPrefix is the namespace of a managed entry's units.
const UnitPrefix = FilePrefix + "entry-"

// The directories systemd reads units from, in the order it prefers them.
var unitSearchDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// TimerUnitName and ServiceUnitName are the two units of a managed entry.
func TimerUnitName(id string) string   { return UnitPrefix + id + ".timer" }
func ServiceUnitName(id string) string { return UnitPrefix + id + ".service" }

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
	// Present says whether the pair is already on the host, Changed whether
	// writing it would change anything.
	Present bool `json:"present"`
	Changed bool `json:"changed"`
	Read    bool `json:"read"`
}

// RenderTimer turns an entry into the pair of unit files, without touching the
// host.
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
		// The unit is named in full rather than left to the implicit pairing by file
		// name: a rename by hand then fails loudly instead of quietly starting
		// something else.
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
func PlanTimer(dir string, entry Schedule) (TimerPlan, error) {
	plan, err := RenderTimer(dir, entry)
	if err != nil {
		return TimerPlan{}, err
	}
	plan.Read = true
	for _, file := range plan.Files {
		// A unit of that name somewhere else on the host is the dangerous case:
		// writing ours into /etc/systemd/system would not collide with it, it would
		// shadow it, and the unit the host really runs would be gone at the next.
		if shadowed, err := shadowingUnit(filepath.Base(file.Path), file.Path); err != nil {
			return TimerPlan{}, err
		} else if shadowed != "" {
			return TimerPlan{}, fmt.Errorf("%w: %s would shadow %s",
				ErrTimerNotManaged, file.Path, shadowed)
		}
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

// shadowingUnit names a unit file of the same name in another of systemd's
// directories, when that file is not one of ours.
func shadowingUnit(name, writing string) (string, error) {
	for _, dir := range unitSearchDirs {
		path := filepath.Join(dir, name)
		if path == writing {
			continue
		}
		content, err := os.ReadFile(path)
		switch {
		case os.IsNotExist(err):
			continue
		case err != nil:
			// A unit that cannot be read is not thereby absent: refusing here is the
			// fail-closed answer, because writing would be the irreversible one.
			return "", fmt.Errorf("reading %s: %w", path, err)
		}
		if !ours(string(content)) {
			return path, nil
		}
	}
	return "", nil
}

// RemoveTimer deletes the pair of a managed timer.
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
// exists on the host and whether it is ours.
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
func ReadManagedTimers(dir string) []Schedule {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		name := file.Name()
		if file.IsDir() || !strings.HasPrefix(name, UnitPrefix) || !strings.HasSuffix(name, ".timer") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var entries []Schedule
	for _, name := range names {
		id := strings.TrimSuffix(strings.TrimPrefix(name, UnitPrefix), ".timer")
		if !ValidIdentifier(id) {
			continue
		}
		timer, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !ours(string(timer)) {
			// A unit that does not carry our marker belongs to the host administrator;
			// it is read with the other timers, from systemd, as a found entry.
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
		// The entry reads back in the language it was ordered in.
		entry.Expression = markerOf(string(timer), MarkerCron)
		if entry.Expression == "" {
			entry.Expression = entry.Calendar
		}
		service, err := os.ReadFile(ServiceUnitPath(dir, id))
		if err != nil || !ours(string(service)) {
			// A timer without its service runs nothing.
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

// MergeManagedTimers puts the entries the panel wrote into the list read from
// systemd.
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
		// The unit file state is the durable answer: a timer is enabled when it is
		// installed, whether or not it happens to be loaded at this moment.
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

// CalendarFromCron turns a cron expression into the OnCalendar expression of a
// timer.
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

// component renders one component of the calendar expression: an asterisk when
// every value is allowed, otherwise the values themselves.
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
