package schedules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The cron entries directory and the prefix of the files belonging to the
// panel.
//
// One file per entry, not a shared file with many lines: thanks to that a
// change of one schedule does not rewrite the others, and removal is
// deleting a file, not editing a line inside somebody else's content.
const (
	CronDDir    = "/etc/cron.d"
	FilePrefix  = "flotestro-"
	FileHeader  = "# Managed by Flotestro. Manual changes will not survive the next operation."
	CrontabPath = "/etc/crontab"
)

// entryIdentifier allows names that can be part of a file name in
// /etc/cron.d. Cron skips files with a dot and other special characters, so
// an entry with a bad name would silently never run.
//
// The character set is the one cron allows: letters, digits, underscore and
// hyphen. A narrower set would make it impossible to take over a found
// entry with a name like "e2scrub_all" - and exactly those stand on hosts.
var entryIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// ValidIdentifier checks the name of a managed entry.
func ValidIdentifier(id string) bool {
	return entryIdentifier.MatchString(id)
}

// EntryPath returns the file of a managed entry.
func EntryPath(dir, id string) string {
	return filepath.Join(dir, FilePrefix+id)
}

// ReadCron gathers the cron entries from /etc/crontab and /etc/cron.d.
//
// User entries are not read in this module: they live in the spool
// directory, belong to specific accounts and reading them is a separate
// privacy decision.
func ReadCron(crontab, dir string, now time.Time) []Schedule {
	var entries []Schedule
	entries = append(entries, readCronFile(crontab, true, now)...)

	files, err := os.ReadDir(dir)
	if err != nil {
		return entries
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		names = append(names, file.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		entries = append(entries, readCronFile(filepath.Join(dir, name), true, now)...)
	}
	return entries
}

// readCronFile parses one file. withUser distinguishes the /etc/crontab
// and /etc/cron.d format - there the user name follows the fifth field -
// from a user crontab, where it is absent.
func readCronFile(path string, withUser bool, now time.Time) []Schedule {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	managed := strings.HasPrefix(filepath.Base(path), FilePrefix)
	identifier := strings.TrimPrefix(filepath.Base(path), FilePrefix)

	var entries []Schedule
	scanner := bufio.NewScanner(file)
	number := 0
	var comment string
	for scanner.Scan() {
		number++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// A disabled entry is commented out, not deleted: disabling is not
		// removal and the content is meant to survive.
		disabled := strings.HasPrefix(line, "#@")
		if disabled {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#@"))
		} else if strings.HasPrefix(line, "#") {
			// A comment is attributed only to our own entries: in somebody
			// else's file the line above an entry is usually a format header
			// or a note about something else, and shown next to the entry it
			// would look like its description.
			if managed && line != FileHeader {
				comment = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			}
			continue
		}
		// Environment variable assignments are not a schedule.
		if !strings.HasPrefix(line, "@") && strings.Contains(strings.Fields(line)[0], "=") {
			continue
		}

		entry, ok := parseCronLine(line, withUser)
		if !ok {
			continue
		}
		entry.Path = path
		entry.Line = number
		entry.Enabled = !disabled
		entry.Comment = comment
		comment = ""
		if managed {
			entry.Source = SourceManaged
			entry.ID = identifier
			// The panel wrote its own entry itself, so it knows the line is
			// an argument list and may show it as such.
			entry.Command = strings.Fields(entry.CommandLine)
		} else {
			entry.Source = SourceManual
			entry.ID = fmt.Sprintf("%s:%d", path, number)
		}
		// The date is computed only for active entries: a disabled entry
		// has no next run and giving one would be false.
		if entry.Enabled {
			if expression, err := ParseExpression(entry.Expression); err == nil {
				if dates := expression.NextRuns(now, 1); len(dates) > 0 {
					date := dates[0]
					entry.NextRun = &date
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// parseCronLine separates the expression, the user and the command.
func parseCronLine(line string, withUser bool) (Schedule, bool) {
	fields := strings.Fields(line)
	expressionFields := cronFields
	if strings.HasPrefix(line, "@") {
		expressionFields = 1
	}
	minimum := expressionFields + 1
	if withUser {
		minimum++
	}
	if len(fields) < minimum {
		return Schedule{}, false
	}

	entry := Schedule{
		Kind:       KindCron,
		Expression: strings.Join(fields[:expressionFields], " "),
	}
	rest := fields[expressionFields:]
	if withUser {
		entry.User = rest[0]
		rest = rest[1:]
	}
	entry.CommandLine = strings.Join(rest, " ")
	return entry, true
}

// WriteEntry writes a managed entry.
//
// The write is atomic: the file is created next to the target and replaces
// the previous one only when complete. Cron reads the directory at any
// moment, so a file written in place could be read half-way - with an entry
// nobody ordered.
func WriteEntry(dir string, entry Schedule) error {
	if !ValidIdentifier(entry.ID) {
		return fmt.Errorf("invalid entry identifier %q", entry.ID)
	}
	if _, err := ParseExpression(entry.Expression); err != nil {
		return err
	}
	command, err := ComposeCommand(entry.Command)
	if err != nil {
		return err
	}
	user := entry.User
	if user == "" {
		user = "root"
	}

	prefix := ""
	if !entry.Enabled {
		prefix = "#@"
	}
	content := FileHeader + "\n"
	if entry.Comment != "" {
		content += "# " + strings.ReplaceAll(entry.Comment, "\n", " ") + "\n"
	}
	content += fmt.Sprintf("%s%s %s %s\n", prefix, entry.Expression, user, command)

	target := EntryPath(dir, entry.ID)
	temporary := target + ".new"
	if err := os.WriteFile(temporary, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, target)
}

// RemoveEntry deletes the file of a managed entry.
func RemoveEntry(dir, id string) error {
	if !ValidIdentifier(id) {
		return fmt.Errorf("invalid entry identifier %q", id)
	}
	err := os.Remove(EntryPath(dir, id))
	if os.IsNotExist(err) {
		// An entry that does not exist is the target state of a removal.
		return nil
	}
	return err
}

// shellCharacters are disallowed in command arguments.
//
// Cron runs the command through a shell, so an argument with a
// metacharacter stops being an argument and becomes a second command. The
// basic module does not accept an arbitrary shell line - the command is an
// argument array.
const shellCharacters = "|&;<>()$`\\\"'\n\r\t*?[]{}~!#"

// ComposeCommand assembles the arguments into a line for cron.
func ComposeCommand(arguments []string) (string, error) {
	if len(arguments) == 0 {
		return "", fmt.Errorf("the command is empty")
	}
	if !strings.HasPrefix(arguments[0], "/") {
		// A relative path depends on cron's PATH, which is often different
		// from the operator's PATH. An entry working by hand and not from
		// cron is the hardest failure to diagnose in this module.
		return "", fmt.Errorf("the command must be an absolute path, is %q", arguments[0])
	}
	for _, argument := range arguments {
		if argument == "" {
			return "", fmt.Errorf("empty command argument")
		}
		if strings.ContainsAny(argument, shellCharacters) {
			return "", fmt.Errorf("the argument %q contains a shell character", argument)
		}
		// The percent sign has its own meaning in cron: it ends the command
		// and starts the standard input.
		if strings.Contains(argument, "%") {
			return "", fmt.Errorf("the argument %q contains a percent sign", argument)
		}
	}
	return strings.Join(arguments, " "), nil
}

// HostTimezone returns the host time zone.
//
// The zone name comes from the system configuration, not from time.Local:
// the latter is always called "Local" and does not answer at what time the
// entry really runs. An undetermined zone stays empty - "UTC" written just
// in case would be guessing.
func HostTimezone() string {
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" {
			return name
		}
	}
	target, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	const zoneDir = "/usr/share/zoneinfo/"
	if index := strings.Index(target, zoneDir); index >= 0 {
		return target[index+len(zoneDir):]
	}
	return ""
}
