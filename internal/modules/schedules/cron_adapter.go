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
const (
	CronDDir    = "/etc/cron.d"
	FilePrefix  = "flotestro-"
	FileHeader  = "# Managed by Flotestro. Manual changes will not survive the next operation."
	CrontabPath = "/etc/crontab"
)

// entryIdentifier allows names that can be part of a file name in /etc/cron.
// d.
var entryIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// ValidIdentifier checks the name of a managed entry.
func ValidIdentifier(id string) bool {
	return entryIdentifier.MatchString(id)
}

// userName allows the account names a cron line can carry safely. The user
// stands between the expression and the command in a /etc/cron.
var userName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidUser checks the name of the account an entry runs as.
func ValidUser(name string) bool {
	return userName.MatchString(name)
}

// EntryPath returns the file of a managed entry.
func EntryPath(dir, id string) string {
	return filepath.Join(dir, FilePrefix+id)
}

// ReadCron gathers the cron entries from /etc/crontab and /etc/cron. d.
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

// readCronFile parses one file. withUser distinguishes the /etc/crontab and
// /etc/cron.
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
			// A comment is attributed only to our own entries: in somebody else's file
			// the line above an entry is usually a format header or a note about
			// something else, and shown next to the entry it would look like its
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
				if dates := expression.NextRuns(now, PreviewRuns); len(dates) > 0 {
					date := dates[0]
					entry.NextRun = &date
					entry.NextRuns = dates
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

// WriteEntry writes a managed entry. The write is atomic: the file is created
// next to the target and replaces the previous one only when complete.
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
	// An entry without a user is not an entry for root: the account is a decision
	// of the operator, and root is the one that needs a grant of its own.
	if entry.User == "" {
		return fmt.Errorf("the entry has no user; the account it runs as has to be named")
	}
	if !ValidUser(entry.User) {
		return fmt.Errorf("invalid user name %q", entry.User)
	}
	user := entry.User

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
const shellCharacters = "|&;<>()$`\\\"'\n\r\t*?[]{}~!#"

// ComposeCommand assembles the arguments into a line for cron.
func ComposeCommand(arguments []string) (string, error) {
	if len(arguments) == 0 {
		return "", fmt.Errorf("the command is empty")
	}
	if !strings.HasPrefix(arguments[0], "/") {
		// A relative path depends on cron's PATH, which is often different from the
		// operator's PATH.
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

// HostTimezone returns the host time zone. The zone name comes from the system
// configuration, not from time.
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
