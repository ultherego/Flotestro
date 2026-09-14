package sudoers

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// MainFile is the file every read starts from, relative to the root of
// the file system the parser was given.
const MainFile = "etc/sudoers"

// maxFiles bounds the include walk. A policy is a handful of files; a
// walk that goes further is a loop the visited set did not catch or a
// directory somebody pointed at by mistake.
const maxFiles = 256

// ParseSystem reads the policy of the host the process runs on. Only root
// can open the files, so this is the helper's call.
func ParseSystem(root fs.FS, now time.Time) Snapshot {
	return Parse(root, MainFile, now)
}

// Parse reads the policy starting at the given file. The file system is
// rooted at "/": the includes name absolute paths and are resolved
// against it, so a test can hand the parser a tree of its own.
func Parse(root fs.FS, main string, now time.Time) Snapshot {
	snapshot := Snapshot{Rules: []Rule{}, Defaults: []Default{}, Files: []File{}, ObservedAt: now.UTC()}
	reader := &reader{root: root, visited: map[string]bool{}}
	lines := reader.walk(main, "")
	snapshot.Files = reader.files
	snapshot.Problems = reader.problems

	if len(reader.files) > 0 && reader.files[0].Reason != "" {
		// The main file was not read: nothing below it is known, and the
		// drop-ins the main file would have included are unknown too.
		snapshot.UnavailableReason = reader.files[0].Reason
		return snapshot
	}

	aliases := collectAliases(lines, &snapshot)
	for _, line := range lines {
		text := line.text
		switch {
		case isAliasLine(text):
			// Already taken in the first pass.
		case strings.HasPrefix(text, "Defaults"):
			snapshot.Defaults = append(snapshot.Defaults, parseDefaults(line))
		default:
			rules, err := parseUserSpec(line, aliases)
			if err != nil {
				snapshot.Problems = append(snapshot.Problems, Problem{
					Source: line.source, Line: line.number, Text: text, Reason: err.Error(),
				})
				continue
			}
			snapshot.Rules = append(snapshot.Rules, rules...)
		}
	}
	return snapshot
}

// logicalLine is one statement after the continuation lines are joined
// and the comments removed, with where it came from.
type logicalLine struct {
	source string
	number int
	text   string
}

// reader walks the files. It keeps what it opened, so a drop-in it could
// not read shows in the picture with its reason.
type reader struct {
	root     fs.FS
	visited  map[string]bool
	files    []File
	problems []Problem
}

// walk reads one file and, in order, the files it includes at the place of
// the include directive - that is where sudo puts them, and the order
// decides which Defaults win.
func (r *reader) walk(file, includedFrom string) []logicalLine {
	display := "/" + strings.TrimPrefix(file, "/")
	if r.visited[file] || len(r.files) >= maxFiles {
		return nil
	}
	r.visited[file] = true

	content, err := fs.ReadFile(r.root, strings.TrimPrefix(file, "/"))
	if err != nil {
		r.files = append(r.files, File{Path: display, IncludedFrom: includedFrom, Reason: describe(err)})
		return nil
	}
	entry := File{Path: display, IncludedFrom: includedFrom}
	index := len(r.files)
	r.files = append(r.files, entry)

	var lines []logicalLine
	raw := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	r.files[index].Lines = len(raw)
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		r.files[index].Lines--
	}
	for number := 0; number < len(raw); number++ {
		start := number + 1
		text := raw[number]
		// A trailing backslash continues the statement on the next line.
		for strings.HasSuffix(text, "\\") && number+1 < len(raw) {
			number++
			text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(raw[number])
		}
		text = stripComment(strings.TrimSpace(text))
		if text == "" {
			continue
		}
		if target, directory, ok := includeDirective(text); ok {
			lines = append(lines, r.include(target, directory, file, display, start)...)
			continue
		}
		lines = append(lines, logicalLine{source: display, number: start, text: text})
	}
	return lines
}

// include resolves one include directive. A relative path is relative to
// the directory of the including file, as sudo resolves it; "%h" in the
// name stands for the hostname, which the parser does not know, so such a
// directive is reported rather than guessed.
func (r *reader) include(target string, directory bool, from, display string, line int) []logicalLine {
	if strings.Contains(target, "%h") {
		r.problems = append(r.problems, Problem{
			Source: display, Line: line, Text: target,
			Reason: "the include names the host with %h, which the parser cannot resolve",
		})
		return nil
	}
	if !strings.HasPrefix(target, "/") {
		target = path.Join(path.Dir("/"+strings.TrimPrefix(from, "/")), target)
	}
	target = strings.TrimPrefix(path.Clean(target), "/")
	if !directory {
		return r.walk(target, display)
	}
	entries, err := fs.ReadDir(r.root, target)
	if err != nil {
		r.files = append(r.files, File{Path: "/" + target, IncludedFrom: display, Reason: describe(err)})
		return nil
	}
	// The files of a directory go in lexical order, the order sudo reads
	// them in. A name with a dot or a trailing tilde is an editor's or a
	// package manager's leftover and sudo skips it.
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	var lines []logicalLine
	for _, name := range names {
		lines = append(lines, r.walk(target+"/"+name, display)...)
	}
	return lines
}

// includeDirective recognises the four include forms: the old "#include"
// and the "@include" of sudo 1.9, each with a directory variant.
func includeDirective(text string) (target string, directory bool, ok bool) {
	for _, form := range []struct {
		prefix    string
		directory bool
	}{
		{"#includedir", true}, {"@includedir", true}, {"#include", false}, {"@include", false},
	} {
		if !strings.HasPrefix(text, form.prefix) {
			continue
		}
		rest := text[len(form.prefix):]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			// "#included" or "#includes" is a comment, not a directive.
			continue
		}
		if comment := strings.Index(rest, " #"); comment >= 0 {
			rest = rest[:comment]
		}
		rest = strings.Trim(strings.TrimSpace(rest), `"`)
		if rest == "" {
			return "", false, false
		}
		return rest, form.directory, true
	}
	return "", false, false
}

// stripComment removes a comment from a line. A "#" starts a comment
// unless it starts a uid ("#1000") or an include; a comment inside a
// statement follows whitespace.
func stripComment(text string) string {
	if strings.HasPrefix(text, "#") {
		if _, _, ok := includeDirective(text); ok {
			return text
		}
		// "#1000 ALL=..." is a uid at the start of a user specification and
		// stays; anything else after the hash is a comment.
		if len(text) < 2 || text[1] < '0' || text[1] > '9' {
			return ""
		}
	}
	for index := 1; index < len(text); index++ {
		if text[index] != '#' {
			continue
		}
		before := text[index-1]
		if before != ' ' && before != '\t' && before != ',' {
			continue
		}
		if index+1 < len(text) && text[index+1] >= '0' && text[index+1] <= '9' {
			// "#1000" inside a list is a uid or a gid.
			continue
		}
		return strings.TrimSpace(text[:index])
	}
	return text
}

// The alias kinds and their keyword.
const (
	aliasUser  = "User_Alias"
	aliasRunas = "Runas_Alias"
	aliasHost  = "Host_Alias"
	aliasCmnd  = "Cmnd_Alias"
)

// aliasTable keeps the alias definitions of every kind.
type aliasTable map[string]map[string][]string

// aliasKind returns the keyword an alias line starts with, or empty.
func aliasKind(text string) string {
	for _, kind := range []string{aliasUser, aliasRunas, aliasHost, aliasCmnd} {
		if strings.HasPrefix(text, kind+" ") || strings.HasPrefix(text, kind+"\t") {
			return kind
		}
	}
	return ""
}

func isAliasLine(text string) bool { return aliasKind(text) != "" }

// collectAliases reads every alias definition before the rules are read:
// sudo resolves aliases when it matches, so a definition below its use is
// as good as one above it.
func collectAliases(lines []logicalLine, snapshot *Snapshot) aliasTable {
	table := aliasTable{aliasUser: {}, aliasRunas: {}, aliasHost: {}, aliasCmnd: {}}
	for _, line := range lines {
		kind := aliasKind(line.text)
		if kind == "" {
			continue
		}
		rest := strings.TrimSpace(line.text[len(kind):])
		// Several aliases of one kind may share a line, separated by ":".
		for _, definition := range splitTopLevel(rest, ':') {
			name, members, found := strings.Cut(definition, "=")
			name = strings.TrimSpace(name)
			if !found || !aliasName.MatchString(name) {
				snapshot.Problems = append(snapshot.Problems, Problem{
					Source: line.source, Line: line.number, Text: line.text,
					Reason: "the alias definition has no name or no '='",
				})
				continue
			}
			table[kind][name] = splitList(members)
		}
	}
	return table
}

// aliasName is the shape of an alias name: capitals, digits and
// underscores, starting with a capital. ALL has the shape but is not an
// alias.
var aliasName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// resolve expands the aliases of one kind in a list. A negated alias
// negates each of its members; a cycle stops at the name that repeats.
func (t aliasTable) resolve(kind string, items []string) []string {
	var result []string
	var expand func(item string, seen map[string]bool)
	expand = func(item string, seen map[string]bool) {
		negated := strings.HasPrefix(item, "!")
		name := strings.TrimLeft(item, "!")
		members, isAlias := t[kind][name]
		if !isAlias || name == "ALL" || seen[name] {
			result = append(result, item)
			return
		}
		seen[name] = true
		for _, member := range members {
			if negated {
				member = "!" + member
			}
			expand(member, seen)
		}
		delete(seen, name)
	}
	for _, item := range items {
		expand(item, map[string]bool{})
	}
	return result
}

// parseDefaults reads one Defaults line. The scope character right after
// the keyword says whom the line concerns.
func parseDefaults(line logicalLine) Default {
	entry := Default{Source: line.source, Line: line.number, Text: line.text, Params: []string{}}
	rest := strings.TrimPrefix(line.text, "Defaults")
	if rest != "" {
		switch rest[0] {
		case '@':
			entry.Scope = "host"
		case ':':
			entry.Scope = "user"
		case '!':
			entry.Scope = "command"
		case '>':
			entry.Scope = "runas"
		}
	}
	if entry.Scope != "" {
		rest = strings.TrimSpace(rest[1:])
		if end := strings.IndexAny(rest, " \t"); end >= 0 {
			entry.Target, rest = rest[:end], rest[end:]
		} else {
			entry.Target, rest = rest, ""
		}
	}
	for _, param := range splitTopLevel(strings.TrimSpace(rest), ',') {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		entry.Params = append(entry.Params, param)
		compact := strings.ReplaceAll(param, " ", "")
		if compact == "!authenticate" || compact == "authenticate=false" {
			entry.DisablesAuthentication = true
		}
	}
	return entry
}

// listSeparator normalises the whitespace around the commas of a list, so
// that "alice, bob" and "alice,bob" split the same way.
var listSeparator = regexp.MustCompile(`\s*,\s*`)

// hostSection marks the start of another host section in a user
// specification: " : hosts = ...".
var hostSection = regexp.MustCompile(`\s:\s+([^\s=()]+)\s*=`)

// tagPrefix is one tag in front of a command.
var tagPrefix = regexp.MustCompile(`^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT):\s*`)

// optionPrefix is one option in front of a command: "TIMEOUT=5m", "CWD=/".
var optionPrefix = regexp.MustCompile(`^(TIMEOUT|ROLE|TYPE|CWD|CHROOT|NOTBEFORE|NOTAFTER|APPARMOR_PROFILE)=(\S+)\s*`)

// parseUserSpec reads one user specification into rules.
func parseUserSpec(line logicalLine, aliases aliasTable) ([]Rule, error) {
	left, right, found := strings.Cut(line.text, "=")
	if !found {
		return nil, errors.New("the line is neither a rule, a Defaults line nor an alias")
	}
	fields := strings.Fields(listSeparator.ReplaceAllString(left, ","))
	if len(fields) < 2 {
		return nil, errors.New("the rule names no host list before '='")
	}
	users := aliases.resolve(aliasUser, splitList(strings.Join(fields[:len(fields)-1], ",")))
	hosts := aliases.resolve(aliasHost, splitList(fields[len(fields)-1]))

	// The command side may hold several host sections; each is its own
	// list of grants with its own run-as and tags.
	type section struct {
		hosts    []string
		commands string
	}
	sections := []section{{hosts: hosts}}
	rest := right
	for {
		match := hostSection.FindStringSubmatchIndex(rest)
		if match == nil {
			sections[len(sections)-1].commands = rest
			break
		}
		sections[len(sections)-1].commands = rest[:match[0]]
		sections = append(sections, section{hosts: aliases.resolve(aliasHost, splitList(rest[match[2]:match[3]]))})
		rest = rest[match[1]:]
	}

	var rules []Rule
	for _, part := range sections {
		if strings.TrimSpace(part.commands) == "" {
			return nil, errors.New("the rule grants no command")
		}
		grants, err := parseCommandList(part.commands, aliases)
		if err != nil {
			return nil, err
		}
		for _, grant := range grants {
			rule := Rule{
				Users: users, Hosts: part.hosts,
				RunAs: grant.runAs, RunAsGroups: grant.runAsGroups, RunAsSelf: grant.runAsSelf,
				Commands: grant.commands, Tags: grant.tags, NoPasswd: grant.noPasswd,
				Source: line.source, Line: line.number, Text: line.text,
			}
			rule.judge()
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// grant is a run of commands sharing one run-as and one set of tags.
type grant struct {
	runAs, runAsGroups []string
	// runAsSelf marks a "(:group)" specification: the command runs as the
	// invoking user with another group, not as root.
	runAsSelf bool
	tags      []string
	noPasswd  bool
	commands  []string
}

func (g grant) sameTerms(other grant) bool {
	return equalLists(g.runAs, other.runAs) && equalLists(g.runAsGroups, other.runAsGroups) &&
		g.runAsSelf == other.runAsSelf && equalLists(g.tags, other.tags) && g.noPasswd == other.noPasswd
}

// parseCommandList reads a Cmnd_Spec_List. A run-as and the tags stay in
// force for the commands after them until changed - that is sudo's rule,
// and the reason "(ALL) NOPASSWD: ALL, /bin/ls" makes both passwordless.
func parseCommandList(text string, aliases aliasTable) ([]grant, error) {
	var grants []grant
	current := grant{}
	for _, item := range splitTopLevel(text, ',') {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "(") {
			end := strings.Index(item, ")")
			if end < 0 {
				return nil, errors.New("the run-as specification has no closing parenthesis")
			}
			runAs, groups, _ := strings.Cut(item[1:end], ":")
			current.runAs = aliases.resolve(aliasRunas, splitList(runAs))
			current.runAsGroups = aliases.resolve(aliasRunas, splitList(groups))
			current.runAsSelf = len(current.runAs) == 0 && len(current.runAsGroups) > 0
			item = strings.TrimSpace(item[end+1:])
		}
		for {
			if match := optionPrefix.FindStringSubmatch(item); match != nil {
				current.tags = appendUnique(current.tags, match[1]+"="+match[2])
				item = item[len(match[0]):]
				continue
			}
			match := tagPrefix.FindStringSubmatch(item)
			if match == nil {
				break
			}
			current = current.withTag(match[1])
			item = item[len(match[0]):]
		}
		if item == "" {
			return nil, errors.New("a command specification names no command")
		}
		commands := aliases.resolve(aliasCmnd, []string{item})
		if len(grants) > 0 && grants[len(grants)-1].sameTerms(current) {
			grants[len(grants)-1].commands = append(grants[len(grants)-1].commands, commands...)
			continue
		}
		next := current
		next.commands = commands
		next.tags = slices.Clone(current.tags)
		grants = append(grants, next)
	}
	if len(grants) == 0 {
		return nil, errors.New("the rule grants no command")
	}
	return grants, nil
}

// withTag applies one tag. NOPASSWD and PASSWD set the password flag; the
// other pairs add or remove their tag.
func (g grant) withTag(tag string) grant {
	result := g
	result.tags = slices.Clone(g.tags)
	switch tag {
	case "NOPASSWD":
		result.noPasswd = true
	case "PASSWD":
		result.noPasswd = false
	case "EXEC", "NOSETENV", "NOLOG_INPUT", "NOLOG_OUTPUT", "NOMAIL", "NOFOLLOW", "NOINTERCEPT":
		result.tags = slices.DeleteFunc(result.tags, func(existing string) bool {
			return existing == strings.TrimPrefix(tag, "NO") || (tag == "EXEC" && existing == "NOEXEC")
		})
	default:
		result.tags = appendUnique(result.tags, tag)
	}
	return result
}

// splitTopLevel splits on a separator outside parentheses and quotes, and
// honours a backslash before the separator.
func splitTopLevel(text string, separator byte) []string {
	var parts []string
	depth := 0
	quoted := false
	start := 0
	for index := 0; index < len(text); index++ {
		switch char := text[index]; {
		case char == '\\' && index+1 < len(text):
			index++
		case char == '"':
			quoted = !quoted
		case quoted:
		case char == '(':
			depth++
		case char == ')':
			if depth > 0 {
				depth--
			}
		case char == separator && depth == 0:
			parts = append(parts, text[start:index])
			start = index + 1
		}
	}
	parts = append(parts, text[start:])
	return parts
}

// splitList splits a comma-separated list of names.
func splitList(text string) []string {
	var items []string
	for _, item := range splitTopLevel(text, ',') {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func equalLists(a, b []string) bool {
	return slices.Equal(a, b)
}

func appendUnique(list []string, item string) []string {
	if slices.Contains(list, item) {
		return list
	}
	return append(list, item)
}

// describe turns a read error into a reason with the path in it: the
// operator sees which drop-in was refused.
func describe(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		switch {
		case errors.Is(err, fs.ErrPermission):
			return "permission denied reading /" + pathErr.Path
		case errors.Is(err, fs.ErrNotExist):
			return "/" + pathErr.Path + " does not exist"
		}
		return "/" + pathErr.Path + ": " + pathErr.Err.Error()
	}
	return err.Error()
}
