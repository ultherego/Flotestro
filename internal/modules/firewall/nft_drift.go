package firewall

import (
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// SystemctlPath points at systemd's control tool. The path is fixed, not
// searched in PATH: the helper runs only known binaries.
const SystemctlPath = "/usr/bin/systemctl"

// NftUnitName is the unit that restores the ruleset at boot. What it loads is
// read from the unit, because the distributions do not agree on that path.
const NftUnitName = "nftables.service"

// nftIncludeDir is where nft looks for an include written without a
// directory. The directory of the including file is tried first.
const nftIncludeDir = "/etc/nftables"

// nftMaxIncludeDepth stops a file that includes itself.
const nftMaxIncludeDepth = 8

// The reasons an nftables host does not agree with what it restores at boot.
// A rule is either in both views or it is a fact the operator has to know
const (
	// DriftNftNotPersisted: the kernel filters with a rule the boot source does
	// not carry, so the rule is gone after the next reboot.
	DriftNftNotPersisted = "nft_rule_not_persisted"
	// DriftNftNotLoaded: the boot source carries a rule the kernel does not
	// have.
	DriftNftNotLoaded = "nft_rule_not_loaded"
	// DriftNftNotComparable: the rule is written with a variable or a name the
	// two views do not share, so neither side can be said to hold it.
	DriftNftNotComparable = "nft_rule_not_comparable"
	// DriftNftSourceUnreadable: the host names the file it restores from and
	// the file could not be read.
	DriftNftSourceUnreadable = "nft_persistent_source_unreadable"
	// DriftNftSourceUnknown: the host does not say what restores its ruleset at
	// boot, so there is nothing to compare the running rules with.
	DriftNftSourceUnknown = "nft_persistent_source_unknown"
	// DriftNftSourceInactive: the file is there and nothing loads it at boot.
	DriftNftSourceInactive = "nft_persistent_source_inactive"
)

// NftUnit is what systemd says about the unit that loads the ruleset.
type NftUnit struct {
	Name string `json:"name,omitempty"`
	// LoadState says whether the unit exists on this host at all.
	LoadState string `json:"load_state,omitempty"`
	// BootState is systemd's own word for whether the unit runs at boot -
	// enabled, disabled, masked, static - repeated here and judged in the panel.
	BootState string `json:"boot_state,omitempty"`
	// Files are the paths the command line of the unit hands to nft, in its
	// order.
	Files []string `json:"files,omitempty"`
}

// NftPersistence is what the host restores its nftables ruleset from at the
// next boot, and whether the running rules could be compared with it.
type NftPersistence struct {
	Unit NftUnit `json:"unit"`
	// Files are the paths actually read, the includes among them, in reading
	// order.
	Files []string `json:"files,omitempty"`
	// Compared says whether the two views were compared at all. False carries a
	// Reason: not compared is unknown, and unknown is never agreement.
	Compared bool `json:"compared"`
	// Reason is the stable code saying why they were not.
	Reason string `json:"reason,omitempty"`
	// Detail says what that means for the host, in one sentence.
	Detail string `json:"detail,omitempty"`
}

// NftUnitArguments asks systemd what this host restores its ruleset from.
func NftUnitArguments() []string {
	return []string{SystemctlPath, "show", "--no-pager",
		"--property=LoadState", "--property=UnitFileState", "--property=ExecStart",
		NftUnitName}
}

var (
	nftUnitArgv = regexp.MustCompile(`argv\[\]=([^;}]*)`)
	nftVariable = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`)
	nftDefine   = regexp.MustCompile(`^define\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)
	nftIncludes = regexp.MustCompile(`^include\s+"([^"]+)"`)
)

// ParseNftUnit reads the answer of "systemctl show".
func ParseNftUnit(output string) NftUnit {
	unit := NftUnit{Name: NftUnitName}
	for _, raw := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(raw), "=")
		if !found {
			continue
		}
		switch key {
		case "LoadState":
			unit.LoadState = value
		case "UnitFileState":
			unit.BootState = value
		case "ExecStart":
			unit.Files = append(unit.Files, nftLoadedFiles(value)...)
		}
	}
	return unit
}

// nftLoadedFiles reads the files an ExecStart hands to nft. systemd prints the
// command line either as a record with argv[] inside it or plainly.
func nftLoadedFiles(value string) []string {
	command := value
	if fields := nftUnitArgv.FindStringSubmatch(value); fields != nil {
		command = fields[1]
	}
	arguments := strings.Fields(command)
	var files []string
	for i, argument := range arguments {
		if argument != "-f" && argument != "--file" || i+1 >= len(arguments) {
			continue
		}
		// "nft -f -" carries the ruleset in the unit itself, not in a file.
		if file := arguments[i+1]; file != "-" {
			files = append(files, file)
		}
	}
	return files
}

// NftPersistentState compares the ruleset the kernel filters with against the
// source the host restores at boot. It reads nothing but the files the unit
func NftPersistentState(unit NftUnit, root fs.FS, running []Rule) (NftPersistence, []Drift) {
	state := NftPersistence{Unit: unit}
	switch {
	case unit.LoadState != "loaded":
		return nftNotCompared(state, DriftNftSourceUnknown,
			"this host has no "+NftUnitName+", so nothing says what would restore its rules "+
				"after a reboot and a rule in force now may be gone then")
	case len(unit.Files) == 0:
		return nftNotCompared(state, DriftNftSourceUnknown,
			"the unit "+NftUnitName+" hands nft no file, so what it would restore at boot cannot be read")
	case unit.BootState == "disabled" || unit.BootState == "masked":
		state.Files = unit.Files
		return nftNotCompared(state, DriftNftSourceInactive,
			"the unit "+NftUnitName+" is "+unit.BootState+", so nothing loads "+
				strings.Join(unit.Files, ", ")+" and no rule in force now survives a reboot")
	}

	content, files, missing := ReadNftSource(root, unit.Files)
	state.Files = files
	if missing != "" {
		return nftNotCompared(state, DriftNftSourceUnreadable,
			"the ruleset is restored from "+missing+" and that file could not be read, "+
				"so there is nothing to compare the running rules with")
	}
	filed, understood := NftFileRules(content)
	if !understood {
		return nftNotCompared(state, DriftNftNotComparable,
			"the boot source holds a construct this panel does not read, so a rule missing from it "+
				"would not mean the kernel is the only place that has it")
	}
	state.Compared = true
	return state, NftDrift(NftComparableRules(filed), NftComparableRules(running))
}

// nftNotCompared records why the two views were not compared: the answer is
// the reason itself, never silence.
func nftNotCompared(state NftPersistence, reason, detail string) (NftPersistence, []Drift) {
	state.Reason = reason
	state.Detail = detail
	return state, []Drift{{Reason: reason, Detail: detail}}
}

// NftComparableRules picks the rules the boot source is answerable for. A
// foreign table - docker, firewalld, iptables-nft - is written by its owner at
func NftComparableRules(rules []Rule) []Rule {
	own := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Source != SourceForeign {
			own = append(own, rule)
		}
	}
	return own
}

// NftDrift compares what the host restores at boot with what the kernel
// filters with now. The two views are matched as multisets: two identical
func NftDrift(filed, loaded []Rule) []Drift {
	var drift []Drift
	filedKeys, filedUnreadable := nftKeys(filed,
		"the boot source writes this rule in a notation the kernel does not use, "+
			"so the panel cannot say whether it is loaded", &drift)
	loadedKeys, _ := nftKeys(loaded,
		"the kernel holds this rule in a notation the boot source does not use, "+
			"so the panel cannot say whether it is kept", &drift)

	remaining := nftCounts(loadedKeys)
	for index, rule := range filed {
		key, ok := filedKeys[index]
		if !ok {
			continue
		}
		if remaining[key] > 0 {
			remaining[key]--
			continue
		}
		drift = append(drift, nftDriftOf(DriftNftNotLoaded, rule,
			"the host restores this rule at boot and the kernel is not filtering with it; "+
				"it takes effect only when the ruleset is loaded again"))
	}
	if filedUnreadable > 0 {
		// With a rule the file spells in its own way, a rule of the kernel
		// without a counterpart may well be that very rule.
		return drift
	}
	remaining = nftCounts(filedKeys)
	for index, rule := range loaded {
		key, ok := loadedKeys[index]
		if !ok {
			continue
		}
		if remaining[key] > 0 {
			remaining[key]--
			continue
		}
		drift = append(drift, nftDriftOf(DriftNftNotPersisted, rule,
			"the kernel filters with this rule and the boot source does not carry it; "+
				"it disappears at the next reboot"))
	}
	return drift
}

// nftDriftOf names one difference. The panel marker is written the same way in
// every adapter, so the rule is named the same way too.
func nftDriftOf(reason string, rule Rule, detail string) Drift {
	return Drift{Reason: reason, Rule: rule.Text, RuleID: UFWRuleID(rule.Comment),
		Family: rule.Family, Table: rule.Table, Chain: rule.Chain, Detail: detail}
}

// nftKeys renders one side of the comparison and records the rules it could
// not render as a drift of their own: a rule nobody can compare is not a rule
func nftKeys(rules []Rule, detail string, drift *[]Drift) (map[int]string, int) {
	keys := make(map[int]string, len(rules))
	unreadable := 0
	for index, rule := range rules {
		key, ok := nftRuleKey(rule)
		if !ok {
			unreadable++
			*drift = append(*drift, nftDriftOf(DriftNftNotComparable, rule, detail))
			continue
		}
		keys[index] = key
	}
	return keys, unreadable
}

func nftCounts(keys map[int]string) map[string]int {
	counts := make(map[string]int, len(keys))
	for _, key := range keys {
		counts[key]++
	}
	return counts
}

var (
	nftPortArgument = regexp.MustCompile(`\b[sd]port\s+(?:!=\s*)?(\{[^}]*\}|\S+)`)
	nftSetBody      = regexp.MustCompile(`\{[^}]*\}`)
	nftSpaces       = regexp.MustCompile(`\s+`)
)

// nftRuleKey renders a rule in the one spelling both views can be compared in.
// A rule the two do not spell alike at all is refused, not guessed.
func nftRuleKey(rule Rule) (string, bool) {
	text := rule.Text
	if nftVariable.MatchString(text) {
		// A rule built from a define is one string in the file and another in
		// the kernel.
		return "", false
	}
	if !nftNumericPorts(text) {
		return "", false
	}
	// The counters grow on their own and the file never carries their values.
	text = ruleCounters.ReplaceAllString(text, "counter")
	text = strings.ReplaceAll(text, `"`, "")
	text = strings.TrimSuffix(strings.TrimSpace(text), ";")
	text = nftSetBody.ReplaceAllStringFunc(text, nftSortedSet)
	text = strings.TrimSpace(nftSpaces.ReplaceAllString(text, " "))
	return rule.Family + "|" + rule.Table + "|" + rule.Chain + "|" + text, true
}

// nftNumericPorts says whether the ports of a rule are written as numbers.
// nft prints a service by its number and a file may hold its name, and the two
func nftNumericPorts(text string) bool {
	for _, match := range nftPortArgument.FindAllStringSubmatch(text, -1) {
		for _, element := range strings.Split(strings.Trim(match[1], "{}"), ",") {
			element = strings.TrimSpace(element)
			if element == "" || strings.HasPrefix(element, "@") {
				continue
			}
			if strings.ContainsFunc(element, func(r rune) bool {
				return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
			}) {
				return false
			}
		}
	}
	return true
}

// nftSortedSet writes an anonymous set in one spelling: its elements keep no
// order of their own, and the two views type them as they please.
func nftSortedSet(set string) string {
	parts := strings.Split(strings.Trim(set, "{}"), ",")
	elements := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			elements = append(elements, part)
		}
	}
	sort.Strings(elements)
	return "{" + strings.Join(elements, ",") + "}"
}

// ReadNftSource reads the script the host restores its ruleset from, following
// the includes it names. It returns the text, the files it came from in
func ReadNftSource(root fs.FS, entry []string) (content string, files []string, missing string) {
	reader := nftScript{root: root, seen: map[string]bool{}}
	for _, file := range entry {
		reader.read(file, 0)
	}
	if reader.missing != "" {
		return "", reader.files, reader.missing
	}
	return reader.text.String(), reader.files, ""
}

// nftScript collects the text of a script together with everything it
// includes.
type nftScript struct {
	root    fs.FS
	seen    map[string]bool
	files   []string
	text    strings.Builder
	missing string
}

func (s *nftScript) read(file string, depth int) {
	if s.missing != "" || depth > nftMaxIncludeDepth {
		return
	}
	file = path.Clean(file)
	if s.seen[file] {
		// A file that includes itself, directly or in a ring, is read once.
		return
	}
	s.seen[file] = true
	content, err := fs.ReadFile(s.root, strings.TrimPrefix(file, "/"))
	if err != nil {
		s.missing = file
		return
	}
	s.files = append(s.files, file)
	for _, raw := range strings.Split(string(content), "\n") {
		fields := nftIncludes.FindStringSubmatch(strings.TrimSpace(nftStripComment(raw)))
		if fields == nil {
			s.text.WriteString(raw)
			s.text.WriteByte('\n')
			continue
		}
		for _, included := range s.expand(fields[1], path.Dir(file)) {
			s.read(included, depth+1)
		}
	}
}

// expand resolves an include: a glob is read in the order nft reads it, and a
// path without a directory is looked for beside the including file first and
func (s *nftScript) expand(pattern, dir string) []string {
	candidates := []string{pattern}
	if !path.IsAbs(pattern) {
		candidates = []string{path.Join(dir, pattern), path.Join(nftIncludeDir, pattern)}
	}
	for _, candidate := range candidates {
		matches, err := fs.Glob(s.root, strings.TrimPrefix(candidate, "/"))
		if err != nil || len(matches) == 0 {
			continue
		}
		found := make([]string, 0, len(matches))
		for _, match := range matches {
			found = append(found, "/"+match)
		}
		return found
	}
	// A glob matching nothing is a directory with no rule files in it, and that
	// is an answer; a file named outright and not there is not.
	if strings.ContainsAny(pattern, "*?[") {
		return nil
	}
	return candidates[:1]
}

var (
	nftFileTable     = regexp.MustCompile(`^table\s+(\S+)(?:\s+(\S+))?\s*\{$`)
	nftFileChain     = regexp.MustCompile(`^chain\s+(\S+)\s*\{$`)
	nftChainProperty = regexp.MustCompile(`^(?:type\s+\S+\s+hook|policy|comment|devices|flags)\b`)
	nftTopStatement  = regexp.MustCompile(`^(?:flush|define|redefine|undefine|include)\b`)
)

// NftFileRules reads the rules out of an nft script. It returns false when the
// script holds a construct it could not place: a half-read file would make the
func NftFileRules(content string) ([]Rule, bool) {
	content = nftResolveDefines(content)
	var rules []Rule
	var stack []string
	var family, table, chain string
	understood := true
	depth := 0

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(nftStripComment(raw))
		if line == "" {
			continue
		}
		if depth > 0 {
			// Inside a named set, map or flowtable: a block of the table that
			// holds no rules.
			depth += nftBraces(line)
			continue
		}
		top := ""
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if line == "}" || line == "};" {
			if len(stack) == 0 {
				understood = false
				continue
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if nftBraces(line) > 0 {
			switch top {
			case "":
				fields := nftFileTable.FindStringSubmatch(line)
				if fields == nil {
					understood = false
					depth = nftBraces(line)
					continue
				}
				family, table = "ip", fields[1]
				if fields[2] != "" {
					family, table = fields[1], fields[2]
				}
				stack = append(stack, "table")
			case "table":
				fields := nftFileChain.FindStringSubmatch(line)
				if fields == nil {
					depth = nftBraces(line)
					continue
				}
				chain = fields[1]
				stack = append(stack, "chain")
			default:
				understood = false
				depth = nftBraces(line)
			}
			continue
		}
		switch top {
		case "chain":
			if nftChainProperty.MatchString(line) {
				continue
			}
			text := strings.TrimSuffix(line, ";")
			rule := Rule{Family: family, Table: table, Chain: chain, Text: text,
				Source: tableOrigin(family, table)}
			if fields := ruleComment.FindStringSubmatch(text); fields != nil {
				rule.Comment = fields[1]
			}
			rules = append(rules, rule)
		case "":
			// A rule added at the top level with "add rule ..." is a rule this
			// parser does not place, and silence about it would be a lie.
			if !nftTopStatement.MatchString(line) {
				understood = false
			}
		}
	}
	if len(stack) > 0 || depth > 0 {
		understood = false
	}
	return rules, understood
}

// nftResolveDefines puts the value of every define into the rules that use it.
// A variable left unresolved keeps its name, and such a rule is not compared.
func nftResolveDefines(content string) string {
	defines := map[string]string{}
	for _, raw := range strings.Split(content, "\n") {
		fields := nftDefine.FindStringSubmatch(strings.TrimSpace(nftStripComment(raw)))
		if fields != nil {
			defines[fields[1]] = strings.TrimSuffix(strings.TrimSpace(fields[2]), ";")
		}
	}
	if len(defines) == 0 {
		return content
	}
	return nftVariable.ReplaceAllStringFunc(content, func(name string) string {
		if value, found := defines[name[1:]]; found {
			return value
		}
		return name
	})
}

// nftStripComment removes what nft treats as a comment. A hash inside quotes
// is part of a rule comment, not the start of one.
func nftStripComment(line string) string {
	quoted := false
	for index, letter := range line {
		switch letter {
		case '"':
			quoted = !quoted
		case '#':
			if !quoted {
				return line[:index]
			}
		}
	}
	return line
}

func nftBraces(line string) int {
	return strings.Count(line, "{") - strings.Count(line, "}")
}
