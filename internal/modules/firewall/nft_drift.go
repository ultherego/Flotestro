package firewall

import (
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
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
	// Restore is what rebuilds the panel's own table after a reboot. No boot
	// source of a distribution carries that table.
	Restore BootRestore `json:"restore"`
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
// source the host restores at boot, reading only the files the unit hands nft.
func NftPersistentState(unit NftUnit, root fs.FS, running []Rule, restore BootRestore) (NftPersistence, []Drift) {
	state := NftPersistence{Unit: unit, Restore: restore}
	// Where the restore is in force, the panel's own table is answered for by
	// it and not by the boot source of the distribution.
	prefix := BootRestoreDrift(restore)
	notCompared := func(reason, detail string) (NftPersistence, []Drift) {
		state, drift := nftNotCompared(state, reason, detail)
		return state, append(prefix, drift...)
	}
	if restore.InForce() {
		running = nftWithoutPanelTable(running)
	}
	switch {
	case unit.LoadState != "loaded":
		return notCompared(DriftNftSourceUnknown,
			"this host has no "+NftUnitName+", so nothing says what would restore its rules "+
				"after a reboot and a rule in force now may be gone then")
	case len(unit.Files) == 0:
		return notCompared(DriftNftSourceUnknown,
			"the unit "+NftUnitName+" hands nft no file, so what it would restore at boot cannot be read")
	case unit.BootState == "disabled" || unit.BootState == "masked":
		state.Files = unit.Files
		return notCompared(DriftNftSourceInactive,
			"the unit "+NftUnitName+" is "+unit.BootState+", so nothing loads "+
				strings.Join(unit.Files, ", ")+" and no rule in force now survives a reboot")
	}

	content, files, missing := ReadNftSource(root, unit.Files)
	state.Files = files
	if missing != "" {
		return notCompared(DriftNftSourceUnreadable,
			"the ruleset is restored from "+missing+" and that file could not be read, "+
				"so there is nothing to compare the running rules with")
	}
	filed, understood := NftFileRules(content)
	if !understood {
		return notCompared(DriftNftNotComparable,
			"the boot source holds a construct this panel does not read, so a rule missing from it "+
				"would not mean the kernel is the only place that has it")
	}
	if restore.InForce() {
		filed = nftWithoutPanelTable(filed)
	}
	state.Compared = true
	return state, append(prefix, NftDrift(NftComparableRules(filed), NftComparableRules(running))...)
}

// nftWithoutPanelTable drops the panel's own table from a view of the rules.
func nftWithoutPanelTable(rules []Rule) []Rule {
	kept := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Source != SourceManaged {
			kept = append(kept, rule)
		}
	}
	return kept
}

// nftNotCompared records why the two views were not compared: the answer is
// the reason itself, never silence.
func nftNotCompared(state NftPersistence, reason, detail string) (NftPersistence, []Drift) {
	state.Reason = reason
	state.Detail = detail
	return state, []Drift{{Reason: reason, Detail: detail}}
}

// NftComparableRules picks the rules the boot source is answerable for. A
// foreign table - docker, firewalld, iptables-nft - is written by its owner.
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
// filters with now, matching the two views as multisets.
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
// not render as a drift of their own, rather than as rules in agreement.
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
// nft prints a service by its number where a file may hold its name.
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
// the includes it names: the text, the files read, and the first one missing.
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

// expand resolves an include the way nft does: a relative path beside the
// including file first, then in the include directory.
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
// script holds a construct it could not place, so a partial read is not used.
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

// BootRestoreUnitName is the unit that rebuilds the panel's own table after a
// reboot. No boot source of a distribution carries that table.
const BootRestoreUnitName = "flotestro-firewall-restore.service"

// BootRestoreFile holds what the last run of that unit recorded. It lives
// beside the registry the table is rebuilt from.
const BootRestoreFile = "boot-restore.json"

// bootIDPath is the kernel's name for this boot: a record written before the
// last restart says nothing about the rules the host filters with now.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// What the panel's own table is restored by after a reboot, or why it is not.
// The first four mean the panel's rules are gone once the machine restarts.
const (
	// DriftBootRestoreUnitAbsent: this host has no unit rebuilding the table,
	// which is every host whose agent is of a release from before this one.
	DriftBootRestoreUnitAbsent = "nft_boot_restore_unit_absent"
	// DriftBootRestoreUnitInactive: the unit is installed and disabled or
	// masked, so it rebuilds nothing.
	DriftBootRestoreUnitInactive = "nft_boot_restore_unit_inactive"
	// DriftBootRestoreFailed: the unit ran and the table was not rebuilt.
	DriftBootRestoreFailed = "nft_boot_restore_failed"
	// DriftBootRestorePending: the unit is enabled and has not run since this
	// host started, so nothing here proves the table comes back.
	DriftBootRestorePending = "nft_boot_restore_pending"
	// BootRestoreNotNeeded: the host's own nftables unit loads the panel's
	// table already, and two mechanisms writing one table fight each other.
	BootRestoreNotNeeded = "nft_boot_restore_not_needed"
	// BootRestoreNotApplicable: firewalld or ufw is on this host and owns its
	// rules, so the restore leaves it alone. Where the panel nevertheless has
	// rules of its own in the registry here, nothing puts those back.
	BootRestoreNotApplicable = "nft_boot_restore_not_applicable"
)

// BootRestoreUnit is what systemd says about the unit that rebuilds the
// panel's table at boot.
type BootRestoreUnit struct {
	Name string `json:"name,omitempty"`
	// LoadState says whether the unit exists on this host at all.
	LoadState string `json:"load_state,omitempty"`
	// BootState is systemd's word for whether the unit runs at boot.
	BootState string `json:"boot_state,omitempty"`
	// ActiveState and Result are how the last run ended.
	ActiveState string `json:"active_state,omitempty"`
	Result      string `json:"result,omitempty"`
}

// BootRestoreRecord is what a run of the restore wrote about itself. The
// helper writes it as root; the agent only reads it back.
type BootRestoreRecord struct {
	At time.Time `json:"at"`
	// Boot is the boot the run belongs to.
	Boot string `json:"boot,omitempty"`
	// Rules is how many registered rules the run had to rebuild.
	Rules int `json:"rules"`
	// Reason is the stable code of what the run decided; empty means the table
	// was rebuilt.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// BootRestore is what the panel is told about the panel's own table after a
// reboot: the unit, the run, and whether the rules are back.
type BootRestore struct {
	Unit BootRestoreUnit `json:"unit"`
	// Ran says whether the restore ran at this boot of this host.
	Ran   bool      `json:"ran"`
	At    time.Time `json:"at,omitempty"`
	Rules int       `json:"rules"`
	// Registered is how many rules the registry holds now; -1 means it could
	// not be read, which is not the same answer as none.
	Registered int `json:"registered"`
	// Reason is the stable code, and Detail what it means for this host.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// InForce says whether the panel's own rules are in the kernel again after a
// reboot. Not knowing is not agreement, and neither is another tool's answer.
func (b BootRestore) InForce() bool {
	switch b.Reason {
	case "":
		return b.Ran
	case BootRestoreNotNeeded:
		// The host's own unit loads the panel's table, which is the table being
		// asked about.
		return true
	}
	return false
}

// BootRestoreUnitArguments asks systemd about the unit that rebuilds the
// panel's table.
func BootRestoreUnitArguments() []string {
	return []string{SystemctlPath, "show", "--no-pager",
		"--property=LoadState", "--property=UnitFileState",
		"--property=ActiveState", "--property=Result", BootRestoreUnitName}
}

// ParseBootRestoreUnit reads the answer of "systemctl show".
func ParseBootRestoreUnit(output string) BootRestoreUnit {
	unit := BootRestoreUnit{Name: BootRestoreUnitName}
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
		case "ActiveState":
			unit.ActiveState = value
		case "Result":
			unit.Result = value
		}
	}
	return unit
}

// BootRestoreState judges what this host does with the panel's own table at
// boot: systemd answers for the unit, the record answers for the run.
func BootRestoreState(unit BootRestoreUnit, record BootRestoreRecord, bootID string,
	registered int) BootRestore {
	state := BootRestore{Unit: unit, At: record.At, Rules: record.Rules, Registered: registered}
	// A record of an earlier boot is not an answer about this one; where
	// neither side names a boot, the record is taken as it stands.
	ranHere := !record.At.IsZero() &&
		(bootID == "" || record.Boot == "" || record.Boot == bootID)
	switch {
	case unit.LoadState != "loaded":
		state.Reason = DriftBootRestoreUnitAbsent
		state.Detail = "this host has no " + BootRestoreUnitName + ", so nothing rebuilds the " +
			"panel's own table after a reboot and the rules the panel applied are in force only " +
			"until the machine restarts"
	case unit.BootState == "disabled" || unit.BootState == "masked":
		state.Reason = DriftBootRestoreUnitInactive
		state.Detail = "the unit " + BootRestoreUnitName + " is " + unit.BootState +
			", so the panel's own table is not rebuilt after a reboot"
	case unit.ActiveState == "failed" || (unit.Result != "" && unit.Result != "success"):
		state.Ran = ranHere
		state.Reason = DriftBootRestoreFailed
		state.Detail = "the unit " + BootRestoreUnitName + " did not finish, so the panel's own " +
			"table was not rebuilt"
		if ranHere && record.Detail != "" {
			state.Detail = record.Detail
		}
	case !ranHere:
		state.Reason = DriftBootRestorePending
		state.Detail = "the unit " + BootRestoreUnitName + " is enabled and has not run since " +
			"this host started, so nothing here proves the panel's own table comes back"
	default:
		state.Ran = true
		state.Reason, state.Detail = record.Reason, record.Detail
	}
	return state
}

// BootRestoreDrift names the one difference that matters here: the panel gave
// this host rules and nothing puts them back after a reboot.
func BootRestoreDrift(state BootRestore) []Drift {
	if state.Registered == 0 || state.InForce() {
		return nil
	}
	return []Drift{{Reason: state.Reason, Family: FlotestroFamily, Table: FlotestroTable,
		Detail: state.Detail}}
}

// BootRestoreDecision is what the restore is to do on this host. It is
// computed from files and from systemd's answer, and touches nothing.
type BootRestoreDecision struct {
	// Rebuild says whether the panel's own table is to be built again.
	Rebuild bool
	Rules   int
	Reason  string
	Detail  string
}

// PlanBootRestore decides what the helper does with the panel's own table at
// boot. Everything it reads comes from the given root.
func PlanBootRestore(registry Registry, root fs.FS, unit NftUnit) BootRestoreDecision {
	decision := BootRestoreDecision{Rules: len(registry.Rules)}
	switch {
	case len(registry.Rules) == 0:
		// A host the panel never gave a rule has nothing to rebuild, and that
		// is an answer, not a failure.
		decision.Detail = "the panel has given this host no rule, so there is nothing to rebuild"
	case hostFileExists(root, FirewallCmdPath):
		decision.Reason = BootRestoreNotApplicable
		decision.Detail = "firewalld holds the rules on this host and writes its own tables at every start"
	case UFWEnabled(hostFile(root, UFWConfigFile)):
		decision.Reason = BootRestoreNotApplicable
		decision.Detail = "ufw holds the rules on this host and restores them from its own files"
	case !hostFileExists(root, NftPath):
		decision.Reason = DriftBootRestoreFailed
		decision.Detail = "this host has no nftables (nft) binary, so the rules the panel applied " +
			"cannot be rebuilt"
	case nftSourceCarriesPanelTable(root, unit):
		decision.Reason = BootRestoreNotNeeded
		decision.Detail = "the unit " + NftUnitName + " loads the panel's own table itself, so " +
			"rebuilding it here would fight that unit"
	default:
		decision.Rebuild = true
	}
	return decision
}

// nftSourceCarriesPanelTable says whether what this host loads at boot already
// holds the panel's own table. A source that cannot be read does not count.
func nftSourceCarriesPanelTable(root fs.FS, unit NftUnit) bool {
	if unit.LoadState != "loaded" || len(unit.Files) == 0 ||
		unit.BootState == "disabled" || unit.BootState == "masked" {
		return false
	}
	content, _, missing := ReadNftSource(root, unit.Files)
	if missing != "" {
		return false
	}
	rules, _ := NftFileRules(content)
	for _, rule := range rules {
		if rule.Source == SourceManaged {
			return true
		}
	}
	return false
}

// BootIdentifier is the kernel's name for this boot, or empty where the host
// does not tell.
func BootIdentifier(root fs.FS) string {
	return strings.TrimSpace(hostFile(root, bootIDPath))
}

// LoadBootRestoreRecord reads what the last restore recorded. A missing file
// is a host where the restore has not run, which the caller judges.
func LoadBootRestoreRecord(dir string) (BootRestoreRecord, error) {
	data, err := os.ReadFile(filepath.Join(dir, BootRestoreFile))
	if os.IsNotExist(err) {
		return BootRestoreRecord{}, nil
	}
	if err != nil {
		return BootRestoreRecord{}, err
	}
	var record BootRestoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return BootRestoreRecord{}, err
	}
	return record, nil
}

// SaveBootRestoreRecord writes what a run of the restore decided.
func SaveBootRestoreRecord(dir string, record BootRestoreRecord) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, BootRestoreFile)
	// A record read half-way would say the restore did something it did not.
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// hostFileExists says whether the host carries the given absolute path.
func hostFileExists(root fs.FS, file string) bool {
	_, err := fs.Stat(root, strings.TrimPrefix(file, "/"))
	return err == nil
}

// hostFile reads an absolute path of the host; what cannot be read is empty,
// and every caller treats empty as "the host does not say".
func hostFile(root fs.FS, file string) string {
	content, err := fs.ReadFile(root, strings.TrimPrefix(file, "/"))
	if err != nil {
		return ""
	}
	return string(content)
}
