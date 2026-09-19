package firewall

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// nftUnitShow renders the answer of "systemctl show" the way systemd prints
// it, with the command line inside the record of the execution.
func nftUnitShow(load, boot, command string) string {
	return "LoadState=" + load + "\nUnitFileState=" + boot +
		"\nExecStart={ path=/usr/sbin/nft ; argv[]=" + command +
		" ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; status=0/0 }\n"
}

// nftReasons counts the drift by its reason.
func nftReasons(drift []Drift) map[string]int {
	counted := map[string]int{}
	for _, entry := range drift {
		counted[entry.Reason]++
	}
	return counted
}

// The file the host loads at boot, in the form the distribution ships it.
const nftBootSource = `#!/usr/sbin/nft -f
flush ruleset

define management = 8443

table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		ct state established,related accept
		tcp dport $management counter accept comment "flotestro: management"
	}
}
`

// The same ruleset as the kernel prints it: with handles, with the counters
// grown, and with the priority written by name.
const nftLoadedRuleset = `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy drop;
		iif "lo" accept # handle 2
		ct state established,related accept # handle 3
		tcp dport 8443 counter packets 12 bytes 640 accept comment "flotestro: management" # handle 4
	}
}`

// nftDebianHost is a host whose unit loads one file, as Debian, Ubuntu and
// Arch ship it.
func nftDebianHost(content string) (NftUnit, fstest.MapFS) {
	unit := ParseNftUnit(nftUnitShow("loaded", "enabled", "/usr/sbin/nft -f /etc/nftables.conf"))
	return unit, fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{Data: []byte(content)}}
}

// The path is not assumed: Debian and Arch load /etc/nftables.conf, Fedora
// loads its own file, and both are read out of the command line of the unit.
func TestTheBootSourceIsReadFromTheUnitAndNotFromAnExample(t *testing.T) {
	for _, tc := range []struct {
		name, command, want string
	}{
		{"debian", "/usr/sbin/nft -f /etc/nftables.conf", "/etc/nftables.conf"},
		{"fedora", "/sbin/nft -f /etc/sysconfig/nftables.conf", "/etc/sysconfig/nftables.conf"},
		{"arch", "/usr/bin/nft --file /etc/nftables.conf", "/etc/nftables.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unit := ParseNftUnit(nftUnitShow("loaded", "enabled", tc.command))
			if unit.LoadState != "loaded" || unit.BootState != "enabled" {
				t.Fatalf("unit = %+v", unit)
			}
			if len(unit.Files) != 1 || unit.Files[0] != tc.want {
				t.Fatalf("files = %v", unit.Files)
			}
		})
	}
}

// A ruleset handed to nft on its standard input is carried by the unit, not
// by a file the panel could read.
func TestARulesetLoadedFromStandardInputNamesNoFile(t *testing.T) {
	unit := ParseNftUnit(nftUnitShow("loaded", "enabled", "/usr/sbin/nft -f -"))
	if len(unit.Files) != 0 {
		t.Fatalf("files = %v", unit.Files)
	}
	state, drift := NftPersistentState(unit, fstest.MapFS{}, nil, BootRestore{})
	if state.Compared || state.Reason != DriftNftSourceUnknown || len(drift) != 1 {
		t.Fatalf("state = %+v, drift = %+v", state, drift)
	}
}

// A host that cannot say what restores its rules is unknown, and unknown is
// never agreement.
func TestAHostWithoutABootSourceIsUnknownAndNotInAgreement(t *testing.T) {
	unit := ParseNftUnit("LoadState=not-found\nUnitFileState=\n")
	loaded := ParseRuleset(nftLoadedRuleset).Rules

	state, drift := NftPersistentState(unit, fstest.MapFS{}, loaded, BootRestore{})
	if state.Compared {
		t.Fatal("a host with no boot source was reported as compared")
	}
	if state.Reason != DriftNftSourceUnknown || state.Detail == "" {
		t.Fatalf("state = %+v", state)
	}
	if len(drift) != 1 || drift[0].Reason != DriftNftSourceUnknown {
		t.Fatalf("drift = %+v", drift)
	}
}

// A file nothing loads restores nothing, however well it matches the kernel.
func TestASourceNothingLoadsAtBootIsNotAgreement(t *testing.T) {
	for _, boot := range []string{"disabled", "masked"} {
		unit := ParseNftUnit(nftUnitShow("loaded", boot, "/usr/sbin/nft -f /etc/nftables.conf"))
		root := fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{Data: []byte(nftBootSource)}}

		state, drift := NftPersistentState(unit, root, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
		if state.Compared || state.Reason != DriftNftSourceInactive {
			t.Fatalf("%s: state = %+v", boot, state)
		}
		if len(drift) != 1 || drift[0].Reason != DriftNftSourceInactive ||
			!strings.Contains(drift[0].Detail, "/etc/nftables.conf") {
			t.Fatalf("%s: drift = %+v", boot, drift)
		}
	}
}

// The unit names a file that is not there: the comparison has no second view,
// and that is a reason of its own.
func TestASourceThatCannotBeReadIsReportedAndNotPassed(t *testing.T) {
	unit := ParseNftUnit(nftUnitShow("loaded", "enabled", "/usr/sbin/nft -f /etc/nftables.conf"))

	state, drift := NftPersistentState(unit, fstest.MapFS{}, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
	if state.Compared || state.Reason != DriftNftSourceUnreadable {
		t.Fatalf("state = %+v", state)
	}
	if len(drift) != 1 || !strings.Contains(drift[0].Detail, "/etc/nftables.conf") {
		t.Fatalf("drift = %+v", drift)
	}
}

// A ruleset the boot file carries word for word is not a drift, however
// differently the two views write the counters, the handles and the defines.
func TestARulesetMatchingItsBootSourceIsNotDrift(t *testing.T) {
	unit, root := nftDebianHost(nftBootSource)

	state, drift := NftPersistentState(unit, root, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
	if !state.Compared || state.Reason != "" {
		t.Fatalf("state = %+v", state)
	}
	if len(state.Files) != 1 || state.Files[0] != "/etc/nftables.conf" {
		t.Fatalf("files = %v", state.Files)
	}
	if len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// The failure the chapter names: a rule in force now that the boot file does
// not carry reads as enforced today and is gone after the reboot.
func TestARuleTheBootSourceDoesNotCarryIsNotPersisted(t *testing.T) {
	unit, root := nftDebianHost(nftBootSource)
	running := ParseRuleset(strings.Replace(nftLoadedRuleset,
		"\t\tiif \"lo\" accept # handle 2",
		"\t\tiif \"lo\" accept # handle 2\n\t\ttcp dport 3306 accept # handle 9", 1))

	state, drift := NftPersistentState(unit, root, running.Rules, BootRestore{})
	if !state.Compared {
		t.Fatalf("state = %+v", state)
	}
	if len(drift) != 1 || drift[0].Reason != DriftNftNotPersisted ||
		!strings.Contains(drift[0].Rule, "3306") || drift[0].Detail == "" {
		t.Fatalf("drift = %+v", drift)
	}
	if drift[0].Table != "filter" || drift[0].Chain != "input" || drift[0].Family != "inet" {
		t.Fatalf("the drift does not say where the rule is: %+v", drift[0])
	}
}

// A rule the file keeps and the kernel never loaded filters nothing, and the
// panel is to say so before somebody depends on it.
func TestARuleOnlyInTheBootSourceIsReportedAsNotLoaded(t *testing.T) {
	unit, root := nftDebianHost(strings.Replace(nftBootSource,
		"\t\tct state established,related accept",
		"\t\tct state established,related accept\n\t\ttcp dport 636 accept", 1))

	_, drift := NftPersistentState(unit, root, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
	if len(drift) != 1 || drift[0].Reason != DriftNftNotLoaded ||
		!strings.Contains(drift[0].Rule, "636") {
		t.Fatalf("drift = %+v", drift)
	}
}

// The panel names its own rule in the drift: the marker is the only durable
// sign of ownership.
func TestTheDriftNamesThePanelsOwnRule(t *testing.T) {
	unit, root := nftDebianHost("table inet filter {\n\tchain input {\n\t}\n}\n")

	_, drift := NftPersistentState(unit, root, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
	var named int
	for _, entry := range drift {
		if entry.RuleID == "management" {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("drift = %+v", drift)
	}
}

// A rule built from a variable the file does not define is one string here and
// another there: neither view can be said to hold it.
func TestARuleWithAnUnresolvedVariableIsNotComparable(t *testing.T) {
	unit, root := nftDebianHost("table inet filter {\n\tchain input {\n" +
		"\t\ttcp dport $ports accept\n\t}\n}\n")

	_, drift := NftPersistentState(unit, root, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
	counted := nftReasons(drift)
	if counted[DriftNftNotComparable] != 1 {
		t.Fatalf("drift = %+v", drift)
	}
	// A rule of the kernel without a counterpart may well be that very rule, so
	// nothing is called unsaved here.
	if counted[DriftNftNotPersisted] != 0 {
		t.Fatalf("an unreadable file rule turned the kernel's rules into drift: %+v", drift)
	}
}

// nft prints a service by its number and the file may hold its name.
func TestAServiceNameIsNotComparedWithItsNumber(t *testing.T) {
	unit, root := nftDebianHost("table inet filter {\n\tchain input {\n" +
		"\t\ttcp dport ssh accept\n\t}\n}\n")
	running := ParseRuleset("table inet filter { # handle 1\n\tchain input { # handle 1\n" +
		"\t\ttcp dport 22 accept # handle 2\n\t}\n}")

	_, drift := NftPersistentState(unit, root, running.Rules, BootRestore{})
	if len(drift) != 1 || drift[0].Reason != DriftNftNotComparable {
		t.Fatalf("drift = %+v", drift)
	}
}

// A port list and its order, the quotes around an interface and the grown
// counters are spellings, not differences.
func TestTheSpellingOfARuleIsNotADifference(t *testing.T) {
	unit, root := nftDebianHost("table inet filter {\n\tchain input {\n" +
		"\t\ttcp dport { 443, 80 } counter accept\n\t\tiifname eth0 accept\n\t}\n}\n")
	running := ParseRuleset("table inet filter { # handle 1\n\tchain input { # handle 1\n" +
		"\t\ttcp dport { 80, 443 } counter packets 7 bytes 420 accept # handle 2\n" +
		"\t\tiifname \"eth0\" accept # handle 3\n\t}\n}")

	if _, drift := NftPersistentState(unit, root, running.Rules, BootRestore{}); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// Fedora keeps the rules in files its own list includes, and a commented-out
// include is not one of them.
func TestTheIncludesOfTheBootSourceAreFollowedInOrder(t *testing.T) {
	unit := ParseNftUnit(nftUnitShow("loaded", "enabled", "/sbin/nft -f /etc/sysconfig/nftables.conf"))
	root := fstest.MapFS{
		"etc/sysconfig/nftables.conf": &fstest.MapFile{Data: []byte(
			"# include \"/etc/nftables/main.nft\"\ninclude \"/etc/nftables/router.nft\"\n" +
				"include \"/etc/nftables/local/*.nft\"\n")},
		"etc/nftables/router.nft": &fstest.MapFile{Data: []byte(
			"table inet filter {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n")},
		"etc/nftables/local/10-extra.nft": &fstest.MapFile{Data: []byte(
			"table inet filter {\n\tchain input {\n\t\ttcp dport 443 accept\n\t}\n}\n")},
	}
	running := ParseRuleset("table inet filter { # handle 1\n\tchain input { # handle 1\n" +
		"\t\ttcp dport 22 accept # handle 2\n\t\ttcp dport 443 accept # handle 3\n\t}\n}")

	state, drift := NftPersistentState(unit, root, running.Rules, BootRestore{})
	if !state.Compared || len(drift) != 0 {
		t.Fatalf("state = %+v, drift = %+v", state, drift)
	}
	want := []string{"/etc/sysconfig/nftables.conf", "/etc/nftables/router.nft", "/etc/nftables/local/10-extra.nft"}
	if strings.Join(state.Files, " ") != strings.Join(want, " ") {
		t.Fatalf("files = %v", state.Files)
	}
}

// An include naming a file that is not there is a source that could not be
// read; a glob matching nothing is a directory without rule files, which is
func TestAMissingIncludeIsReportedAndAnEmptyGlobIsNot(t *testing.T) {
	unit, _ := nftDebianHost("")
	missing := fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{
		Data: []byte("include \"/etc/nftables/router.nft\"\n")}}
	if state, _ := NftPersistentState(unit, missing, nil, BootRestore{}); state.Reason != DriftNftSourceUnreadable {
		t.Fatalf("state = %+v", state)
	}

	empty := fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{
		Data: []byte("include \"/etc/nftables.d/*.nft\"\n")}}
	if state, _ := NftPersistentState(unit, empty, nil, BootRestore{}); !state.Compared || state.Reason != "" {
		t.Fatalf("state = %+v", state)
	}
}

// A file that includes itself is read once instead of forever.
func TestAFileIncludingItselfIsReadOnce(t *testing.T) {
	unit, _ := nftDebianHost("")
	root := fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{Data: []byte(
		"include \"/etc/nftables.conf\"\ntable inet filter {\n\tchain input {\n" +
			"\t\ttcp dport 22 accept\n\t}\n}\n")}}
	running := ParseRuleset("table inet filter { # handle 1\n\tchain input { # handle 1\n" +
		"\t\ttcp dport 22 accept # handle 2\n\t}\n}")

	state, drift := NftPersistentState(unit, root, running.Rules, BootRestore{})
	if len(state.Files) != 1 || len(drift) != 0 {
		t.Fatalf("files = %v, drift = %+v", state.Files, drift)
	}
}

// A named set is a block of the table, and its closing brace used to be read
// as the end of the table: every chain after it disappeared from both views.
func TestANamedSetDoesNotSwallowTheChainsAfterIt(t *testing.T) {
	const listed = `table inet filter { # handle 1
	set blocked { # handle 5
		type ipv4_addr
		elements = { 10.0.0.1,
			     10.0.0.2 }
	}

	chain input { # handle 1
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept # handle 2
	}
}`
	if rules := ParseRuleset(listed).Rules; len(rules) != 1 || rules[0].Chain != "input" {
		t.Fatalf("rules = %+v", rules)
	}

	source := "table inet filter {\n\tset blocked {\n\t\ttype ipv4_addr\n" +
		"\t\telements = { 10.0.0.1, 10.0.0.2 }\n\t}\n\n\tchain input {\n" +
		"\t\ttcp dport 22 accept\n\t}\n}\n"
	filed, understood := NftFileRules(source)
	if !understood || len(filed) != 1 || filed[0].Chain != "input" {
		t.Fatalf("understood = %v, rules = %+v", understood, filed)
	}
}

// A table belonging to another program is rewritten by its owner at every
// start and is not kept in the boot file; calling it unsaved would be noise.
func TestForeignTablesAreNotComparedWithTheBootSource(t *testing.T) {
	unit, root := nftDebianHost(nftBootSource)
	running := ParseRuleset(nftLoadedRuleset + "\n" +
		"table ip docker { # handle 9\n\tchain DOCKER { # handle 1\n" +
		"\t\tiifname \"docker0\" counter packets 0 bytes 0 return # handle 2\n\t}\n}")

	if _, drift := NftPersistentState(unit, root, running.Rules, BootRestore{}); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// A rule added at the top level is a rule this parser does not place. A file
// read only in part would make the kernel look like the only place that has
func TestAConstructTheParserCannotPlaceStopsTheComparison(t *testing.T) {
	unit, root := nftDebianHost("add rule inet filter input tcp dport 25 drop\n")

	state, drift := NftPersistentState(unit, root, ParseRuleset(nftLoadedRuleset).Rules, BootRestore{})
	if state.Compared || state.Reason != DriftNftNotComparable {
		t.Fatalf("state = %+v", state)
	}
	if len(drift) != 1 || drift[0].Detail == "" {
		t.Fatalf("drift = %+v", drift)
	}
}

// A table written without its family is the ip family, and a chain of it is
// still a chain.
func TestATableWrittenWithoutItsFamilyIsRead(t *testing.T) {
	filed, understood := NftFileRules("table filter {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n")
	if !understood || len(filed) != 1 {
		t.Fatalf("understood = %v, rules = %+v", understood, filed)
	}
	if filed[0].Family != "ip" || filed[0].Table != "filter" || filed[0].Source != SourceManual {
		t.Fatalf("rule = %+v", filed[0])
	}
}

// bootRestoreShow renders the answer of "systemctl show" for the unit that
// rebuilds the panel's table.
func bootRestoreShow(load, boot, active, result string) string {
	return "LoadState=" + load + "\nUnitFileState=" + boot +
		"\nActiveState=" + active + "\nResult=" + result + "\n"
}

// panelRegistry is a registry with rules in it; what the rules say does not
// matter to the decision, only that the panel gave this host some.
func panelRegistry() Registry {
	return Registry{Rules: []RuleSpec{{ID: "test", Chain: ChainInput, Action: "drop",
		Protocol: "tcp", Ports: []string{"25"}}}}
}

// The panel's own table as the kernel prints it.
const nftPanelRuleset = `table inet flotestro { # handle 7
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		ip saddr 10.10.0.0/16 tcp dport 25 counter packets 0 bytes 0 drop comment "flotestro:test" # handle 2
	}
}`

// A record written at this boot by a unit systemd calls healthy is the one
// case in which the panel's rules are back after a restart.
func TestARestoreOfThisBootAnswersForThePanelTable(t *testing.T) {
	unit := ParseBootRestoreUnit(bootRestoreShow("loaded", "enabled", "active", "success"))
	record := BootRestoreRecord{At: time.Now().UTC(), Boot: "abc", Rules: 1,
		Detail: "the panel's own table was rebuilt from 1 registered rules"}

	state := BootRestoreState(unit, record, "abc", 1)
	if !state.Ran || !state.InForce() || state.Reason != "" {
		t.Fatalf("state = %+v", state)
	}
	if drift := BootRestoreDrift(state); len(drift) != 0 {
		t.Fatalf("drift = %+v", drift)
	}
}

// A host without the unit and a host whose unit failed are two different
// answers: the first is an agent from before this release.
func TestNoRestoreUnitIsNotTheSameAnswerAsAFailedOne(t *testing.T) {
	absent := BootRestoreState(ParseBootRestoreUnit("LoadState=not-found\nUnitFileState=\n"),
		BootRestoreRecord{}, "abc", 2)
	if absent.Reason != DriftBootRestoreUnitAbsent || absent.InForce() {
		t.Fatalf("absent = %+v", absent)
	}
	if drift := BootRestoreDrift(absent); len(drift) != 1 ||
		drift[0].Reason != DriftBootRestoreUnitAbsent || drift[0].Table != FlotestroTable {
		t.Fatalf("drift = %+v", drift)
	}

	failed := BootRestoreState(
		ParseBootRestoreUnit(bootRestoreShow("loaded", "enabled", "failed", "exit-code")),
		BootRestoreRecord{At: time.Now().UTC(), Boot: "abc", Rules: 2,
			Reason: DriftBootRestoreFailed, Detail: "the rule registry could not be read: broken"},
		"abc", 2)
	if failed.Reason != DriftBootRestoreFailed || failed.InForce() {
		t.Fatalf("failed = %+v", failed)
	}
	if !strings.Contains(failed.Detail, "registry") {
		t.Errorf("the failure does not say what the run recorded: %q", failed.Detail)
	}
}

// A unit switched off and a unit that has not run yet are facts of their own,
// and neither means the rules come back.
func TestASwitchedOffOrUnrunRestoreIsNotInForce(t *testing.T) {
	for _, tc := range []struct {
		why    string
		unit   string
		record BootRestoreRecord
		want   string
	}{
		{"disabled", bootRestoreShow("loaded", "disabled", "inactive", "success"),
			BootRestoreRecord{}, DriftBootRestoreUnitInactive},
		{"masked", bootRestoreShow("loaded", "masked", "inactive", ""),
			BootRestoreRecord{}, DriftBootRestoreUnitInactive},
		{"never run", bootRestoreShow("loaded", "enabled", "inactive", "success"),
			BootRestoreRecord{}, DriftBootRestorePending},
		{"a record of an earlier boot", bootRestoreShow("loaded", "enabled", "inactive", "success"),
			BootRestoreRecord{At: time.Now().UTC(), Boot: "older", Rules: 1}, DriftBootRestorePending},
	} {
		t.Run(tc.why, func(t *testing.T) {
			state := BootRestoreState(ParseBootRestoreUnit(tc.unit), tc.record, "abc", 1)
			if state.Reason != tc.want || state.InForce() || state.Detail == "" {
				t.Fatalf("state = %+v", state)
			}
		})
	}
}

// A host the panel never gave a rule has nothing to restore, so the absence
// of the unit there is not a difference anybody is to act on.
func TestAHostWithoutPanelRulesRaisesNoRestoreDrift(t *testing.T) {
	state := BootRestoreState(ParseBootRestoreUnit("LoadState=not-found\n"), BootRestoreRecord{}, "abc", 0)
	if len(BootRestoreDrift(state)) != 0 {
		t.Fatalf("state = %+v", state)
	}
	// A registry that could not be read is not an empty one.
	unknown := BootRestoreState(ParseBootRestoreUnit("LoadState=not-found\n"), BootRestoreRecord{}, "abc", -1)
	if len(BootRestoreDrift(unknown)) != 1 {
		t.Fatalf("a host whose registry could not be read was taken for one without rules: %+v", unknown)
	}
}

// The decision to rebuild is taken from the host's own files, and every
// refusal names itself.
func TestTheRestoreRefusesWhereAnotherMechanismHoldsTheRules(t *testing.T) {
	const bootFileWithPanelTable = `flush ruleset
table inet flotestro {
	chain input {
		type filter hook input priority 0; policy accept;
		ip saddr 10.10.0.0/16 tcp dport 25 drop comment "flotestro:test"
	}
}
`
	nftHost := ParseNftUnit(nftUnitShow("loaded", "enabled", "/usr/sbin/nft -f /etc/nftables.conf"))
	nft := fstest.MapFS{"usr/sbin/nft": &fstest.MapFile{Data: []byte("binary")}}
	with := func(extra fstest.MapFS) fstest.MapFS {
		root := fstest.MapFS{}
		for name, file := range nft {
			root[name] = file
		}
		for name, file := range extra {
			root[name] = file
		}
		return root
	}

	for _, tc := range []struct {
		why      string
		registry Registry
		root     fstest.MapFS
		unit     NftUnit
		rebuild  bool
		reason   string
	}{
		{why: "a host the panel never gave a rule", registry: Registry{}, root: nft,
			unit: nftHost, reason: ""},
		{why: "firewalld holds the rules", registry: panelRegistry(),
			root: with(fstest.MapFS{"usr/bin/firewall-cmd": &fstest.MapFile{Data: []byte("binary")}}),
			unit: nftHost, reason: BootRestoreNotApplicable},
		{why: "ufw holds the rules", registry: panelRegistry(),
			root: with(fstest.MapFS{"etc/ufw/ufw.conf": &fstest.MapFile{Data: []byte("ENABLED=yes\n")}}),
			unit: nftHost, reason: BootRestoreNotApplicable},
		{why: "an inactive ufw holds nothing", registry: panelRegistry(),
			root: with(fstest.MapFS{"etc/ufw/ufw.conf": &fstest.MapFile{Data: []byte("ENABLED=no\n")}}),
			unit: nftHost, rebuild: true},
		{why: "a host without nft", registry: panelRegistry(), root: fstest.MapFS{},
			unit: nftHost, reason: DriftBootRestoreFailed},
		{why: "the host's own unit loads the panel table", registry: panelRegistry(),
			root: with(fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{
				Data: []byte(bootFileWithPanelTable)}}),
			unit: nftHost, reason: BootRestoreNotNeeded},
		{why: "the host's own unit loads something else", registry: panelRegistry(),
			root: with(fstest.MapFS{"etc/nftables.conf": &fstest.MapFile{Data: []byte(nftBootSource)}}),
			unit: nftHost, rebuild: true},
		{why: "a host with no nftables unit at all", registry: panelRegistry(), root: nft,
			unit: ParseNftUnit("LoadState=not-found\n"), rebuild: true},
	} {
		t.Run(tc.why, func(t *testing.T) {
			decision := PlanBootRestore(tc.registry, tc.root, tc.unit)
			if decision.Rebuild != tc.rebuild || decision.Reason != tc.reason {
				t.Fatalf("decision = %+v", decision)
			}
			if !decision.Rebuild && decision.Detail == "" {
				t.Error("a refusal without a reason in words")
			}
		})
	}
}

// The panel's own table is in no boot file, so as long as nothing restores it
// the panel says the rules disappear at the next reboot - and stops saying it
func TestThePanelTableIsAnsweredForByTheRestoreAndNotByTheBootSource(t *testing.T) {
	unit, root := nftDebianHost(nftBootSource)
	running := ParseRuleset(nftLoadedRuleset + "\n" + nftPanelRuleset).Rules

	_, drift := NftPersistentState(unit, root, running, BootRestoreState(
		ParseBootRestoreUnit("LoadState=not-found\n"), BootRestoreRecord{}, "abc", 1))
	counted := nftReasons(drift)
	if counted[DriftNftNotPersisted] != 1 || counted[DriftBootRestoreUnitAbsent] != 1 {
		t.Fatalf("drift = %+v", drift)
	}

	state, drift := NftPersistentState(unit, root, running, BootRestoreState(
		ParseBootRestoreUnit(bootRestoreShow("loaded", "enabled", "active", "success")),
		BootRestoreRecord{At: time.Now().UTC(), Boot: "abc", Rules: 1}, "abc", 1))
	if !state.Compared || len(drift) != 0 {
		t.Fatalf("state = %+v, drift = %+v", state, drift)
	}
	if !state.Restore.Ran || state.Restore.Reason != "" {
		t.Fatalf("restore = %+v", state.Restore)
	}
}

// The record travels between the helper that writes it and the agent that
// reads it, so it goes through the disk exactly as it is.
func TestTheRestoreRecordSurvivesTheDisk(t *testing.T) {
	dir := t.TempDir()
	if record, err := LoadBootRestoreRecord(dir); err != nil || !record.At.IsZero() {
		t.Fatalf("a directory without a record: %+v, %v", record, err)
	}
	written := BootRestoreRecord{At: time.Now().UTC().Truncate(time.Second), Boot: "abc",
		Rules: 3, Reason: BootRestoreNotNeeded, Detail: "the unit loads the panel's table itself"}
	if err := SaveBootRestoreRecord(dir, written); err != nil {
		t.Fatalf("writing the record: %v", err)
	}
	read, err := LoadBootRestoreRecord(dir)
	if err != nil || !read.At.Equal(written.At) || read.Boot != written.Boot ||
		read.Rules != written.Rules || read.Reason != written.Reason {
		t.Fatalf("read = %+v, err = %v", read, err)
	}
}

// firewalld and ufw restore their own rules, never the panel's table. Where
// the panel has rules of its own on such a host, nothing puts them back.
func TestAnotherToolsPersistenceIsNotThePanelsOwn(t *testing.T) {
	unit := ParseBootRestoreUnit(bootRestoreShow("loaded", "enabled", "active", "success"))
	record := BootRestoreRecord{At: time.Now().UTC(), Boot: "abc",
		Reason: BootRestoreNotApplicable, Detail: "ufw holds the rules on this host"}

	if state := BootRestoreState(unit, record, "abc", 0); len(BootRestoreDrift(state)) != 0 {
		t.Fatalf("a host whose rules belong to its adapter: %+v", state)
	}
	state := BootRestoreState(unit, record, "abc", 2)
	if state.InForce() || len(BootRestoreDrift(state)) != 1 {
		t.Fatalf("state = %+v", state)
	}
}
