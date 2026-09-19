package sudoers

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// The sudoers Debian ships, verbatim: the file every fixture starts from.
const debianDefault = `#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults	use_pty

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
`

// The sudoers Fedora ships, cut to what matters: the old include form,
// a wheel rule and Defaults with quoted values.
const fedoraDefault = `## Sudoers allows particular users to run various commands as
## the root user, without needing the root password.
Defaults   !visiblepw
Defaults    always_set_home
Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin

## Allow root to run any commands anywhere
root	ALL=(ALL) 	ALL

## Allows people in group wheel to run all commands
%wheel	ALL=(ALL)	ALL

## Same thing without a password
# %wheel	ALL=(ALL)	NOPASSWD: ALL

## Read drop-in files from /etc/sudoers.d (the # here does not mean a comment)
#includedir /etc/sudoers.d
`

func parseTree(t *testing.T, tree fstest.MapFS) Snapshot {
	t.Helper()
	return Parse(tree, MainFile, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC))
}

func ruleAt(t *testing.T, snapshot Snapshot, source string, line int) Rule {
	t.Helper()
	for _, rule := range snapshot.Rules {
		if rule.Source == source && rule.Line == line {
			return rule
		}
	}
	t.Fatalf("no rule from %s:%d among %d rules", source, line, len(snapshot.Rules))
	return Rule{}
}

func TestDebianDefaultReadsRootAndTheSudoGroup(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers":           {Data: []byte(debianDefault)},
		"etc/sudoers.d/README":  {Data: []byte("#\n# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on\n# installation of the package now includes the directive:\n#\n")},
		"etc/sudoers.d/foo.bak": {Data: []byte("intruder ALL=(ALL) NOPASSWD: ALL\n")},
		"etc/sudoers.d/bar~":    {Data: []byte("intruder ALL=(ALL) NOPASSWD: ALL\n")},
	})
	if snapshot.UnavailableReason != "" {
		t.Fatalf("unavailable: %s", snapshot.UnavailableReason)
	}
	if len(snapshot.Rules) != 2 {
		t.Fatalf("rules = %d: %+v", len(snapshot.Rules), snapshot.Rules)
	}
	if len(snapshot.Problems) != 0 {
		t.Fatalf("problems = %+v", snapshot.Problems)
	}

	root := ruleAt(t, snapshot, "/etc/sudoers", 21)
	if !slices.Equal(root.Users, []string{"root"}) || !root.AllHosts || !root.AllCommands || !root.RunAsAnyUser {
		t.Errorf("root rule = %+v", root)
	}
	// Root's own grant gives root nothing: it is neither root-equivalent
	// nor critical, or the default file of every Debian host would warn.
	if root.RootEquivalent || root.Critical {
		t.Errorf("root's own rule is flagged: %+v", root)
	}

	group := ruleAt(t, snapshot, "/etc/sudoers", 24)
	if !slices.Equal(group.Users, []string{"%sudo"}) || !slices.Equal(group.RunAs, []string{"ALL"}) || !slices.Equal(group.RunAsGroups, []string{"ALL"}) {
		t.Errorf("group rule = %+v", group)
	}
	if !group.RootEquivalent || group.NoPasswd {
		t.Errorf("the sudo group rule: root_equivalent = %v, nopasswd = %v", group.RootEquivalent, group.NoPasswd)
	}
	if !slices.Equal(group.CriticalReasons, []string{"every command as any user"}) {
		t.Errorf("reasons = %v", group.CriticalReasons)
	}

	// Four Defaults, all global; the quoted secure_path stays one parameter.
	if len(snapshot.Defaults) != 4 {
		t.Fatalf("defaults = %+v", snapshot.Defaults)
	}
	if snapshot.Defaults[2].Params[0] != `secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"` {
		t.Errorf("secure_path = %v", snapshot.Defaults[2].Params)
	}
	if snapshot.PasswordlessGlobally() {
		t.Error("the default file turned authentication off")
	}

	// The README has no dot, so sudo reads it - and so does the parser; the
	// backup and the editor leftover are skipped, so their intruder line is not a
	// rule.
	paths := make([]string, 0, len(snapshot.Files))
	for _, file := range snapshot.Files {
		paths = append(paths, file.Path)
		if file.Reason != "" {
			t.Errorf("%s: %s", file.Path, file.Reason)
		}
	}
	if !slices.Equal(paths, []string{"/etc/sudoers", "/etc/sudoers.d/README"}) {
		t.Errorf("files = %v", paths)
	}
	if snapshot.Files[1].IncludedFrom != "/etc/sudoers" {
		t.Errorf("the README is not marked as included from the main file: %+v", snapshot.Files[1])
	}
}

func TestANoPasswdDropInIsRootWithoutAPassword(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers":                       {Data: []byte(debianDefault)},
		"etc/sudoers.d/90-cloud-init-users": {Data: []byte("# Created by cloud-init v. 23.1\nubuntu ALL=(ALL) NOPASSWD:ALL\n")},
		"etc/sudoers.d/50-deploy":           {Data: []byte("deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app, PASSWD: /usr/bin/apt-get update\n")},
	})
	if len(snapshot.Problems) != 0 {
		t.Fatalf("problems = %+v", snapshot.Problems)
	}

	// The drop-ins come in lexical order after the main file.
	sources := make([]string, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		sources = append(sources, rule.Source)
	}
	if !slices.Equal(sources, []string{"/etc/sudoers", "/etc/sudoers", "/etc/sudoers.d/50-deploy", "/etc/sudoers.d/50-deploy", "/etc/sudoers.d/90-cloud-init-users"}) {
		t.Errorf("sources = %v", sources)
	}

	cloud := ruleAt(t, snapshot, "/etc/sudoers.d/90-cloud-init-users", 2)
	if !cloud.NoPasswd || !cloud.RootEquivalent || !cloud.AllCommands {
		t.Errorf("cloud-init rule = %+v", cloud)
	}
	if !slices.Equal(cloud.CriticalReasons, []string{"every command as any user", "NOPASSWD"}) {
		t.Errorf("reasons = %v", cloud.CriticalReasons)
	}

	// A tag stays in force until the next tag: the systemctl command is
	// passwordless and the apt-get one is not, so they are two rules.
	restart := ruleAt(t, snapshot, "/etc/sudoers.d/50-deploy", 1)
	if !restart.NoPasswd || !slices.Equal(restart.Commands, []string{"/usr/bin/systemctl restart app"}) {
		t.Errorf("deploy restart rule = %+v", restart)
	}
	// A specific command without a password is worth a look, but it is not
	// root.
	if restart.RootEquivalent || !slices.Equal(restart.CriticalReasons, []string{"NOPASSWD"}) {
		t.Errorf("a specific command is flagged as root: %+v", restart)
	}
	var update *Rule
	for index := range snapshot.Rules {
		if snapshot.Rules[index].Source == "/etc/sudoers.d/50-deploy" && !snapshot.Rules[index].NoPasswd {
			update = &snapshot.Rules[index]
		}
	}
	if update == nil || !slices.Equal(update.Commands, []string{"/usr/bin/apt-get update"}) || !slices.Equal(update.RunAs, []string{"root"}) {
		t.Errorf("deploy update rule = %+v", update)
	}

	passwordless := snapshot.RootWithoutPassword()
	if len(passwordless) != 1 || passwordless[0].Source != "/etc/sudoers.d/90-cloud-init-users" {
		t.Errorf("root without a password = %+v", passwordless)
	}
	if len(snapshot.RootEquivalentRules()) != 2 {
		t.Errorf("root-equivalent = %+v", snapshot.RootEquivalentRules())
	}
}

func TestFedoraDefaultReadsTheOldIncludeForm(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers":           {Data: []byte(fedoraDefault)},
		"etc/sudoers.d/vagrant": {Data: []byte("vagrant ALL=(ALL) NOPASSWD: ALL\n")},
	})
	if len(snapshot.Problems) != 0 {
		t.Fatalf("problems = %+v", snapshot.Problems)
	}
	wheel := ruleAt(t, snapshot, "/etc/sudoers", 14)
	if !slices.Equal(wheel.Users, []string{"%wheel"}) || !wheel.RootEquivalent || wheel.NoPasswd {
		t.Errorf("wheel rule = %+v", wheel)
	}
	// The commented-out passwordless wheel rule is a comment.
	if len(snapshot.Rules) != 3 {
		t.Errorf("rules = %+v", snapshot.Rules)
	}
	vagrant := ruleAt(t, snapshot, "/etc/sudoers.d/vagrant", 1)
	if !vagrant.NoPasswd || !vagrant.RootEquivalent {
		t.Errorf("vagrant rule = %+v", vagrant)
	}
	if len(snapshot.Defaults) != 6 || snapshot.Defaults[0].Params[0] != "!visiblepw" {
		t.Errorf("defaults = %+v", snapshot.Defaults)
	}
	if snapshot.Defaults[4].Params[0] != `env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"` {
		t.Errorf("env_keep = %v", snapshot.Defaults[4].Params)
	}
}

func TestAliasesAreResolvedIntoTheRules(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers": {Data: []byte(`# Aliases may be defined after their use; sudo resolves them at match time.
ADMINS WEB = (OPS) NOPASSWD: SERVICES, PASSWD: /usr/bin/apt-get update
User_Alias ADMINS = alice, bob : AUDITORS = carol
Runas_Alias OPS = root, operator
Host_Alias WEB = web1, web2
Cmnd_Alias SERVICES = /usr/bin/systemctl restart nginx, \
    /usr/bin/systemctl reload nginx
Cmnd_Alias SHELLS = /bin/sh, /bin/bash
AUDITORS ALL = (ALL) !SHELLS, /usr/bin/journalctl
`)},
	})
	if len(snapshot.Problems) != 0 {
		t.Fatalf("problems = %+v", snapshot.Problems)
	}
	if len(snapshot.Rules) != 3 {
		t.Fatalf("rules = %d: %+v", len(snapshot.Rules), snapshot.Rules)
	}
	services := snapshot.Rules[0]
	if !slices.Equal(services.Users, []string{"alice", "bob"}) || !slices.Equal(services.Hosts, []string{"web1", "web2"}) {
		t.Errorf("services rule = %+v", services)
	}
	if !slices.Equal(services.RunAs, []string{"root", "operator"}) || !services.NoPasswd {
		t.Errorf("services run-as = %v, nopasswd = %v", services.RunAs, services.NoPasswd)
	}
	if !slices.Equal(services.Commands, []string{"/usr/bin/systemctl restart nginx", "/usr/bin/systemctl reload nginx"}) {
		t.Errorf("services commands = %v", services.Commands)
	}
	if services.RootEquivalent || services.AllHosts {
		t.Errorf("a service restart on two hosts is flagged: %+v", services)
	}
	update := snapshot.Rules[1]
	if update.NoPasswd || !slices.Equal(update.Commands, []string{"/usr/bin/apt-get update"}) {
		t.Errorf("update rule = %+v", update)
	}
	// A negated alias negates each member; a negated shell is not a way to
	// root.
	auditors := snapshot.Rules[2]
	if !slices.Equal(auditors.Users, []string{"carol"}) || !slices.Equal(auditors.Commands, []string{"!/bin/sh", "!/bin/bash", "/usr/bin/journalctl"}) {
		t.Errorf("auditors rule = %+v", auditors)
	}
	if auditors.RootEquivalent {
		t.Error("a rule that forbids the shells is flagged as root")
	}
}

func TestIncludesAreFollowedAndTheMissingOnesNamed(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers":          {Data: []byte("root ALL=(ALL) ALL\n#include /etc/sudoers.local # the old form\n@include /etc/sudoers.missing\n@includedir /etc/sudoers.d\n")},
		"etc/sudoers.local":    {Data: []byte("@include nested\nops ALL=(ALL) ALL\n")},
		"etc/nested":           {Data: []byte("@include /etc/sudoers.local\nDefaults:ops !authenticate\n")},
		"etc/sudoers.d/10-app": {Data: []byte("app ALL=(www-data) /usr/bin/php\n")},
	})
	paths := map[string]string{}
	for _, file := range snapshot.Files {
		paths[file.Path] = file.Reason
	}
	for _, expected := range []string{"/etc/sudoers", "/etc/sudoers.local", "/etc/nested", "/etc/sudoers.d/10-app"} {
		reason, opened := paths[expected]
		if !opened || reason != "" {
			t.Errorf("%s: opened = %v, reason = %q", expected, opened, reason)
		}
	}
	// A missing include is a file with a reason, not a silent gap, and a
	// loop through the nested include ends without a second read.
	if reason := paths["/etc/sudoers.missing"]; !strings.Contains(reason, "does not exist") {
		t.Errorf("the missing include: %q", reason)
	}
	if len(snapshot.Files) != 5 {
		t.Errorf("files = %+v", snapshot.Files)
	}
	sources := make([]string, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		sources = append(sources, rule.Source+":"+rule.Users[0])
	}
	if !slices.Equal(sources, []string{"/etc/sudoers:root", "/etc/sudoers.local:ops", "/etc/sudoers.d/10-app:app"}) {
		t.Errorf("rules = %v", sources)
	}
	if len(snapshot.Defaults) != 1 || snapshot.Defaults[0].Scope != "user" || snapshot.Defaults[0].Target != "ops" || !snapshot.Defaults[0].DisablesAuthentication {
		t.Errorf("defaults = %+v", snapshot.Defaults)
	}
	// A per-user !authenticate is not a global one.
	if snapshot.PasswordlessGlobally() {
		t.Error("a per-user default was read as global")
	}
	app := ruleAt(t, snapshot, "/etc/sudoers.d/10-app", 1)
	if app.RootEquivalent || !slices.Equal(app.RunAs, []string{"www-data"}) {
		t.Errorf("a grant as www-data is flagged as root: %+v", app)
	}
}

func TestAGlobalAuthenticateOffMakesEveryRootRulePasswordless(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers": {Data: []byte("Defaults !authenticate\n%wheel ALL=(ALL) ALL\n")},
	})
	if !snapshot.PasswordlessGlobally() {
		t.Fatal("the global !authenticate was not read")
	}
	if rules := snapshot.RootWithoutPassword(); len(rules) != 1 || rules[0].NoPasswd {
		t.Errorf("root without a password = %+v", rules)
	}
}

func TestTheShapesOfAUserSpecification(t *testing.T) {
	snapshot := parseTree(t, fstest.MapFS{
		"etc/sudoers": {Data: []byte(`alice ALL = /bin/ls : web1 = (:admin) /bin/cat
%#1000 ALL=(ALL) ALL # a gid, and a comment after the rule
#1001 ALL=(root) /usr/bin/su -
bob ALL=(ALL:ALL) NOEXEC: SETENV: /usr/bin/vim
carol ALL=(ALL) NOPASSWD: ALL, !/usr/bin/su
dave ALL=(ALL) CWD=/tmp TIMEOUT=5m /usr/bin/make
this line has no equals sign
eve ALL=
`)},
	})
	if len(snapshot.Problems) != 2 {
		t.Fatalf("problems = %+v", snapshot.Problems)
	}
	for _, problem := range snapshot.Problems {
		if problem.Line != 7 && problem.Line != 8 {
			t.Errorf("a problem at the wrong line: %+v", problem)
		}
	}

	// Two host sections give two rules; the second runs as the user with
	// the admin group, which is not root.
	first := ruleAt(t, snapshot, "/etc/sudoers", 1)
	if !first.AllHosts || !slices.Equal(first.Commands, []string{"/bin/ls"}) {
		t.Errorf("first section = %+v", first)
	}
	var second Rule
	for _, rule := range snapshot.Rules {
		if rule.Line == 1 && !rule.AllHosts {
			second = rule
		}
	}
	if !slices.Equal(second.Hosts, []string{"web1"}) || !slices.Equal(second.RunAsGroups, []string{"admin"}) || !second.RunAsSelf {
		t.Errorf("second section = %+v", second)
	}

	gid := ruleAt(t, snapshot, "/etc/sudoers", 2)
	if !slices.Equal(gid.Users, []string{"%#1000"}) || !gid.RootEquivalent {
		t.Errorf("gid rule = %+v", gid)
	}
	if strings.Contains(gid.Text, "comment") {
		t.Errorf("the comment stayed in the text: %q", gid.Text)
	}

	uid := ruleAt(t, snapshot, "/etc/sudoers", 3)
	if !slices.Equal(uid.Users, []string{"#1001"}) || !uid.RootEquivalent {
		t.Errorf("uid su rule = %+v", uid)
	}
	if !slices.Equal(uid.CriticalReasons, []string{"a shell or su as root"}) {
		t.Errorf("reasons = %v", uid.CriticalReasons)
	}

	vim := ruleAt(t, snapshot, "/etc/sudoers", 4)
	if !slices.Equal(vim.Tags, []string{"NOEXEC", "SETENV"}) || vim.NoPasswd || vim.RootEquivalent {
		t.Errorf("vim rule = %+v", vim)
	}

	// "NOPASSWD: ALL, !/usr/bin/su" is one rule: the tag carries over the
	// comma, and the negated su is listed as written.
	carol := ruleAt(t, snapshot, "/etc/sudoers", 5)
	if !slices.Equal(carol.Commands, []string{"ALL", "!/usr/bin/su"}) || !carol.NoPasswd || !carol.RootEquivalent {
		t.Errorf("carol rule = %+v", carol)
	}

	dave := ruleAt(t, snapshot, "/etc/sudoers", 6)
	if !slices.Equal(dave.Tags, []string{"CWD=/tmp", "TIMEOUT=5m"}) || !slices.Equal(dave.Commands, []string{"/usr/bin/make"}) {
		t.Errorf("dave rule = %+v", dave)
	}
}

// The unprivileged agent cannot open the file; the helper can. A refused
// main file is a policy that is not known, not an empty one.
func TestARefusedMainFileIsUnavailable(t *testing.T) {
	snapshot := Parse(refusingFS{}, MainFile, time.Now())
	if !strings.Contains(snapshot.UnavailableReason, "permission denied") {
		t.Errorf("unavailable reason = %q", snapshot.UnavailableReason)
	}
	if snapshot.Rules == nil || len(snapshot.Rules) != 0 {
		t.Errorf("rules = %v", snapshot.Rules)
	}
	absent := parseTree(t, fstest.MapFS{})
	if !strings.Contains(absent.UnavailableReason, "does not exist") {
		t.Errorf("a host without sudo: %q", absent.UnavailableReason)
	}
}

// refusingFS refuses every open the way the kernel refuses a reader
// without root.
type refusingFS struct{}

func (refusingFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}
