// Package sudoers reads the local sudo policy of a host: /etc/sudoers and
// the files it includes.
//
// The directory's sudo rules are read centrally; the local files are what
// an administrator wrote on the host itself, and they apply next to the
// directory's rules - or instead of them on a host outside the domain.
// The panel shows both and marks the grants that amount to root, because
// "who can become root on this host" is the question the operator asks.
//
// The parser resolves the aliases and follows the includes, but it does
// not decide who is allowed what: it reports the rules as written, with
// their file and line, and the judgement is made in the panel. A line it
// does not understand is reported as a problem rather than dropped, so a
// rule the panel does not show is a rule the operator knows it missed.
package sudoers

import (
	"slices"
	"strings"
	"time"
)

// Snapshot is the local sudo policy of one host.
type Snapshot struct {
	Rules    []Rule    `json:"rules"`
	Defaults []Default `json:"defaults"`
	// Files lists every file the parser opened, with the reason where the
	// read failed: a drop-in the helper could not read is a policy the
	// panel does not know rather than an absent one.
	Files []File `json:"files"`
	// Problems lists the lines the parser did not understand.
	Problems []Problem `json:"problems,omitempty"`
	// UnavailableReason says why the main file was not read at all.
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
}

// Rule is one grant: who may run what, where and as whom. A user
// specification with several command lists gives several rules, one per
// run-as and tag combination, so every rule has one answer to "without a
// password?".
type Rule struct {
	// Users are the grantees as written: user names, %group, %#gid,
	// +netgroup, #uid, with the aliases resolved. A leading "!" is a
	// negation.
	Users []string `json:"users"`
	Hosts []string `json:"hosts"`
	// RunAs and RunAsGroups are the identities the commands may run as.
	// An empty RunAs is sudo's default, which is root.
	RunAs       []string `json:"run_as,omitempty"`
	RunAsGroups []string `json:"run_as_groups,omitempty"`
	// RunAsSelf marks a "(:group)" specification: the commands run as the
	// invoking user with another group, which is not root.
	RunAsSelf bool     `json:"run_as_self,omitempty"`
	Commands  []string `json:"commands"`
	// Tags are the ones other than NOPASSWD and PASSWD - NOEXEC, SETENV,
	// LOG_OUTPUT - which the operator reads but the panel does not judge.
	Tags     []string `json:"tags,omitempty"`
	NoPasswd bool     `json:"nopasswd"`
	// The categories, mirroring the directory's rule shape so that the
	// panel shows both sources in one table.
	AllUsers     bool `json:"all_users"`
	AllHosts     bool `json:"all_hosts"`
	AllCommands  bool `json:"all_commands"`
	RunAsAnyUser bool `json:"run_as_any_user"`
	// RootEquivalent says the rule lets its grantees become root: every
	// command, or a shell, as root or as anyone. A rule granted to root
	// itself is not root-equivalent - root gains nothing.
	RootEquivalent bool `json:"root_equivalent"`
	// Critical marks a rule of raised risk, with the reasons.
	Critical        bool     `json:"critical"`
	CriticalReasons []string `json:"critical_reasons,omitempty"`
	Source          string   `json:"source"`
	Line            int      `json:"line"`
	Text            string   `json:"text"`
}

// Default is one Defaults line.
type Default struct {
	// Scope is empty for a global default, or user, host, command or
	// runas; Target is what the scope names.
	Scope  string   `json:"scope,omitempty"`
	Target string   `json:"target,omitempty"`
	Params []string `json:"params"`
	// DisablesAuthentication marks "!authenticate": in the global scope it
	// makes every rule passwordless, whatever the rule says.
	DisablesAuthentication bool   `json:"disables_authentication"`
	Source                 string `json:"source"`
	Line                   int    `json:"line"`
	Text                   string `json:"text"`
}

// File is one file the parser opened.
type File struct {
	Path string `json:"path"`
	// IncludedFrom names the file whose include directive led here.
	IncludedFrom string `json:"included_from,omitempty"`
	Lines        int    `json:"lines"`
	Reason       string `json:"reason,omitempty"`
}

// Problem is a line the parser did not understand.
type Problem struct {
	Source string `json:"source"`
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// PasswordlessGlobally says whether a global Defaults line turns
// authentication off for everybody.
func (s Snapshot) PasswordlessGlobally() bool {
	for _, entry := range s.Defaults {
		if entry.Scope == "" && entry.DisablesAuthentication {
			return true
		}
	}
	return false
}

// RootWithoutPassword lists the rules that make somebody root without a
// password: root-equivalent rules tagged NOPASSWD, and every
// root-equivalent rule when a global default turns authentication off.
func (s Snapshot) RootWithoutPassword() []Rule {
	global := s.PasswordlessGlobally()
	var result []Rule
	for _, rule := range s.Rules {
		if rule.RootEquivalent && (rule.NoPasswd || global) {
			result = append(result, rule)
		}
	}
	return result
}

// RootEquivalentRules lists the rules that let somebody become root.
func (s Snapshot) RootEquivalentRules() []Rule {
	var result []Rule
	for _, rule := range s.Rules {
		if rule.RootEquivalent {
			result = append(result, rule)
		}
	}
	return result
}

// judge fills in the categories and the risk of a rule from its resolved
// lists. It is the only place the module says anything beyond what the
// file says, and what it says is one word: whether the grant is root.
func (r *Rule) judge() {
	r.AllUsers = slices.Contains(r.Users, "ALL")
	r.AllHosts = slices.Contains(r.Hosts, "ALL")
	r.AllCommands = slices.Contains(r.Commands, "ALL")
	r.RunAsAnyUser = slices.Contains(r.RunAs, "ALL")

	// The run-as reaches root when the rule names nobody (sudo's default is
	// root), names root, or names everyone.
	reachesRoot := (len(r.RunAs) == 0 && !r.RunAsSelf) || r.RunAsAnyUser ||
		slices.Contains(r.RunAs, "root") || slices.Contains(r.RunAs, "#0")
	escapes := r.AllCommands || slices.ContainsFunc(r.Commands, isShellOrSu)

	// A rule whose only grantees are root itself grants nothing new.
	grantsToOthers := slices.ContainsFunc(r.Users, func(user string) bool {
		return user != "root" && user != "#0" && !strings.HasPrefix(user, "!")
	})
	r.RootEquivalent = grantsToOthers && reachesRoot && escapes

	var reasons []string
	if r.RootEquivalent {
		switch {
		case r.AllCommands && r.RunAsAnyUser:
			reasons = append(reasons, "every command as any user")
		case r.AllCommands:
			reasons = append(reasons, "every command as root")
		default:
			reasons = append(reasons, "a shell or su as root")
		}
	} else if r.AllCommands && grantsToOthers {
		reasons = append(reasons, "every command")
	}
	if r.NoPasswd && grantsToOthers {
		reasons = append(reasons, "NOPASSWD")
	}
	if r.AllUsers {
		reasons = append(reasons, "every user")
	}
	r.Critical = len(reasons) > 0
	r.CriticalReasons = reasons
}

// isShellOrSu says whether a command is a way to a root shell: a shell
// itself, su, or sudo. The arguments do not matter - "/bin/bash -c" is
// still a shell.
func isShellOrSu(command string) bool {
	if strings.HasPrefix(command, "!") {
		return false
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	base := fields[0]
	if index := strings.LastIndex(base, "/"); index >= 0 {
		base = base[index+1:]
	}
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "su", "sudo", "env":
		return true
	}
	return false
}
