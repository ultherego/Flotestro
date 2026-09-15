package sudoers

import (
	"testing"
	"testing/fstest"
	"time"
)

// FuzzParse feeds the sudoers parser a main file and one drop-in of any
// content.
//
// The parser reads files only root can write, so the input is trusted in
// origin but not in shape: sudo's grammar is wide and the files are edited
// by hand. A file the parser cannot read must show up as a problem in the
// picture, never as a crash of the helper. The property: the parser
// returns, every rule and every problem names the file and the line it
// came from, and the observed time is the one given.
func FuzzParse(f *testing.F) {
	dropin := "vagrant ALL=(ALL) NOPASSWD: ALL\n"
	for _, seed := range []string{
		debianDefault,
		fedoraDefault,
		"intruder ALL=(ALL) NOPASSWD: ALL\n",
		`# Aliases may be defined after their use; sudo resolves them at match time.
ADMINS WEB = (OPS) NOPASSWD: SERVICES, PASSWD: /usr/bin/apt-get update
User_Alias ADMINS = alice, bob : AUDITORS = carol
Runas_Alias OPS = root, operator
Host_Alias WEB = web1, web2
Cmnd_Alias SERVICES = /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx
`,
		`alice ALL = /bin/ls : web1 = (:admin) /bin/cat
%#1000 ALL=(ALL) ALL # a gid, and a comment after the rule
#1001 ALL=(root) /usr/bin/su -
bob ALL=(ALL:ALL) NOEXEC: SETENV: /usr/bin/vim
carol ALL=(ALL) NOPASSWD: ALL, !/usr/bin/su
dave ALL=(ALL) CWD=/tmp TIMEOUT=5m /usr/bin/make
this line has no equals sign
eve ALL=
`,
		"Defaults@web1 !authenticate\nDefaults:alice env_keep += \"MAIL PS1\"\nDefaults!\nDefaults>\n",
		"@include /etc/sudoers\n#include ../sudoers\n@includedir /\n#include %h.conf\n#include \"\"\n",
		"a ALL=(\nb ALL=()\nc ALL=(:)\nd ALL=( ALL ) ,\ne ALL=\\\n(root) /bin/sh\n",
		"Cycle_A ALL=ALL\nCmnd_Alias A = B\nCmnd_Alias B = A\nfrank ALL=(ALL) A\n",
		"",
		"\r\n\\\n",
	} {
		f.Add(seed, dropin)
	}

	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, main, extra string) {
		tree := fstest.MapFS{
			"etc/sudoers":               {Data: []byte(main)},
			"etc/sudoers.d/extra":       {Data: []byte(extra)},
			"etc/sudoers.d/README":      {Data: []byte("# a comment\n")},
			"etc/sudoers.d/.hidden":     {Data: []byte("hidden ALL=(ALL) ALL\n")},
			"etc/sudoers.d/backup~":     {Data: []byte("backup ALL=(ALL) ALL\n")},
			"etc/sudoers.d/nested/deep": {Data: []byte("deep ALL=(ALL) ALL\n")},
		}
		snapshot := Parse(tree, MainFile, now)
		if !snapshot.ObservedAt.Equal(now) {
			t.Fatalf("observed at %s, we want %s", snapshot.ObservedAt, now)
		}
		if len(snapshot.Files) == 0 {
			t.Fatal("the main file is not in the picture")
		}
		for _, rule := range snapshot.Rules {
			if rule.Source == "" || rule.Line <= 0 || rule.Text == "" {
				t.Fatalf("a rule without its origin: %+v", rule)
			}
		}
		for _, problem := range snapshot.Problems {
			if problem.Source == "" || problem.Line <= 0 || problem.Reason == "" {
				t.Fatalf("a problem without its origin or reason: %+v", problem)
			}
		}
	})
}
