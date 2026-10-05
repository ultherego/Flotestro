package schedules

import (
	"strings"
	"testing"
)

// The command is kept in the file as one line and read back with a split on
// whitespace, so an argument that contains a space comes back as two. An
// approved "/usr/bin/rm -rf /var/tmp/old cache" would then remove two other
// directories - a destructive operation over something nobody approved.
func TestAnArgumentWithWhitespaceIsRefused(t *testing.T) {
	for _, argument := range []string{
		"/var/tmp/old cache",
		"--exclude=/srv/my backups",
		"a\tb",
		"a\nb",
		// The reader is strings.Fields, which splits on unicode.IsSpace, so a
		// separator does not have to be one of the five ASCII characters. A
		// path with a no-break space passed the guard and came back as two
		// arguments (audit of 6c38561, HP-09).
		"/srv/data/ cache",
		"/srv/data archive",
		"/srv/data　archive",
		"/srv/data\u0085archive",
	} {
		if _, err := ComposeCommand([]string{"/usr/bin/rm", "-rf", argument}); err == nil {
			t.Errorf("the argument %q was accepted; it comes back as two", argument)
		}
	}
}

// The same guard protects the whole round trip and not one of its ends: an
// argument the composer takes has to come back as itself, whatever rune is in
// it.
func TestEveryAcceptedArgumentComesBackAsOne(t *testing.T) {
	for _, argument := range []string{
		"/srv/data/ cache",
		"/srv/data archive",
		"/srv/data　archive",
		"/srv/data\u0085archive",
		"/srv/data/ärchiv",
	} {
		line, err := ComposeCommand([]string{"/usr/bin/rm", "-rf", argument})
		if err != nil {
			continue
		}
		if back := strings.Fields(line); len(back) != 3 {
			t.Errorf("the accepted argument %q came back as %d arguments: %q", argument, len(back)-2, back)
		}
	}
}

// What the schedule can carry still goes through, and comes back unchanged.
func TestACommandWithoutWhitespaceSurvivesTheRoundTrip(t *testing.T) {
	argv := []string{"/usr/bin/restic", "backup", "--tag=nightly", "/srv/data"}
	line, err := ComposeCommand(argv)
	if err != nil {
		t.Fatal(err)
	}
	back := strings.Fields(line)
	if len(back) != len(argv) {
		t.Fatalf("the command came back as %d arguments, want %d: %q", len(back), len(argv), line)
	}
	for i := range argv {
		if back[i] != argv[i] {
			t.Errorf("argument %d came back as %q, want %q", i, back[i], argv[i])
		}
	}
}
