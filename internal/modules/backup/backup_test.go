package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefinitionValidatesBasics(t *testing.T) {
	base := Definition{
		ID: "nightly", Tool: ToolRestic, Repository: "/srv/backup",
		Paths: []string{"/etc", "/var/lib/app"}, KeepLast: 7,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("a valid definition rejected: %v", err)
	}

	bad := map[string]Definition{
		"without an identifier":   {Tool: ToolRestic, Repository: "/srv/backup"},
		"identifier with a slash": {ID: "a/b", Tool: ToolRestic, Repository: "/srv/backup"},
		"unknown tool":            {ID: "nightly", Tool: "tar", Repository: "/srv/backup"},
		"without a repository":    {ID: "nightly", Tool: ToolRestic},
		"relative path":           {ID: "nightly", Tool: ToolRestic, Repository: "/srv/backup", Paths: []string{"etc"}},
		"runbook without a name":  {ID: "nightly", Tool: ToolRunbook},
		"runbook with a slash":    {ID: "nightly", Tool: ToolRunbook, Runbook: "../etc/passwd"},
	}
	for name, definition := range bad {
		if err := definition.Validate(); err == nil {
			t.Errorf("%s: the definition was accepted", name)
		}
	}
}

func TestValidateRestoreRequiresTargetAndPlan(t *testing.T) {
	good := Restore{SnapshotID: "abc123", Target: "/srv/restore", Overwrite: OverwriteEmpty}
	if err := ValidateRestore(good); err != nil {
		t.Fatalf("a valid restore rejected: %v", err)
	}

	// A restore straight into the host filesystem unpacks an old state onto a
	// running system - and that is a different operation than restoring a copy.
	for _, target := range []string{
		"/", "/etc", "/etc/nginx", "/usr/local", "/var", "/home", "/root",
		"/tmp/copy", "/var/tmp/copy", "/var/lib/flotestro/data",
	} {
		bad := good
		bad.Target = target
		if err := ValidateRestore(bad); err == nil {
			t.Errorf("a restore into %s was accepted", target)
		}
	}
	// The interior of home directories and /srv is an ordinary place for
	// data.
	for _, target := range []string{"/home/anna/copy", "/srv/restore", "/var/lib/copies"} {
		ok := good
		ok.Target = target
		if err := ValidateRestore(ok); err != nil {
			t.Errorf("a restore into %s rejected: %v", target, err)
		}
	}
	// Without an overwrite plan the effect of the operation is unknown.
	noPlan := good
	noPlan.Overwrite = ""
	if err := ValidateRestore(noPlan); err == nil {
		t.Error("a restore without an overwrite plan was accepted")
	}
	noCopy := good
	noCopy.SnapshotID = ""
	if err := ValidateRestore(noCopy); err == nil {
		t.Error("a restore without naming a copy was accepted")
	}
	relative := good
	relative.Target = "var/tmp/x"
	if err := ValidateRestore(relative); err == nil {
		t.Error("a restore into a relative path was accepted")
	}
	upwards := good
	upwards.Target = "/var/tmp/../../etc"
	if err := ValidateRestore(upwards); err == nil {
		t.Error("a target leaving the directory was accepted")
	}
}

func TestCheckTargetGuardsOverwritePlan(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckTarget(Restore{Target: empty, Overwrite: OverwriteEmpty}); err != nil {
		t.Fatalf("an empty directory rejected: %v", err)
	}

	busy := filepath.Join(dir, "busy")
	if err := os.Mkdir(busy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(busy, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckTarget(Restore{Target: busy, Overwrite: OverwriteEmpty}); err == nil {
		t.Fatal("a restore into a non-empty directory passed despite the 'empty' plan")
	}
	if err := CheckTarget(Restore{Target: busy, Overwrite: OverwriteAllowed}); err != nil {
		t.Fatalf("a restore with explicit consent to overwrite rejected: %v", err)
	}

	// The directory is not created half-way down the tree: a typo must not
	// create a directory in a random place.
	if err := CheckTarget(Restore{
		Target: filepath.Join(dir, "no", "such", "thing"), Overwrite: OverwriteEmpty,
	}); err == nil {
		t.Fatal("a target with a non-existent parent was accepted")
	}
}

func TestMaskRemovesCredentialsFromOutput(t *testing.T) {
	output := "repository /srv/backup opened with password secret-repository-password\n" +
		"pushing to https://user:secret-repository-password@backup.example.test/repo\n"
	masked := Mask(output, [][]byte{[]byte("secret-repository-password")})
	if strings.Contains(masked, "secret-repository-password") {
		t.Fatalf("the password stayed in the output:\n%s", masked)
	}
	if !strings.Contains(masked, "https://user:[masked]@backup.example.test/repo") {
		t.Fatalf("the address with credentials was not masked:\n%s", masked)
	}

	// Credentials in an address are masked also when the panel does not know
	// them: the password may be written into the repository address itself.
	unknown := Mask("https://user:secret-from-address@host/repo", nil)
	if strings.Contains(unknown, "secret-from-address") {
		t.Fatalf("the password from the address stayed in the output: %s", unknown)
	}
}

func TestLimitKeepsEndOfOutput(t *testing.T) {
	// The end of the output matters more than the beginning: the errors
	// and the operation summary are there.
	long := strings.Repeat("a", MaxOutput) + "END"
	trimmed := Limit(long)
	if len(trimmed) > MaxOutput+64 {
		t.Fatalf("the output after trimming has %d bytes", len(trimmed))
	}
	if !strings.HasSuffix(trimmed, "END") {
		t.Fatal("the trimmed output does not end where the original does")
	}
}

func TestLastSuccessTakesNewestCopy(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	snapshots := []Snapshot{
		{ID: "a", Time: now.Add(-72 * time.Hour)},
		{ID: "c", Time: now.Add(-2 * time.Hour)},
		{ID: "b", Time: now.Add(-24 * time.Hour)},
	}
	SortSnapshots(snapshots)
	if snapshots[0].ID != "a" || snapshots[2].ID != "c" {
		t.Fatalf("copies sorted as %+v", snapshots)
	}
	last := LastSuccess(snapshots)
	if last == nil || !last.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("last copy = %v", last)
	}
	// A repository without copies has no last copy date - and that is not
	// a zero date, only its absence.
	if LastSuccess(nil) != nil {
		t.Fatal("an empty repository got a last copy date")
	}
}

func TestValidateEnvironmentGuardsVariableNames(t *testing.T) {
	if err := ValidateEnvironment([]string{"AWS_ACCESS_KEY_ID", "B2_ACCOUNT_KEY"}); err != nil {
		t.Fatalf("valid names rejected: %v", err)
	}
	for _, name := range []string{"", "lower", "WITH SPACE", "PATH=x", "A;B"} {
		if err := ValidateEnvironment([]string{name}); err == nil {
			t.Errorf("the name %q was accepted", name)
		}
	}
}

func TestRunbookRefusesScriptWritableOutsideRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test checks the refusal for a foreign file; as root every file is our own")
	}
	runbook := &Runbook{}
	// A name outside the pattern falls off without touching the disk.
	if _, err := runbook.Path("../../etc/shadow"); err == nil {
		t.Fatal("a name leaving the directory was accepted")
	}
	// A file that does not exist is a refusal too - the panel does not
	// create runbooks.
	if _, err := runbook.Path("surely-no-such-thing"); err == nil {
		t.Fatal("a non-existent runbook was accepted")
	}
}

// A repository nobody has created yet is a state, not a failure to read one:
// it holds no copies, so the first backup into it can be confirmed by the copy
// that appears afterwards.
func TestARepositoryThatIsNotThereYetIsNamedAsSuch(t *testing.T) {
	for _, output := range []string{
		"Fatal: unable to open config file: stat /srv/backups/config: no such file or directory",
		"Fatal: repository does not exist: unable to open config file",
		"Repository /srv/backups does not exist.",
		"Repository not found",
	} {
		if !repositoryAbsent(output) {
			t.Errorf("the tool said the repository is not there and it was not recognised: %q", output)
		}
	}
	for _, output := range []string{
		"Fatal: wrong password or no key found",
		"Fatal: unable to create lock in backend: repository is already locked",
		"ssh: connect to host backup.example.test port 22: Connection refused",
		"",
	} {
		if repositoryAbsent(output) {
			t.Errorf("a refusal that leaves the state unknown was read as an empty repository: %q", output)
		}
	}
}

// A backup tool runs as root and has variables that run commands:
// RESTIC_PASSWORD_COMMAND, BORG_PASSCOMMAND, BORG_RSH. Borg is Python, which
// adds PYTHONPATH, and the loader adds LD_PRELOAD to every process there is.
// A check on the shape of a name admits all of them, so the names the panel
// may set are listed (audit of 6c38561, HP-01).
func TestOnlyTheCredentialsOfARepositoryAreAccepted(t *testing.T) {
	for _, name := range []string{
		"RESTIC_PASSWORD_COMMAND", "BORG_PASSCOMMAND", "BORG_RSH", "PYTHONPATH",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "HOME", "TMPDIR", "IFS",
	} {
		err := ValidateEnvironment([]string{name})
		if !errors.Is(err, ErrForbiddenVariable) {
			t.Errorf("the variable %s was accepted: %v", name, err)
		}
		// The refusal says what is allowed, not only that this is not.
		if err != nil && !strings.Contains(err.Error(), "RESTIC_REPOSITORY") {
			t.Errorf("the refusal of %s does not say what the panel may set: %v", name, err)
		}
	}
	if err := ValidateEnvironment([]string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RESTIC_REPOSITORY", "BORG_REPO",
	}); err != nil {
		t.Errorf("the credentials of a repository were refused: %v", err)
	}
	// A name of the wrong shape is still refused as such.
	if err := ValidateEnvironment([]string{"not a name"}); err == nil {
		t.Error("a name of the wrong shape was accepted")
	}
}

// os/exec deduplicates cmd.Env keeping the last occurrence of a name, so what
// the order carried has to come first: appended after the safe values it won
// over them, and the tool runs as root (HP-01).
func TestTheSafeVariablesWinOverTheOnesTheOrderCarried(t *testing.T) {
	order := Order{
		Environment: map[string][]byte{
			"PATH":   []byte("/tmp/attacker/bin"),
			"HOME":   []byte("/tmp/attacker"),
			"TMPDIR": []byte("/tmp/attacker"),
		},
		Password: []byte("secret"),
	}
	environment := toolEnvironment(order, "RESTIC_PASSWORD")

	// The effective value of a name is its last occurrence, which is what
	// os/exec keeps.
	effective := map[string]string{}
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		effective[name] = value
	}
	for name, wrong := range map[string]string{
		"PATH": "/tmp/attacker/bin", "HOME": "/tmp/attacker", "TMPDIR": "/tmp/attacker",
	} {
		if effective[name] == wrong {
			t.Errorf("%s came from the order: %s", name, effective[name])
		}
	}
	if !strings.HasPrefix(effective["PATH"], "/usr/local/sbin") {
		t.Errorf("PATH = %q", effective["PATH"])
	}
	if effective["RESTIC_PASSWORD"] != "secret" {
		t.Errorf("the password of the repository did not reach the tool: %q", effective["RESTIC_PASSWORD"])
	}
}
