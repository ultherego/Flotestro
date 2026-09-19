package packages

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are the output of the tools on an Arch host under LC_ALL=C.

const checkupdatesFixture = `linux 6.16.5.arch1-1 -> 6.16.6.arch1-1
glibc 2.42+r25+g4eec3d0d3d0c-1 -> 2.42+r30+g6ae1c8c4a1a0-1
which 2.23-1 -> 2.23-2
flotestro-agent 0.9.0-1 -> 0.9.1-1
`

func TestCheckupdatesLinesBecomeChanges(t *testing.T) {
	changes := ParseCheckupdates(checkupdatesFixture + "\nnot a change\n")
	if len(changes) != 4 {
		t.Fatalf("read %d changes, expected 4: %+v", len(changes), changes)
	}
	if changes[0].Name != "linux" || changes[0].CurrentVersion != "6.16.5.arch1-1" ||
		changes[0].CandidateVersion != "6.16.6.arch1-1" {
		t.Errorf("the first change was read as %+v", changes[0])
	}
	// Arch has no security metadata: nothing may be marked as a security
	// update, and nothing as harmless either - the adapter says "unknown"
	// through its own error rather than through this flag.
	for _, change := range changes {
		if change.Security {
			t.Errorf("%s was marked as a security update without metadata", change.Name)
		}
	}
}

// A security-only plan and a partial upgrade are refusals with a code, not
// empty plans: an empty plan would read as "nothing to do".
func TestPacmanRefusesWhatArchDoesNotSupport(t *testing.T) {
	p := &Pacman{}
	_, err := p.Plan(t.Context(), Options{SecurityOnly: true})
	if !errors.Is(err, ErrSecurityUnknown) {
		t.Errorf("a security-only plan ended with %v", err)
	}
	if code, _ := ErrorCodeOf(err); code != ErrorSecurityUnknown {
		t.Errorf("the code of a security-only plan is %q", code)
	}
	_, err = p.Plan(t.Context(), Options{Packages: []string{"which"}})
	if !errors.Is(err, ErrPartialUpgrade) {
		t.Errorf("a partial upgrade plan ended with %v", err)
	}
	if code, _ := ErrorCodeOf(err); code != ErrorPartialUpgrade {
		t.Errorf("the code of a partial upgrade is %q", code)
	}
	_, err = p.Upgrade(t.Context(), Options{Packages: []string{"which"}})
	if !errors.Is(err, ErrPartialUpgrade) {
		t.Errorf("a partial upgrade ended with %v", err)
	}
	if !Refused(err) {
		t.Error("a partial upgrade is not a refusal")
	}
}

func TestPacmanPrintedTargetsCarryTheOriginAndTheSize(t *testing.T) {
	output := "linux\t6.16.6.arch1-1\tcore\t150000000\nwhich\t2.23-2\tcore\t17000\n"
	targets := ParsePacmanTargets(output)
	if len(targets) != 2 {
		t.Fatalf("read %d targets: %+v", len(targets), targets)
	}
	if targets["linux"].Origin != "core" || targets["linux"].Size != 150000000 {
		t.Errorf("linux was read as %+v", targets["linux"])
	}
}

func TestPacmanQueryVersionsAreSplit(t *testing.T) {
	pkgs := ParsePacmanQuery("acl 2.3.2-1\ndbus 1:1.16.2-1\nyay-bin 12.5.0-1\nbroken\n")
	if len(pkgs) != 3 {
		t.Fatalf("read %d packages: %+v", len(pkgs), pkgs)
	}
	if pkgs[1].Epoch != "1" || pkgs[1].Version != "1.16.2" || pkgs[1].Release != "1" {
		t.Errorf("the epoch was read as %+v", pkgs[1])
	}
	if pkgs[0].Epoch != "" || pkgs[0].Version != "2.3.2" || pkgs[0].Release != "1" {
		t.Errorf("a plain version was read as %+v", pkgs[0])
	}
	if pkgs[0].EVR() != "2.3.2-1" || pkgs[1].EVR() != "1:1.16.2-1" {
		t.Errorf("EVR = %q, %q", pkgs[0].EVR(), pkgs[1].EVR())
	}
}

// A package from the AUR is a local package; a package from a custom sync
// repository is a third-party one; the packages of core and extra belong to
// the distribution. Without the sync databases nothing is known - and that
// is an answer other than "the distribution's".
func TestPacmanOriginsAreClassified(t *testing.T) {
	pkgs := ParsePacmanQuery("acl 2.3.2-1\nyay-bin 12.5.0-1\nfoo-tool 1.0-1\nmystery 1.0-1\n")
	foreign := map[string]bool{"yay-bin": true}
	repositories := ParsePacmanSyncList(
		"core acl 2.3.2-1 [installed]\nextra acl 2.3.2-1\ncustom foo-tool 1.0-1 [installed]\n")
	FillPacmanOrigin(pkgs, foreign, true, repositories)

	want := map[string][2]string{
		"acl":      {"core", OriginDistribution},
		"yay-bin":  {OriginForeign, OriginLocal},
		"foo-tool": {"custom", OriginThirdParty},
		"mystery":  {"", OriginUnknown},
	}
	for _, pkg := range pkgs {
		expected := want[pkg.Name]
		if pkg.Origin != expected[0] || pkg.OriginClass != expected[1] {
			t.Errorf("%s: origin %q/%q, expected %q/%q",
				pkg.Name, pkg.Origin, pkg.OriginClass, expected[0], expected[1])
		}
	}
}

// pacman.conf as the distribution ships it, with a mirror list, a commented
// out section and a custom repository of the administrator.
const pacmanConfFixture = `#
# /etc/pacman.conf
#
[options]
HoldPkg     = pacman glibc
Architecture = auto
IgnorePkg   = linux-lts
#IgnoreGroup =
Color
CheckSpace
SigLevel    = Required DatabaseOptional
LocalFileSigLevel = Optional

[core]
Include = MIRRORLIST

[extra]
Include = MIRRORLIST

#[multilib]
#Include = MIRRORLIST

[custom]
SigLevel = Never
Server = https://packages.example.test/arch/$arch
`

// writePacmanFixture puts the configuration and its mirror list in a
// temporary directory.
func writePacmanFixture(t *testing.T, content string) string {
	t.Helper()
	directory := t.TempDir()
	mirrorlist := filepath.Join(directory, "mirrorlist")
	if err := os.WriteFile(mirrorlist, []byte("## Arch Linux repository mirrorlist\n"+
		"Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n"+
		"Server = https://mirror.example.test/archlinux/$repo/os/$arch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "pacman.conf")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(content, "MIRRORLIST", mirrorlist)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPacmanConfSectionsBecomeSources(t *testing.T) {
	path := writePacmanFixture(t, pacmanConfFixture)
	config, err := parsePacmanConf(path)
	if err != nil {
		t.Fatal(err)
	}
	sources := pacmanRepositories(config)
	byID := map[string]Repository{}
	for _, source := range sources {
		byID[source.ID] = source
	}
	if len(sources) != 3 {
		t.Fatalf("recognised %d sources: %+v", len(sources), sources)
	}
	core := byID["core"]
	if core.URL != "https://geo.mirror.pkgbuild.com/$repo/os/$arch" {
		t.Errorf("core has no server from the mirror list: %+v", core)
	}
	// The options section sets the signature level for a section without
	// one of its own.
	if !core.Signed || !core.Enabled || core.Managed {
		t.Errorf("core was read as %+v", core)
	}
	custom := byID["custom"]
	if custom.Signed || custom.URL != "https://packages.example.test/arch/$arch" {
		t.Errorf("the custom source was read as %+v", custom)
	}
	if _, present := byID["multilib"]; present {
		t.Error("a commented out section was read as a source")
	}
}

func TestSigLevelSaysWhetherSignaturesAreRequired(t *testing.T) {
	cases := map[string]bool{
		"Required DatabaseOptional": true,
		"PackageRequired":           true,
		"Never":                     false,
		"Optional TrustAll":         false,
		"Required PackageOptional":  false,
		"":                          false,
	}
	for level, want := range cases {
		if got := SigLevelRequiresSignature(level); got != want {
			t.Errorf("SigLevel %q: required = %v, expected %v", level, got, want)
		}
	}
}

// A source written by the panel is a marked section; writing it again
// replaces it, and removing it takes the marker along. A section of the
// same name that is not the panel's stays untouched - and the write is
// refused rather than doubled.
func TestPacmanSourcesAreWrittenAndRemovedIdempotently(t *testing.T) {
	repo := Repository{
		ID: "internal", URL: "https://packages.example.test/arch/$arch",
		Enabled: true, Signed: true,
	}
	content, err := AddPacmanSource(pacmanConfFixture, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, panelMarker+"\n[internal]\nSigLevel = Required DatabaseOptional\n"+
		"Server = https://packages.example.test/arch/$arch\n") {
		t.Fatalf("the section was not written:\n%s", content)
	}
	repo.URL = "https://mirror.example.test/arch/$arch"
	again, err := AddPacmanSource(content, repo)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(again, "[internal]") != 1 {
		t.Fatalf("the second write doubled the section:\n%s", again)
	}
	if !strings.Contains(again, "Server = https://mirror.example.test/arch/$arch") {
		t.Fatalf("the second write did not replace the address:\n%s", again)
	}
	// The sections of the file are all still there.
	for _, header := range []string{"[options]", "[core]", "[extra]", "[custom]", "#[multilib]"} {
		if !strings.Contains(again, header) {
			t.Errorf("%s disappeared from the file", header)
		}
	}

	removed, err := RemovePacmanSource(again, "internal")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(removed, "internal") || strings.Contains(removed, panelMarker) {
		t.Fatalf("the removal left traces:\n%s", removed)
	}
	if strings.TrimSpace(removed) != strings.TrimSpace(pacmanConfFixture) {
		t.Fatalf("the removal changed the rest of the file:\n%s", removed)
	}

	// The administrator's section is not the panel's to rewrite.
	if _, err := AddPacmanSource(pacmanConfFixture, Repository{ID: "custom", URL: "https://x.example.test/",
		Enabled: true}); err == nil {
		t.Fatal("the panel took over a section it does not manage")
	}
	// A commented out section of the distribution is a comment, not a
	// source of the same name.
	if _, err := AddPacmanSource(pacmanConfFixture, Repository{ID: "multilib",
		URL: "https://x.example.test/", Enabled: true}); err != nil {
		t.Fatalf("a commented out section blocked the write: %v", err)
	}
}

func TestADisabledPacmanSourceIsCommentedOutAndStillVisible(t *testing.T) {
	repo := Repository{ID: "internal", URL: "https://packages.example.test/arch/$arch", Signed: true}
	content, err := AddPacmanSource(pacmanConfFixture, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "#[internal]\n#SigLevel = Required DatabaseOptional\n#Server = ") {
		t.Fatalf("the disabled source is not commented out:\n%s", content)
	}
	path := writePacmanFixture(t, content)
	config, err := parsePacmanConf(path)
	if err != nil {
		t.Fatal(err)
	}
	var found *Repository
	for _, source := range pacmanRepositories(config) {
		if source.ID == "internal" {
			copied := source
			found = &copied
		}
	}
	if found == nil {
		t.Fatal("the disabled source is not visible to the panel")
	}
	if found.Enabled || !found.Managed || !found.Signed ||
		found.URL != "https://packages.example.test/arch/$arch" {
		t.Errorf("the disabled source was read as %+v", *found)
	}
}

// The hold lives in one marked line of the options section. Holding again
// changes nothing, releasing the last package removes the line, and a
// package held by the administrator's own line is reported rather than
// silently left held.
func TestPacmanHoldsAreOneMarkedLine(t *testing.T) {
	held, err := SetPacmanHolds(pacmanConfFixture, []string{"which"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(held, holdMarker+"\nIgnorePkg = which\n") {
		t.Fatalf("the hold was not written:\n%s", held)
	}
	// The line stands in the options section, before the first repository.
	if strings.Index(held, holdMarker) > strings.Index(held, "[core]") {
		t.Fatalf("the hold landed outside the options section:\n%s", held)
	}
	managed, all := PacmanHolds(held)
	if len(managed) != 1 || managed[0] != "which" {
		t.Errorf("managed holds = %v", managed)
	}
	// The administrator's own IgnorePkg counts as a hold as well: the
	// package will not get updates whoever held it.
	if len(all) != 2 || all[0] != "linux-lts" || all[1] != "which" {
		t.Errorf("all holds = %v", all)
	}

	again, err := SetPacmanHolds(held, []string{"which", "vim"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(again, holdMarker) != 1 || !strings.Contains(again, "IgnorePkg = vim which\n") {
		t.Fatalf("the second hold is not idempotent:\n%s", again)
	}

	released, err := SetPacmanHolds(again, []string{"vim", "which"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(released, holdMarker) {
		t.Fatalf("releasing the last package left the line:\n%s", released)
	}
	if strings.TrimSpace(released) != strings.TrimSpace(pacmanConfFixture) {
		t.Fatalf("the release changed the rest of the file:\n%s", released)
	}

	if _, err := SetPacmanHolds(pacmanConfFixture, []string{"linux-lts"}, false); err == nil {
		t.Fatal("a package held by the administrator was released without a word")
	}
	// Releasing a package nobody held is nothing to do.
	if same, err := SetPacmanHolds(pacmanConfFixture, []string{"htop"}, false); err != nil ||
		same != pacmanConfFixture {
		t.Errorf("releasing an unheld package changed the file (%v)", err)
	}
}

func TestPacmanHoldsWithoutAnOptionsSectionCreateOne(t *testing.T) {
	held, err := SetPacmanHolds("[core]\nInclude = /etc/pacman.d/mirrorlist\n", []string{"which"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(held, "[options]\n"+holdMarker+"\nIgnorePkg = which\n[core]") {
		t.Fatalf("the options section was not created:\n%s", held)
	}
}

func TestPacmanFailuresAreClassified(t *testing.T) {
	p := &Pacman{}
	locked := p.failure("pacman -Syu", commandResult{Ran: true, ExitCode: 1,
		Stderr: "error: failed to init transaction (unable to lock database)\n" +
			"error: could not lock database: File exists\n" +
			"  if you're sure a package manager is not already\n  running, you can remove /var/lib/pacman/db.lck\n"})
	if !errors.Is(locked, ErrLocked) {
		t.Errorf("a lock was classified as %v", locked)
	}

	trust := p.failure("pacman -Syu", commandResult{Ran: true, ExitCode: 1,
		Stderr: "error: which: signature from \"Levente Polyak <anthraxx@archlinux.org>\" is unknown trust\n" +
			":: File /var/cache/pacman/pkg/which-2.23-2-x86_64.pkg.tar.zst is corrupted (invalid or corrupted package (PGP signature)).\n" +
			"error: failed to commit transaction (invalid or corrupted package)\nErrors occurred, no packages were upgraded.\n"})
	if code, ok := ErrorCodeOf(trust); ok {
		t.Errorf("a trust problem got the code %q of another error", code)
	}
	if !strings.Contains(trust.Error(), "does not trust") || !strings.Contains(trust.Error(), "anthraxx") {
		t.Errorf("the trust problem does not name the key: %v", trust)
	}

	missing := p.failure("pacman -S", commandResult{Ran: true, ExitCode: 1,
		Stderr: "error: target not found: nosuchpackage\n"})
	if !strings.Contains(missing.Error(), "target not found: nosuchpackage") {
		t.Errorf("a missing target was described as %v", missing)
	}

	conflict := p.failure("pacman -Rs", commandResult{Ran: true, ExitCode: 1,
		Stderr: "checking dependencies...\nerror: failed to prepare transaction (could not satisfy dependencies)\n" +
			":: removing glibc breaks dependency 'glibc' required by bash\n"})
	if !strings.Contains(conflict.Error(), "removing glibc breaks dependency") {
		t.Errorf("a dependency conflict was described as %v", conflict)
	}
	if reason := PacmanUnresolvable("error: unresolvable package conflicts detected\n" +
		"error: failed to prepare transaction (conflicting dependencies)\n:: foo-1 and bar-2 are in conflict\n"); reason == "" {
		t.Error("a package conflict was not recognised")
	}

	database := p.failure("pacman -Syu", commandResult{Ran: true, ExitCode: 1,
		Stderr: "error: failed to prepare transaction (invalid or corrupted database)\n"})
	if !errors.Is(database, ErrDatabaseBroken) {
		t.Errorf("a damaged database was classified as %v", database)
	}
	if code, _ := ErrorCodeOf(database); code != ErrorDatabaseBroken {
		t.Errorf("the code of a damaged database is %q", code)
	}
}

func TestPacmanTargetsNotFoundAreListed(t *testing.T) {
	missing := PacmanTargetsNotFound("error: target not found: foo\nerror: target not found: bar\n")
	if len(missing) != 2 || missing[0] != "foo" || missing[1] != "bar" {
		t.Errorf("missing = %v", missing)
	}
	if without([]string{"foo", "which", "bar"}, missing)[0] != "which" {
		t.Error("the missing targets were not dropped from the order")
	}
}

func TestPacmanPrintedNamesSkipTheNoise(t *testing.T) {
	names := pacmanPrintedNames("warning: something\nwhich\ntree\n:: note\n\n")
	if len(names) != 2 || names[0] != "which" || names[1] != "tree" {
		t.Errorf("names = %v", names)
	}
}

// The steps pacman counts are progress like the steps of dnf.
func TestPacmanStepsAreProgress(t *testing.T) {
	progress, ok := dnfStepFrom("(3/12) upgrading glibc")
	if !ok || progress.Step != 3 || progress.Total != 12 || progress.Message != "upgrading glibc" {
		t.Errorf("the step was read as %+v (%v)", progress, ok)
	}
	if _, ok := dnfStepFrom(":: Processing package changes..."); ok {
		t.Error("a heading was read as a step")
	}
}

func TestArchBasePackagesAreProtected(t *testing.T) {
	for _, pkg := range []string{"base", "linux", "pacman", "glibc", "openssh", "systemd"} {
		if !Protected(pkg) {
			t.Errorf("%s is not protected", pkg)
		}
	}
	if Protected("linux-firmware") || Protected("which") {
		t.Error("an ordinary package was treated as protected")
	}
}

func TestKernelPackagesAreRecognised(t *testing.T) {
	for _, name := range []string{"linux", "linux-lts", "linux-zen", "linux-cachyos"} {
		if !pacmanKernelPackage(name) {
			t.Errorf("%s was not recognised as a kernel", name)
		}
	}
	for _, name := range []string{"linux-firmware", "linux-headers", "linux-api-headers", "linux-lts-docs"} {
		if pacmanKernelPackage(name) {
			t.Errorf("%s was treated as a kernel", name)
		}
	}
}

// The repair removes a lock nobody holds and leaves the lock of a running
// pacman alone.
func TestAStaleLockIsRemovedOnlyWithoutARunningPacman(t *testing.T) {
	directory := t.TempDir()
	lock := filepath.Join(directory, "db.lck")
	proc := filepath.Join(directory, "proc")
	if err := os.MkdirAll(filepath.Join(proc, "4242"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "4242", "comm"), []byte("pacman\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	removed, running, err := removeStaleLock(lock, proc)
	if err != nil || removed || running != "pid 4242" {
		t.Fatalf("with a running pacman: removed=%v running=%q err=%v", removed, running, err)
	}
	if !fileExists(lock) {
		t.Fatal("the lock of a running pacman was removed")
	}

	if err := os.WriteFile(filepath.Join(proc, "4242", "comm"), []byte("bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, running, err = removeStaleLock(lock, proc)
	if err != nil || !removed || running != "" {
		t.Fatalf("without a running pacman: removed=%v running=%q err=%v", removed, running, err)
	}
	if fileExists(lock) {
		t.Fatal("the stale lock stayed")
	}
	// No lock is nothing to do.
	if removed, _, _ := removeStaleLock(lock, proc); removed {
		t.Fatal("a missing lock was reported as removed")
	}
}

func TestDatabaseCheckComplaintsNameThePackage(t *testing.T) {
	blocked := ParsePacmanDatabaseCheck(
		"error: missing 'libfoo.so=1-64' dependency for 'bar'\n" +
			"error: missing 'libfoo.so=1-64' dependency for 'bar'\n" +
			"error: could not open database\n")
	if len(blocked) != 2 {
		t.Fatalf("blocked = %+v", blocked)
	}
	if blocked[0].Name != "bar" || !strings.Contains(blocked[0].Status, "missing 'libfoo.so=1-64'") {
		t.Errorf("the first complaint was read as %+v", blocked[0])
	}
	if blocked[1].Name != "database" {
		t.Errorf("a complaint without a package was read as %+v", blocked[1])
	}
}

func TestValidateRepositoryKnowsPacman(t *testing.T) {
	repo := Repository{ID: "internal", URL: "https://packages.example.test/arch/$arch", Enabled: true, Signed: true}
	if err := ValidateRepository(repo, PacmanName, false); err != nil {
		t.Fatalf("a correct pacman source was rejected: %v", err)
	}
	withSuite := repo
	withSuite.Suites = []string{"stable"}
	if err := ValidateRepository(withSuite, PacmanName, false); err == nil {
		t.Fatal("a pacman source with a suite was accepted")
	}
	withPassword := repo
	withPassword.Username = "fleet"
	if err := ValidateRepository(withPassword, PacmanName, true); err == nil {
		t.Fatal("a pacman source with a password was accepted")
	}
	files, err := SourceFiles(repo, PacmanName, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/etc/pacman.d/flotestro-internal.asc" {
		t.Errorf("the files of a signed pacman source: %+v", files)
	}
	if paths := SourcePaths("internal", PacmanName); len(paths) != 1 || paths[0] != files[0].Path {
		t.Errorf("SourcePaths = %v", paths)
	}
}

func TestPacmanEntriesAreSplit(t *testing.T) {
	key, value, ok := pacmanEntry("Server = https://x.example.test/$repo")
	if !ok || key != "Server" || value != "https://x.example.test/$repo" {
		t.Errorf("entry = %q %q %v", key, value, ok)
	}
	if key, _, ok := pacmanEntry("Color"); !ok || key != "Color" {
		t.Errorf("a bare option was read as %q %v", key, ok)
	}
	if _, _, ok := pacmanEntry("# IgnorePkg = foo"); ok {
		t.Error("a comment was read as an entry")
	}
	if header, ok := pacmanSectionHeader("[extra-testing]"); !ok || header != "extra-testing" {
		t.Errorf("header = %q %v", header, ok)
	}
}

// TestPacmanPlanDoesNotDependOnCheckupdates guards the declaration of the
// adapter: the plan is computed from a database that is already on the host,
// so a host without pacman-contrib reports the plan as available and really
// makes one. A feature that said "plan" only where checkupdates is installed
// hid an operation that works, and a plan that failed after the order would
// be worse still.
func TestPacmanPlanDoesNotDependOnCheckupdates(t *testing.T) {
	features := PacmanFeatures(true)
	for _, feature := range []string{"repair", "hold", "plan"} {
		if !features[feature] {
			t.Errorf("%s is reported as unavailable on a host with pacman", feature)
		}
	}
	// The repositories of Arch carry no security metadata, so the count of
	// security updates is unknown rather than zero - that stays false
	// whatever is installed.
	if features["security"] {
		t.Error("the security feature is reported on a distribution without security metadata")
	}
	if PacmanReason(true) == "" {
		t.Error("a host with pacman still has something to say about the security count")
	}
	if strings.Contains(PacmanReason(true), "checkupdates") {
		t.Errorf("the reason names checkupdates, which the plan does not need: %q", PacmanReason(true))
	}
	if !strings.Contains(PacmanReason(false), "pacman") {
		t.Errorf("the reason of a host without pacman does not name it: %q", PacmanReason(false))
	}
	for name, available := range PacmanFeatures(false) {
		if available {
			t.Errorf("a host without pacman reports the feature %s", name)
		}
	}
}

// TestPacmanDatabaseArgumentsLeaveTheHostDatabaseAlone guards the query
// against the host's own database: an empty --dbpath would point pacman at
// the root of the file system, so the argument is left out entirely.
func TestPacmanDatabaseArgumentsLeaveTheHostDatabaseAlone(t *testing.T) {
	if args := pacmanDatabaseArgs(""); args != nil {
		t.Errorf("args = %v, expected the query of the host's own database", args)
	}
	args := pacmanDatabaseArgs(SyncCopyDir)
	if len(args) != 2 || args[0] != "--dbpath" || args[1] != SyncCopyDir {
		t.Errorf("args = %v", args)
	}
}

// TestPlanMetadataMissingIsARefusal guards that a host with no repository
// metadata at all says so with its own code instead of answering with an
// empty plan - nothing pending and nothing read look the same to an
// operator, and only one of them is true.
func TestPlanMetadataMissingIsARefusal(t *testing.T) {
	code, ok := ErrorCodeOf(ErrPlanMetadataMissing)
	if !ok || code != ErrorPlanMetadataMissing {
		t.Errorf("code = %q, %v", code, ok)
	}
	if !Refused(ErrPlanMetadataMissing) {
		t.Error("nothing was attempted, so the error is a refusal of the host")
	}
	if !strings.Contains(ErrPlanMetadataMissing.Error(), SyncCopyDir) {
		t.Errorf("the refusal does not name the copy: %v", ErrPlanMetadataMissing)
	}
}
