package packages

import (
	"strings"
	"testing"
)

func TestValidateRepositoryWatchesTheTrust(t *testing.T) {
	base := Repository{
		ID: "internal", URL: "https://packages.example.test/debian",
		Suites: []string{"stable"}, Components: []string{"main"},
		Enabled: true, Signed: true,
	}
	if err := ValidateRepository(base, "apt", false); err != nil {
		t.Fatalf("a correct source was rejected: %v", err)
	}

	// A source without signature checking over plain http means that being on
	// the way is enough for the host to install somebody else's packages.
	unsigned := base
	unsigned.Signed = false
	unsigned.URL = "http://packages.example.test/debian"
	if err := ValidateRepository(unsigned, "apt", false); err == nil {
		t.Fatal("a source without signatures over http was accepted")
	}
	unsigned.URL = "https://packages.example.test/debian"
	if err := ValidateRepository(unsigned, "apt", false); err != nil {
		t.Fatalf("a source without signatures over https was rejected: %v", err)
	}

	// A password over plain http is read by anyone who is on the way.
	withPassword := base
	withPassword.URL = "http://packages.example.test/debian"
	withPassword.Username = "fleet"
	if err := ValidateRepository(withPassword, "apt", true); err == nil {
		t.Fatal("a source with a password over http was accepted")
	}
	withoutUser := base
	if err := ValidateRepository(withoutUser, "apt", true); err == nil {
		t.Fatal("a password without a user name was accepted")
	}

	badNames := []string{"", "../escape", "Capitals", "with a space", strings.Repeat("a", 80)}
	for _, name := range badNames {
		bad := base
		bad.ID = name
		if err := ValidateRepository(bad, "apt", false); err == nil {
			t.Fatalf("the identifier %q was accepted", name)
		}
	}

	// APT needs a suite; DNF is described by its address alone.
	withoutSuite := base
	withoutSuite.Suites = nil
	if err := ValidateRepository(withoutSuite, "apt", false); err == nil {
		t.Fatal("an APT source without a suite was accepted")
	}
	if err := ValidateRepository(base, "dnf", false); err == nil {
		t.Fatal("a DNF source with a suite was accepted")
	}

	// Removing a source needs no address: the identifier alone describes it.
	removal := Repository{ID: "internal"}
	if err := ValidateRepository(removal, "apt", false); err != nil {
		t.Fatalf("the removal of a source was rejected: %v", err)
	}
}

func TestTheSourceFilesKeepThePasswordSeparate(t *testing.T) {
	repo := Repository{
		ID: "internal", Name: "Internal", URL: "https://packages.example.test/debian",
		Suites: []string{"stable"}, Components: []string{"main"}, Enabled: true,
		Signed: true, Username: "fleet", SecretName: "repo.password",
	}
	files, err := SourceFiles(repo, "apt", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", []byte("s3kr3t"))
	if err != nil {
		t.Fatalf("SourceFiles: %v", err)
	}

	var source, password *File
	for i := range files {
		switch {
		case strings.HasSuffix(files[i].Path, ".sources"):
			source = &files[i]
		case strings.HasSuffix(files[i].Path, ".conf"):
			password = &files[i]
		}
	}
	if source == nil || password == nil {
		t.Fatalf("the file of the source or of the password is missing: %+v", files)
	}
	// The file of the source is public and is to stay that way - so the
	// password must not be in it.
	if strings.Contains(string(source.Content), "s3kr3t") {
		t.Fatal("the password landed in the public file of the source")
	}
	if !strings.Contains(string(source.Content), "repo.password") {
		t.Fatal("the file of the source does not say which secret the password comes from")
	}
	// A user name is not a secret, and without it the panel would see a source
	// with a password without knowing who it presents itself as.
	if !strings.Contains(string(source.Content), userMarker+"fleet") {
		t.Fatalf("the file of the source does not say who it presents itself as:\n%s", source.Content)
	}
	if source.Mode != 0o644 {
		t.Errorf("the file of the source has the permissions %o", source.Mode)
	}
	if password.Mode != 0o600 || !password.Sensitive {
		t.Errorf("the file of the password has the permissions %o (sensitive=%v)",
			password.Mode, password.Sensitive)
	}
	if !strings.Contains(string(source.Content), "Signed-By: /etc/apt/keyrings/flotestro-internal.asc") {
		t.Errorf("the source does not name its own key:\n%s", source.Content)
	}
}

func TestTheDNFSourceFilesCloseTheFileWithThePassword(t *testing.T) {
	repo := Repository{
		ID: "internal", URL: "https://packages.example.test/rpm", Enabled: true,
		Signed: true, Username: "fleet", SecretName: "repo.password", Priority: 10,
	}
	files, err := SourceFiles(repo, "dnf", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", []byte("s3kr3t"))
	if err != nil {
		t.Fatalf("SourceFiles: %v", err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Path, ".repo") {
			continue
		}
		// DNF has no separate password file, so the whole description of the
		// source has to be closed to everyone but root.
		if file.Mode != 0o600 || !file.Sensitive {
			t.Fatalf("the file of a source with a password has the permissions %o (sensitive=%v)",
				file.Mode, file.Sensitive)
		}
		if !strings.Contains(string(file.Content), "gpgcheck=1") {
			t.Errorf("the source does not check the signatures:\n%s", file.Content)
		}
		if !strings.Contains(string(file.Content), "priority=10") {
			t.Errorf("the priority did not reach the file:\n%s", file.Content)
		}
		return
	}
	t.Fatalf("no file of the source was created: %+v", files)
}

func TestReadDNFSectionsTellsTheStatesOfASourceApart(t *testing.T) {
	content := panelMarker + "\n" + secretMarker + "repo.password\n" +
		"[internal]\nname=Internal\nbaseurl=https://packages.example.test/rpm\n" +
		"enabled=1\ngpgcheck=1\nusername=fleet\npriority=10\n\n" +
		"[old]\nname=Old\nbaseurl=https://old.example.test/rpm\nenabled=0\ngpgcheck=0\n"

	sources := readDNFSections("/etc/yum.repos.d/internal.repo", content)
	if len(sources) != 2 {
		t.Fatalf("recognised %d sources: %+v", len(sources), sources)
	}
	if !sources[0].Managed || sources[0].SecretName != "repo.password" {
		t.Errorf("the source of the panel was described as %+v", sources[0])
	}
	if !sources[0].Enabled || !sources[0].Signed || sources[0].Username != "fleet" {
		t.Errorf("the state of the source was read as %+v", sources[0])
	}
	if sources[1].Enabled || sources[1].Signed {
		t.Errorf("a disabled source without signatures was read as %+v", sources[1])
	}
}

func TestReadListSourceRecognisesTheKey(t *testing.T) {
	// The one-line entry is left to the distribution, but we have to be able
	// to read it: it describes the sources the panel did not write.
	sources := readListSourceFromContent("/etc/apt/sources.list.d/foreign.list",
		"# a comment\ndeb [signed-by=/usr/share/keyrings/foreign.gpg] https://foreign.example.test/debian stable main contrib\n"+
			"deb http://without-a-key.example.test/debian stable main\n")
	if len(sources) != 2 {
		t.Fatalf("recognised %d sources: %+v", len(sources), sources)
	}
	if !sources[0].Signed || sources[0].URL != "https://foreign.example.test/debian" {
		t.Errorf("the source with a key was read as %+v", sources[0])
	}
	if sources[0].Suites[0] != "stable" || len(sources[0].Components) != 2 {
		t.Errorf("the suite and the components were read as %+v", sources[0])
	}
	if sources[1].Signed {
		t.Errorf("a source without a key was read as signed: %+v", sources[1])
	}
}

func TestTheFirstAPTErrorReadsAWarningAsAnError(t *testing.T) {
	// apt ends with the code zero also when an index could not be fetched. To
	// the panel that is not a warning: a source that does not answer will
	// block every next package operation on the host.
	output := "Get:1 https://packages.example.test/debian stable InRelease\n" +
		"Err:1 https://packages.example.test/debian stable InRelease\n" +
		"  Temporary failure resolving 'packages.example.test'\n" +
		"W: Some index files failed to download.\n"
	if line := firstAPTError(output); line == "" {
		t.Fatal("a failed fetch of the index was passed over in silence")
	}
	if firstAPTError("Get:1 https://packages.example.test/debian stable InRelease\nFetched 1 B\n") != "" {
		t.Fatal("a correct fetch was treated as an error")
	}
}

func TestTheFirstDNFErrorReadsAWarningAsAnError(t *testing.T) {
	// dnf ends with the code zero and the message "Metadata cache created"
	// also when not a single address of the source could be opened.
	dnf5 := ">>> Curl error (6): Could not resolve hostname for https://packages.example.test/\n" +
		">>> Usable URL not found\nRepositories loaded.\nMetadata cache created.\n"
	if firstDNFError(dnf5) == "" {
		t.Fatal("a failed fetch of the metadata (dnf5) was passed over in silence")
	}
	dnf4 := "Errors during downloading metadata for repository 'internal':\n" +
		"  - Curl error (6): Couldn't resolve host name\n"
	if firstDNFError(dnf4) == "" {
		t.Fatal("a failed fetch of the metadata (dnf4) was passed over in silence")
	}
	if firstDNFError("Repositories loaded.\nMetadata cache created.\n") != "" {
		t.Fatal("a correct fetch was treated as an error")
	}
}
