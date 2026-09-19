package packages

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The output of apt-get --print-uris: the address of the file and the
// checksum the repository index publishes for it.
const printURIsOutput = `'http://packages.example.net/repo/deb/pool/flotestro-agent_0.56.0-1_amd64.deb' ` +
	`flotestro-agent_0.56.0-1_amd64.deb 8123456 ` +
	`SHA256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff
`

// The address a package is fetched from is read out of what apt printed, and
// a line belonging to another package is not taken for this one.
func TestTheAddressOfAnArtefactIsReadFromWhatAptPrinted(t *testing.T) {
	uri, ok := ParseAPTArtefactURI(printURIsOutput, AgentPackage)
	if !ok {
		t.Fatal("apt named a source and the parser read none")
	}
	if uri != "http://packages.example.net/repo/deb/pool/flotestro-agent_0.56.0-1_amd64.deb" {
		t.Errorf("the address is %q", uri)
	}
	// The checksum of the same line comes from the manifest parser the plan
	// already uses.
	if _, digests := ParseAPTPrintURIs(printURIsOutput); digests[AgentPackage] !=
		"sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff" {
		t.Errorf("the published checksum is %q", digests[AgentPackage])
	}

	other := "'http://packages.example.net/repo/deb/pool/curl_8.5.0-1_amd64.deb' " +
		"curl_8.5.0-1_amd64.deb 1234 SHA256:00\n"
	if _, ok := ParseAPTArtefactURI(other, AgentPackage); ok {
		t.Error("the file of another package was taken for the agent's")
	}
	if _, ok := ParseAPTArtefactURI("Reading package lists...\n", AgentPackage); ok {
		t.Error("output naming no file established an address")
	}
}

// The name apt gives an address in its lists directory drops the scheme and
// the credentials; every slash becomes an underscore.
func TestTheAddressBecomesTheNameAptKeepsItUnder(t *testing.T) {
	cases := map[string]string{
		"http://deb.debian.org/debian/pool/main/c/curl/curl_8_amd64.deb": "deb.debian.org_debian_pool_main_c_curl_curl_8_amd64.deb",
		"https://user:pass@packages.example.net/repo/deb/":               "packages.example.net_repo_deb",
		"http://packages.example.net":                                    "packages.example.net",
	}
	for uri, expected := range cases {
		if got := APTFileName(uri); got != expected {
			t.Errorf("APTFileName(%q) = %q, expected %q", uri, got, expected)
		}
	}
}

// The release file of the repository that publishes a file is the one whose
// address is a prefix of it, and the longest such address wins.
func TestTheReleaseFileOfTheRepositoryThatPublishesTheFileIsFound(t *testing.T) {
	names := []string{
		"deb.debian.org_debian_dists_bookworm_InRelease",
		"packages.example.net_repo_deb_dists_stable_InRelease",
		"packages.example.net_repo_deb_dists_stable_Release",
		"packages.example.net_InRelease",
		"packages.example.net_repo_deb_dists_stable_Packages",
	}
	index, signature, ok := MatchAPTIndex(
		"packages.example.net_repo_deb_pool_flotestro-agent_0.56.0-1_amd64.deb", names)
	if !ok || index != "packages.example.net_repo_deb_dists_stable_InRelease" || signature != "" {
		t.Fatalf("the index is %q with the signature %q (%v)", index, signature, ok)
	}

	// A flat repository has its release file beside the packages.
	flat := []string{"packages.example.net_repo_._Release"}
	index, signature, ok = MatchAPTIndex("packages.example.net_repo_flotestro-agent_0.56.0-1_amd64.deb", flat)
	if !ok || index != "packages.example.net_repo_._Release" ||
		signature != "packages.example.net_repo_._Release.gpg" {
		t.Fatalf("the flat index is %q with the signature %q (%v)", index, signature, ok)
	}

	if _, _, ok := MatchAPTIndex("mirror.example.org_debian_pool_x.deb", names); ok {
		t.Error("a file of a repository the host holds no index of was matched anyway")
	}
}

// A keyring is one apt reads: its own trusted set, and the file a source names
// with Signed-By in either format.
func TestTheTrustedKeysAreTheOnesAptItselfReads(t *testing.T) {
	root := t.TempDir()
	trusted := filepath.Join(root, "trusted.gpg.d")
	sources := filepath.Join(root, "sources.list.d")
	keyrings := filepath.Join(root, "keyrings")
	for _, dir := range []string{trusted, sources, keyrings} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(trusted, "debian-archive.gpg"), "key")
	write(filepath.Join(trusted, "notes.txt"), "not a keyring")
	write(filepath.Join(keyrings, "flotestro.asc"), "key")
	write(filepath.Join(sources, "flotestro.sources"),
		"Types: deb\nURIs: https://packages.example.net/repo/deb\nSuites: stable\n"+
			"Signed-By: "+filepath.Join(keyrings, "flotestro.asc")+"\n")
	write(filepath.Join(sources, "third-party.list"),
		"deb [arch=amd64 signed-by="+filepath.Join(keyrings, "absent.asc")+
			"] https://other.example.net/deb stable main\n")

	withAPTState(t, "", trusted, sources, filepath.Join(root, "sources.list"))
	found := APTTrustedKeyrings()
	expected := []string{
		filepath.Join(trusted, "debian-archive.gpg"),
		filepath.Join(keyrings, "flotestro.asc"),
	}
	if strings.Join(found, ",") != strings.Join(expected, ",") {
		t.Fatalf("apt reads %v, expected %v", found, expected)
	}
}

// Both notations of Signed-By name a file; inline key material names none.
func TestTheKeyringASourceNamesIsRead(t *testing.T) {
	content := "# a comment\n" +
		"Types: deb\n" +
		"URIs: https://packages.example.net/repo/deb\n" +
		"Signed-By: /etc/apt/keyrings/one.asc /etc/apt/keyrings/two.gpg\n" +
		"deb [signed-by=/etc/apt/keyrings/three.asc] https://other.example.net/deb stable main\n"
	found := ParseAPTSignedBy(content)
	expected := "/etc/apt/keyrings/one.asc,/etc/apt/keyrings/two.gpg,/etc/apt/keyrings/three.asc"
	if strings.Join(found, ",") != expected {
		t.Fatalf("the sources name %v, expected %s", found, expected)
	}
	inline := "Types: deb\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n mDMEY...\n"
	if paths := ParseAPTSignedBy(inline); len(paths) != 0 {
		t.Errorf("inline key material named the files %v", paths)
	}
}

// The proof stands when a key apt trusts signed the index and that index
// publishes exactly the file the host holds.
func TestTheSignedRepositoryIndexProvesTheOriginOfThePackage(t *testing.T) {
	const fingerprint = "3B4FE6ACC0B21F32B4B6C1F4A2C794A986419D8A"
	const digest = "1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff"
	lists := aptListsFixture(t, "packages.example.net_repo_deb_dists_stable_InRelease")
	withAPTState(t, lists, "", "", "")
	withAPTTools(t,
		printURIs("http://packages.example.net/repo/deb/pool/flotestro-agent_0.56.0-1_amd64.deb", digest),
		func(context.Context, string, string) (string, error) { return fingerprint, nil })

	proof := EstablishAPTIndexProof(context.Background(), AgentPackage+"=0.56.0-1", digest)
	if !proof.Established || proof.SignedBy != fingerprint {
		t.Fatalf("the proof is %+v", proof)
	}
	if !strings.HasSuffix(proof.IndexPath, "packages.example.net_repo_deb_dists_stable_InRelease") {
		t.Errorf("the index read is %q", proof.IndexPath)
	}
	if token := proof.Token(); token != APTProofPrefix+fingerprint {
		t.Errorf("the result carries %q", token)
	}
	if description := DescribeArtefactSigner(proof.Token()); !strings.Contains(description,
		"repository index signed by "+fingerprint) {
		t.Errorf("the operator reads %q", description)
	}
}

// Every way the origin cannot be established has its own code, and none of
// them passes for a proof.
func TestAnOriginThatCannotBeEstablishedCarriesATypedReason(t *testing.T) {
	const digest = "1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff"
	const uri = "http://packages.example.net/repo/deb/pool/flotestro-agent_0.56.0-1_amd64.deb"
	const stable = "packages.example.net_repo_deb_dists_stable_InRelease"
	accepted := func(context.Context, string, string) (string, error) {
		return "3B4FE6ACC0B21F32B4B6C1F4A2C794A986419D8A", nil
	}
	refused := func(context.Context, string, string) (string, error) {
		return "", errors.New("gpgv did not accept the index")
	}
	unknownOrigin := func(context.Context, string) (string, string, error) {
		return "", "", errors.New("apt named no source")
	}

	check := func(name, reason, index string,
		origin func(context.Context, string) (string, string, error),
		signer func(context.Context, string, string) (string, error)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			var lists []string
			if index != "" {
				lists = append(lists, index)
			}
			withAPTState(t, aptListsFixture(t, lists...), "", "", "")
			withAPTTools(t, origin, signer)

			proof := EstablishAPTIndexProof(context.Background(), AgentPackage+"=0.56.0-1", digest)
			if proof.Established {
				t.Fatalf("an origin that could not be established passed for a proof: %+v", proof)
			}
			if proof.Reason != reason {
				t.Fatalf("the reason is %q, expected %q (%s)", proof.Reason, reason, proof.Detail)
			}
			if token := proof.Token(); token != APTProofUnknownPrefix+reason {
				t.Errorf("the result carries %q", token)
			}
			if description := DescribeArtefactSigner(proof.Token()); !strings.Contains(description, reason) {
				t.Errorf("the operator reads %q", description)
			}
		})
	}

	check("apt says nothing about the source", APTProofOriginUnknown,
		stable, unknownOrigin, accepted)
	check("the host holds no index of that repository", APTProofIndexUnreadable,
		"deb.debian.org_debian_dists_bookworm_InRelease", printURIs(uri, digest), accepted)
	check("the repository publishes no signature of its index", APTProofUnsigned,
		"packages.example.net_repo_deb_dists_stable_Release", printURIs(uri, digest), accepted)
	check("the index is signed by a key apt does not hold", APTProofKeyUntrusted,
		stable, printURIs(uri, digest), refused)
	check("the index publishes another file under that name", APTProofDigestMismatch,
		stable, printURIs(uri, strings.Repeat("9f", 32)), accepted)
	check("the index names no checksum for the file", APTProofIndexUnreadable,
		stable, printURIs(uri, ""), accepted)
}

// The signature of a package file and the signature of a repository index are
// told apart in the result, and an empty field is not read as a proof.
func TestTheResultSaysWhichProofStoodBehindTheFile(t *testing.T) {
	expect := func(value, expected string) {
		t.Helper()
		if got := DescribeArtefactSigner(value); got != expected {
			t.Errorf("DescribeArtefactSigner(%q) = %q, expected %q", value, got, expected)
		}
	}
	expect("", "the signer of the artefact was not established")
	expect("A2C794A986419D8A", "the artefact was signed by A2C794A986419D8A")
	expect(APTProofPrefix+"ABCD", "the proof is the repository index signed by ABCD")
	expect(APTProofUnknownPrefix+APTProofUnsigned,
		"the repository index proved nothing about the artefact ("+APTProofUnsigned+")")
}

// Only a fingerprint long enough to name one key counts as an identity.
func TestAKeyIdentityIsLongEnoughToNameOneKey(t *testing.T) {
	status := "[GNUPG:] NEWSIG\n" +
		"[GNUPG:] GOODSIG A2C794A986419D8A Flotestro Release\n" +
		"[GNUPG:] VALIDSIG 3b4fe6acc0b21f32b4b6c1f4a2c794a986419d8a 2026-09-18\n"
	signer, ok := PGPStatusSigner(status)
	if !ok || signer != "3B4FE6ACC0B21F32B4B6C1F4A2C794A986419D8A" {
		t.Fatalf("the status named %q (%v)", signer, ok)
	}
	if _, ok := PGPStatusSigner("[GNUPG:] BADSIG A2C794A986419D8A Flotestro\n"); ok {
		t.Error("a bad signature named a signer")
	}
	if HexKeyIdentity("86419D8A") || HexKeyIdentity("zzzzzzzzzzzzzzzz") {
		t.Error("a value too short or not hexadecimal was taken for a key identity")
	}
}

// aptListsFixture writes the named release files and returns the directory.
func aptListsFixture(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("Origin: fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// withAPTState points the proof at fixture directories for the length of one
// test; an empty value leaves the directory out of reach.
func withAPTState(t *testing.T, lists, trusted, sources, sourcesFile string) {
	t.Helper()
	previous := []string{aptIndexDir, aptTrustedDir, aptSourcesDir, aptSourcesFile, aptTrustedKeyring}
	absent := filepath.Join(t.TempDir(), "absent")
	value := func(path string) string {
		if path == "" {
			return absent
		}
		return path
	}
	aptIndexDir = value(lists)
	aptTrustedDir = value(trusted)
	aptSourcesDir = value(sources)
	aptSourcesFile = value(sourcesFile)
	aptTrustedKeyring = absent
	t.Cleanup(func() {
		aptIndexDir, aptTrustedDir, aptSourcesDir = previous[0], previous[1], previous[2]
		aptSourcesFile, aptTrustedKeyring = previous[3], previous[4]
	})
}

// withAPTTools replaces the two commands the proof runs, so that no test
// reads the apt state of the machine it runs on.
func withAPTTools(t *testing.T, origin func(context.Context, string) (string, string, error),
	signer func(context.Context, string, string) (string, error)) {
	t.Helper()
	previousOrigin, previousSigner := aptArtefactOrigin, aptIndexSigner
	aptArtefactOrigin, aptIndexSigner = origin, signer
	t.Cleanup(func() { aptArtefactOrigin, aptIndexSigner = previousOrigin, previousSigner })
}

// printURIs is an apt that names one address and one published checksum.
func printURIs(uri, digest string) func(context.Context, string) (string, string, error) {
	return func(context.Context, string) (string, string, error) { return uri, digest, nil }
}
