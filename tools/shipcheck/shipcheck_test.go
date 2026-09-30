package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The workflow reaches these checks by name, and a name it gets wrong is an exit
// code nobody reads as a failure of the thing it meant to check. The tool refuses
// an unknown name, which turns that into a red step - but only once somebody
// pushes, and pushing is the cost this job exists to avoid. So the names the
// workflow asks for are resolved here instead.
func TestTheWorkflowAsksForEveryCheckByAName(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repositoryRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		t.Fatalf("ci.yml: %v", err)
	}

	asked := map[string]bool{}
	commands := 0
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if !strings.Contains(step.Run, "./tools/shipcheck") {
				continue
			}
			commands++
			after := step.Run[strings.Index(step.Run, "./tools/shipcheck")+len("./tools/shipcheck"):]
			// The arguments end where the shell takes over: a redirection or a
			// pipe is not a check name, and neither is a line continuation.
			for _, word := range strings.Fields(after) {
				if word == "\\" {
					continue
				}
				if !checkNameShaped(word) {
					break
				}
				asked[word] = true
			}
		}
	}
	if commands == 0 {
		t.Fatal("ci.yml runs tools/shipcheck nowhere, so none of these checks reach a runner")
	}

	for _, one := range checks {
		if !asked[one.name] {
			t.Errorf("ci.yml asks for no check called %q, so it runs nowhere", one.name)
		}
	}
	for name := range asked {
		if _, err := selectChecks([]string{name}); err != nil {
			t.Errorf("ci.yml asks for %q, and %v", name, err)
		}
	}
}

// checkNameShaped says whether a word could be the name of a check at all. A
// misspelled name still is one, and is reported; a pipe is not.
func checkNameShaped(word string) bool {
	if word == "" {
		return false
	}
	for _, letter := range word {
		if (letter < 'a' || letter > 'z') && (letter < '0' || letter > '9') && letter != '-' {
			return false
		}
	}
	return true
}

// Every check runs in the ordinary test run as well as in the workflow: a rule
// that holds in one place and not the other is a rule somebody crosses locally
// and finds out about an hour later. And every check gets a tree built to break
// it, because a guard that cannot fail is decoration - the reason this file is
// longer than the tool is that proving a check sees the violation costs more than
// writing the check.
const repositoryRoot = "../.."

// The checks the tree is held to. airgap-images-are-signed is not among them: it
// reports an open finding, and the test below pins what it reports so that the
// day it changes is a day somebody reads.
var enforced = []string{
	"site-languages",
	"healthcheck-form",
	"airgap-verify-stops",
	"env-example-reaches-the-deployment",
}

func TestTheTreeAgreesWithWhatItSaysAboutItself(t *testing.T) {
	for _, name := range enforced {
		one := checkNamed(t, name)
		findings, err := one.run(repositoryRoot)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, found := range findings {
			t.Errorf("%s: %s", name, found)
		}
	}
}

// The one check that does not pass yet, pinned to exactly what it finds. It is
// the regression path of an open finding: the air-gap procedure is the only way
// packages reach a disconnected site, and it tells the operator to verify an
// image no job signs. When the image gets signed this test fails and is deleted
// along with the check's place in the reporting job.
func TestTheAirGapProcedureStillNamesAnImageNobodySigns(t *testing.T) {
	findings, err := checkNamed(t, "airgap-images-are-signed").run(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("flotestro-package-repository is signed now: make this check required and delete this test")
	}
	for _, found := range findings {
		if !strings.Contains(found.said, "flotestro-package-repository") {
			t.Errorf("an unexpected image is documented as verified but unsigned: %s", found)
		}
	}
	t.Logf("%d documented loop(s) name an unsigned image", len(findings))
}

func checkNamed(t *testing.T, name string) check {
	t.Helper()
	for _, one := range checks {
		if one.name == name {
			return one
		}
	}
	t.Fatalf("there is no check called %q", name)
	return check{}
}

// selectChecks is what the workflow reaches the checks through, so a name that
// matches nothing has to be an error. The alternative is the failure this
// repository has already had: a pattern that selected no test and reported the
// empty run as a pass.
func TestAskingForACheckThatDoesNotExistIsAnError(t *testing.T) {
	if _, err := selectChecks([]string{"site-languages", "no-such-check"}); err == nil {
		t.Fatal("a name matching nothing was accepted, so a workflow could pass by asking for nothing")
	}
	all, err := selectChecks(nil)
	if err != nil || len(all) != len(checks) {
		t.Fatalf("naming nothing did not select every check: %d, %v", len(all), err)
	}
}

func write(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// run is how the tests reach a check: through the same table the workflow uses,
// so a check renamed in one place and not the other fails here.
func run(t *testing.T, root, name string) []finding {
	t.Helper()
	findings, err := checkNamed(t, name).run(root)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func only(t *testing.T, findings []finding, wanted string) finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].place+" "+findings[0].said, wanted) {
		t.Fatalf("the finding does not mention %q: %s", wanted, findings[0])
	}
	return findings[0]
}

// --- site-languages ---

func siteTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "docs/site/index.html", "<html lang=en>")
	write(t, root, "docs/site/docs/api.html", "<html lang=en>")
	write(t, root, "docs/site/style.css", "body{}")
	write(t, root, "docs/site/img/logo.webp", "binary")
	write(t, root, "docs/site/pl/index.html", "<html lang=pl>")
	write(t, root, "docs/site/pl/docs/api.html", "<html lang=pl>")
	return root
}

func TestSiteLanguagesPassesOnAMirroredSite(t *testing.T) {
	findings, err := siteLanguages(siteTree(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a mirrored site was reported: %v", findings)
	}
}

func TestSiteLanguagesSeesAPageWithNoTranslation(t *testing.T) {
	root := siteTree(t)
	write(t, root, "docs/site/docs/pricing.html", "<html lang=en>")
	found := only(t, run(t, root, "site-languages"), "")
	if !strings.Contains(found.place, "docs/pricing.html") {
		t.Fatalf("the untranslated page was not named: %s", found)
	}
}

func TestSiteLanguagesSeesATranslationWithNoOriginal(t *testing.T) {
	root := siteTree(t)
	write(t, root, "docs/site/pl/docs/cennik.html", "<html lang=pl>")
	only(t, run(t, root, "site-languages"), "has no English counterpart")
}

// The stylesheet and the images are shared on purpose, so asking for a Polish
// copy of them would be asking for a second copy of a file that is right.
func TestSiteLanguagesLeavesTheSharedAssetsAlone(t *testing.T) {
	root := siteTree(t)
	write(t, root, "docs/site/img/screenshot.png", "binary")
	write(t, root, "docs/site/print.css", "body{}")
	if findings, err := siteLanguages(root); err != nil || len(findings) != 0 {
		t.Fatalf("a shared asset was asked for a translation: %v (%v)", findings, err)
	}
}

// An empty site, or one this check no longer knows how to read, must fail here.
func TestSiteLanguagesRefusesToPassOverNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docs/site/index.html", "<html lang=en>")
	only(t, run(t, root, "site-languages"), "compared nothing")
}

// --- healthcheck-form ---

const shelllessContainerfile = `ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot
ARG TOOLS_IMAGE=postgres:17-bookworm
FROM --platform=$TARGETPLATFORM ${RUNTIME_IMAGE} AS control-plane
FROM --platform=$TARGETPLATFORM ${TOOLS_IMAGE} AS admin-tools
`

func composeTree(t *testing.T, healthcheck string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "docker/Containerfile", shelllessContainerfile)
	write(t, root, "docker/compose.yaml", `name: flotestro
services:
  control-plane:
    image: ghcr.io/ultherego/flotestro-control-plane:${FLOTESTRO_VERSION:-latest}
    healthcheck:
      test: `+healthcheck+`
  postgres:
    image: docker.io/library/postgres:17-bookworm
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U flotestro"]
`)
	return root
}

func TestHealthcheckFormPassesOnExecForm(t *testing.T) {
	findings, err := healthcheckForm(composeTree(t, `["CMD", "/usr/local/bin/flotestro-healthcheck"]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("an exec-form healthcheck on a shell-less image was reported: %v", findings)
	}
}

// The repair somebody reaches for after reading that the list form does not pass
// under podman-compose. It breaks the check on both engines instead of fixing it,
// because the image genuinely has no shell.
func TestHealthcheckFormSeesAShellStringOnAShelllessImage(t *testing.T) {
	for _, written := range []string{
		`["CMD-SHELL", "/usr/local/bin/flotestro-healthcheck"]`,
		`/usr/local/bin/flotestro-healthcheck`,
		`["/usr/local/bin/flotestro-healthcheck"]`,
	} {
		found := only(t, run(t, composeTree(t, written), "healthcheck-form"), "")
		if !strings.Contains(found.place, "docker/compose.yaml:") {
			t.Errorf("%s: the finding names no line: %s", written, found)
		}
	}
}

// The database runs a shell command in an image that has one, and a check that
// flagged it would be a check nobody could leave switched on.
func TestHealthcheckFormLeavesAShellBearingImageAlone(t *testing.T) {
	root := composeTree(t, `["CMD", "/usr/local/bin/flotestro-healthcheck"]`)
	findings, err := healthcheckForm(root)
	if err != nil || len(findings) != 0 {
		t.Fatalf("postgres was flagged for using pg_isready: %v (%v)", findings, err)
	}
}

// A service whose image is named by a variable resolves to no build stage, so the
// command has to be what gives it away. The relay is exactly this shape.
func TestHealthcheckFormSeesThroughAnImageNamedByAVariable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docker/Containerfile", shelllessContainerfile)
	write(t, root, "docker/compose.relay.yaml", `name: flotestro-relay
services:
  relay:
    image: ${FLOTESTRO_RELAY_IMAGE:?pin it by digest}
    healthcheck:
      test: ["CMD-SHELL", "/usr/local/bin/flotestro-healthcheck -addr 127.0.0.1:8454"]
`)
	only(t, run(t, root, "healthcheck-form"), "docker/compose.relay.yaml:")
}

func TestHealthcheckFormRefusesToPassOverNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docker/Containerfile", shelllessContainerfile)
	write(t, root, "docker/compose.yaml", `name: flotestro
services:
  postgres:
    image: docker.io/library/postgres:17-bookworm
    healthcheck:
      test: ["CMD-SHELL", "pg_isready"]
`)
	only(t, run(t, root, "healthcheck-form"), "inspected nothing")
}

// The distroless stages are read out of the Containerfile rather than listed in
// the tool, so a Containerfile this check cannot read has to be an error and not
// an empty answer.
func TestHealthcheckFormRefusesAContainerfileItCannotRead(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docker/Containerfile", "FROM scratch AS control-plane\n")
	write(t, root, "docker/compose.yaml", "name: flotestro\nservices: {}\n")
	if _, err := healthcheckForm(root); err == nil {
		t.Fatal("a Containerfile with no RUNTIME_IMAGE was accepted")
	}
}

// --- the air-gap procedure ---

const signingWorkflow = `name: Images
jobs:
  images:
    strategy:
      matrix:
        include:
          - target: control-plane
            image: flotestro-control-plane
          - target: relay
            image: flotestro-relay
    steps:
      - name: Sign
        run: cosign sign --yes --recursive "$REFERENCE@$DIGEST"
  image-check:
    strategy:
      matrix:
        include:
          - target: package-repository
            image: flotestro-package-repository
    steps:
      - name: Build only
        run: echo nothing is signed here
`

func airgapTree(t *testing.T, loop string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, ".github/workflows/images.yml", signingWorkflow)
	write(t, root, "docs/site/docs/installation.html", "<pre><code>"+loop+"</code></pre>\n")
	return root
}

const stoppingLoop = `for name in control-plane relay; do
  reference="ghcr.io/ultherego/flotestro-$name:$version"
  cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com "$reference" \
    || { echo "$reference does not verify" &gt;&amp;2; break; }
  docker pull "$reference"
done`

func TestTheAirGapChecksPassOnAStoppingLoopOfSignedImages(t *testing.T) {
	root := airgapTree(t, stoppingLoop)
	for _, name := range []string{"airgap-verify-stops", "airgap-images-are-signed"} {
		findings, err := checkNamed(t, name).run(root)
		if err != nil || len(findings) != 0 {
			t.Errorf("%s: %v (%v)", name, findings, err)
		}
	}
}

func TestAirgapVerifyStopsSeesALoopThatCarriesOn(t *testing.T) {
	root := airgapTree(t, strings.ReplaceAll(stoppingLoop,
		" \\\n    || { echo \"$reference does not verify\" &gt;&amp;2; break; }", ""))
	only(t, run(t, root, "airgap-verify-stops"), "carries on after a signature does not verify")
}

func TestAirgapImagesAreSignedSeesAnImageNobodySigns(t *testing.T) {
	root := airgapTree(t, strings.Replace(stoppingLoop,
		"for name in control-plane relay; do",
		"for name in control-plane package-repository relay; do", 1))
	only(t, run(t, root, "airgap-images-are-signed"), "flotestro-package-repository")
}

// The second shape the loop is written in: the names come from a variable set
// above it. Missing this form would leave a whole copy of the procedure unread.
func TestTheAirGapChecksReadTheLoopThatTakesItsNamesFromAVariable(t *testing.T) {
	root := airgapTree(t, `images="control-plane package-repository relay"

for name in $images; do
  reference="ghcr.io/ultherego/flotestro-$name:$version"
  cosign verify "$reference"
  docker pull "$reference"
done`)
	if findings, err := airgapImagesAreSigned(root); err != nil || len(findings) != 1 {
		t.Fatalf("the unsigned image was not found in the variable form: %v (%v)", findings, err)
	}
	if findings, err := airgapVerifyStops(root); err != nil || len(findings) != 1 {
		t.Fatalf("the loop that carries on was not found in the variable form: %v (%v)", findings, err)
	}
}

// A loop that is only an illustration of one image is not a procedure, and
// flagging it would train somebody to switch the check off.
func TestTheAirGapChecksIgnoreASingleImageExample(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/images.yml", signingWorkflow)
	write(t, root, "docs/site/docs/installation.html",
		"<pre><code>cosign verify \\\n  ghcr.io/ultherego/flotestro-control-plane:0.62.0</code></pre>\n")
	only(t, run(t, root, "airgap-verify-stops"), "inspected nothing")
}

// A job that stopped signing must not go on counting as one that signs.
func TestSignedImagesReadsOnlyTheJobThatSigns(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/images.yml", signingWorkflow)
	signed, err := signedImages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) != 2 || !signed["flotestro-control-plane"] || !signed["flotestro-relay"] {
		t.Fatalf("the signed set is not the matrix of the signing job: %v", sorted(signed))
	}
	if signed["flotestro-package-repository"] {
		t.Fatal("a build-only matrix was counted as signed")
	}
}

// --- env-example-reaches-the-deployment ---

func envTree(t *testing.T, example, compose, baseline string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "docker/env.example", example)
	write(t, root, "docker/compose.yaml", compose)
	write(t, root, "tools/shipcheck/inert-env-keys.txt", baseline)
	return root
}

const reachingCompose = `name: flotestro
services:
  control-plane:
    image: ghcr.io/ultherego/flotestro-control-plane:${FLOTESTRO_VERSION:-latest}
    environment:
      FLOTESTRO_ADVERTISE: ${FLOTESTRO_ADVERTISE:-127.0.0.1}
      FLOTESTRO_PUBLIC_URL: ${FLOTESTRO_PUBLIC_URL:-}
`

func TestEnvExamplePassesWhenEveryKeyReachesTheDeployment(t *testing.T) {
	root := envTree(t,
		"FLOTESTRO_ADVERTISE=0.0.0.0\n#FLOTESTRO_PUBLIC_URL=https://panel\nFLOTESTRO_VERSION=0.62.0\n",
		reachingCompose, "# nothing\n")
	if findings, err := envExampleReachesTheDeployment(root); err != nil || len(findings) != 0 {
		t.Fatalf("keys that reach the deployment were reported: %v (%v)", findings, err)
	}
}

func TestEnvExampleSeesAKeyThatReachesNothing(t *testing.T) {
	root := envTree(t,
		"FLOTESTRO_ADVERTISE=0.0.0.0\nFLOTESTRO_VERSION=0.62.0\n#FLOTESTRO_IPA_URL=https://ipa\n",
		reachingCompose, "# nothing\n")
	found := only(t, run(t, root, "env-example-reaches-the-deployment"), "FLOTESTRO_IPA_URL")
	if !strings.HasSuffix(found.place, ":3") {
		t.Fatalf("the finding does not name the line the key is offered on: %s", found)
	}
}

// A commented-out key is an offer too: uncommenting it is what the file invites,
// and if that changes nothing the file is lying either way.
func TestEnvExampleReadsACommentedOutKeyAsAnOffer(t *testing.T) {
	root := envTree(t,
		"FLOTESTRO_ADVERTISE=0.0.0.0\nFLOTESTRO_VERSION=0.62.0\n#FLOTESTRO_NOTIFY_ALLOW=10.0.0.0/8\n",
		reachingCompose, "# nothing\n")
	only(t, run(t, root, "env-example-reaches-the-deployment"), "FLOTESTRO_NOTIFY_ALLOW")
}

func TestEnvExampleTakesTheBaselineAsAnExcuseAndNoMore(t *testing.T) {
	example := "FLOTESTRO_ADVERTISE=0.0.0.0\nFLOTESTRO_VERSION=0.62.0\n#FLOTESTRO_IPA_URL=https://ipa\n"
	if findings, err := envExampleReachesTheDeployment(
		envTree(t, example, reachingCompose, "FLOTESTRO_IPA_URL\n")); err != nil || len(findings) != 0 {
		t.Fatalf("a baselined key was reported: %v (%v)", findings, err)
	}
	// And the baseline may only shrink: an entry with nothing left to excuse
	// is a line that has to go, or the list rots into a rubber stamp.
	only(t, run(t,
		envTree(t, example, reachingCompose, "FLOTESTRO_IPA_URL\nFLOTESTRO_GONE\n"), "env-example-reaches-the-deployment"), "still lists FLOTESTRO_GONE")
}

// An env_file: hands the whole file to the container, which is one of the two
// ways to close this gap, so the check has to recognise it as an answer.
func TestEnvExampleAcceptsAnEnvFile(t *testing.T) {
	root := envTree(t,
		"FLOTESTRO_ADVERTISE=0.0.0.0\n#FLOTESTRO_IPA_URL=https://ipa\n",
		`name: flotestro
services:
  control-plane:
    image: ghcr.io/ultherego/flotestro-control-plane:latest
    env_file: [.env]
    environment:
      FLOTESTRO_ADVERTISE: ${FLOTESTRO_ADVERTISE:-127.0.0.1}
`, "# nothing\n")
	if findings, err := envExampleReachesTheDeployment(root); err != nil || len(findings) != 0 {
		t.Fatalf("an env_file was not taken as carrying the keys: %v (%v)", findings, err)
	}
}

// A name in a comment of a compose file is not something the deployment acts on,
// so it must not count as the key having reached a container.
func TestEnvExampleDoesNotCountANameWrittenInAComment(t *testing.T) {
	root := envTree(t,
		"FLOTESTRO_ADVERTISE=0.0.0.0\n#FLOTESTRO_IPA_URL=https://ipa\n",
		reachingCompose+"      # FLOTESTRO_IPA_URL goes here one day\n", "# nothing\n")
	only(t, run(t, root, "env-example-reaches-the-deployment"), "FLOTESTRO_IPA_URL")
}

func TestEnvExampleRefusesToPassOverNothing(t *testing.T) {
	root := envTree(t, "# only comments here\n", reachingCompose, "# nothing\n")
	only(t, run(t, root, "env-example-reaches-the-deployment"), "compared nothing")
}
