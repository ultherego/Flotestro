package compose

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// runner fakes compose: it returns prepared output for consecutive calls.
func runner(answers map[string]string) Runner {
	return func(_ context.Context, args ...string) (string, string, error) {
		for pattern, answer := range answers {
			if strings.Contains(strings.Join(args, " "), pattern) {
				return answer, "", nil
			}
		}
		return "", "unknown command", context.Canceled
	}
}

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// resolver fakes the registry: every tag resolves to the given digest.
func resolver(digests map[string]string) ImageResolver {
	return func(_ context.Context, image string) (ResolvedImage, error) {
		digest, known := digests[image]
		if !known {
			return ResolvedImage{}, context.Canceled
		}
		return ResolvedImage{Digest: digest, Source: DigestFromRegistry}, nil
	}
}

func testPlanner(t *testing.T, answers map[string]string) Planner {
	t.Helper()
	return Planner{Dir: t.TempDir(), Runner: runner(answers),
		Resolver: resolver(map[string]string{"postgres:16": digestA, "nginx:alpine": digestA})}
}

const configuration = `{
  "services": {
    "web": {"image": "nginx@` + digestA + `", "environment": {"PORT": "80"}},
    "db":  {"image": "postgres:16", "environment": {"POSTGRES_PASSWORD": "secret"}}
  }
}`

// The digest binds the deployment to the plan, so it must depend on the
// content, not on the order of services in the manifest.
func TestDigestDoesNotDependOnOrder(t *testing.T) {
	a := Digest("shop", configuration, []Service{
		{Name: "web", Image: "nginx@sha256:aaaa", Replicas: 1},
		{Name: "db", Image: "postgres:16", Replicas: 1},
	})
	b := Digest("shop", configuration, []Service{
		{Name: "db", Image: "postgres:16", Replicas: 1},
		{Name: "web", Image: "nginx@sha256:aaaa", Replicas: 1},
	})
	if a != b {
		t.Error("the digest depends on the service order")
	}

	other := Digest("shop", configuration, []Service{
		{Name: "web", Image: "nginx@sha256:bbbb", Replicas: 1},
		{Name: "db", Image: "postgres:16", Replicas: 1},
	})
	if a == other {
		t.Error("an image change did not change the digest")
	}
	if a == Digest("warehouse", configuration, []Service{
		{Name: "web", Image: "nginx@sha256:aaaa", Replicas: 1},
		{Name: "db", Image: "postgres:16", Replicas: 1},
	}) {
		t.Error("a project change did not change the digest")
	}
}

// A manifest with the same services and images may publish a different port or
// run a different command.
func TestDigestCoversWholeManifest(t *testing.T) {
	services := []Service{{Name: "web", Image: "nginx:alpine", Replicas: 1}}
	withPort8083 := `{"services":{"web":{"image":"nginx:alpine","ports":[{"published":"8083"}]}}}`
	withPort8084 := `{"services":{"web":{"image":"nginx:alpine","ports":[{"published":"8084"}]}}}`

	if Digest("shop", withPort8083, services) == Digest("shop", withPort8084, services) {
		t.Error("a port change did not change the plan digest")
	}
}

// The manifest is stored in the panel together with the version history, so a
// value written into it directly stops being a secret.
func TestPlanWarnsAboutSecretsInManifest(t *testing.T) {
	planner := testPlanner(t, map[string]string{
		"config": configuration,
		"up":     " DRY-RUN MODE -  Container shop-web-1  Creating",
	})
	plan, err := planner.Plan(context.Background(), "shop", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	var aboutSecret, aboutTag bool
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "POSTGRES_PASSWORD") {
			aboutSecret = true
		}
		if strings.Contains(warning, "mutable tag") && strings.Contains(warning, "db") {
			aboutTag = true
		}
	}
	if !aboutSecret {
		t.Errorf("no warning about a secret in the manifest: %v", plan.Warnings)
	}
	// An image named by a tag may mean something else tomorrow.
	if !aboutTag {
		t.Errorf("no warning about a mutable tag: %v", plan.Warnings)
	}
}

// A service pinned by a digest is not a moving target and must not be
// marked as one - otherwise the warnings stop meaning anything.
func TestPinnedImageIsNotWarnedAbout(t *testing.T) {
	planner := testPlanner(t, map[string]string{
		"config": `{"services": {"web": {"image": "nginx@` + digestA + `"}}}`,
		"up":     "",
	})
	plan, err := planner.Plan(context.Background(), "shop", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "mutable tag") {
			t.Errorf("a pinned image was marked as moving: %q", warning)
		}
	}
}

// Compose reports every step twice - during and after. A doubled change list
// would suggest to the operator twice as much work as the deployment does.
func TestChangesAreNotCountedTwice(t *testing.T) {
	changes := changesFromDryRun(strings.Join([]string{
		" DRY-RUN MODE -  Network shop_default  Creating",
		" DRY-RUN MODE -  Network shop_default  Created",
		" DRY-RUN MODE -  Container shop-web-1  Creating",
		" DRY-RUN MODE -  Container shop-web-1  Created",
	}, "\n"))
	if len(changes) != 2 {
		t.Fatalf("changes = %d, want 2: %+v", len(changes), changes)
	}
	if changes[0].Kind != "network" || changes[1].Name != "shop-web-1" {
		t.Errorf("changes = %+v", changes)
	}
}

// The project name goes into a command argument and into container names.
func TestProjectNameIsValidated(t *testing.T) {
	for _, name := range []string{"", "-shop", "Shop", "shop;reboot", "shop/../etc", strings.Repeat("a", 64)} {
		if ValidProjectName(name) {
			t.Errorf("accepted name %q", name)
		}
	}
	for _, name := range []string{"shop", "shop-prod", "shop_2", "a"} {
		if !ValidProjectName(name) {
			t.Errorf("rejected name %q", name)
		}
	}
}

// The deployment goes only with the plan the operator approved.
func TestDeploymentRefusesOnDifferentPlan(t *testing.T) {
	executor := Executor{Planner: testPlanner(t, map[string]string{
		"config": configuration,
		"up":     "",
		"ps":     "",
	})}
	_, err := executor.Deploy(context.Background(), "shop", "services: {}", "0000000000000000", nil)
	if err == nil {
		t.Fatal("the deployment passed despite a different plan")
	}
	if !errors.Is(err, ErrPlanMismatch) || !strings.Contains(err.Error(), "changed since approval") {
		t.Errorf("error = %v", err)
	}
}

// A mutable tag is planned only once its digest is known, and the deployment
// binds that digest: a tag that moved between the approval and the deployment
// is a stale plan, not a surprise in production.
func TestMutableTagIsBoundToTheResolvedDigest(t *testing.T) {
	answers := map[string]string{"config": configuration, "up": "", "ps": ""}
	planner := Planner{Dir: t.TempDir(), Runner: runner(answers),
		Resolver: resolver(map[string]string{"postgres:16": digestA})}
	plan, err := planner.Plan(context.Background(), "shop", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var db Service
	for _, service := range plan.Services {
		if service.Name == "db" {
			db = service
		}
	}
	if db.ImageDigest != digestA || db.DigestSource != DigestFromRegistry ||
		db.PinnedImage != "postgres@"+digestA {
		t.Fatalf("the tag was not bound to its digest: %+v", db)
	}
	digests := plan.ImageDigests()
	if digests["db"] != digestA || digests["web"] != digestA {
		t.Errorf("image digests = %v", digests)
	}

	// The registry now serves another image under the same tag.
	moved := Executor{Planner: Planner{Dir: t.TempDir(), Runner: runner(answers),
		Resolver: resolver(map[string]string{"postgres:16": digestB})}}
	_, err = moved.Deploy(context.Background(), "shop", "services: {}", plan.Digest, plan.ImageDigests())
	if !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("a moved tag was deployed: %v", err)
	}
	// The same digest deploys, and the containers are started from the
	// pinned references through an override file next to the manifest.
	var upArguments []string
	steady := Executor{Planner: Planner{Dir: t.TempDir(),
		Runner: func(ctx context.Context, args ...string) (string, string, error) {
			if len(args) > 0 && strings.Contains(strings.Join(args, " "), " up ") && !strings.Contains(strings.Join(args, " "), "--dry-run") {
				upArguments = args
				for i, argument := range args {
					if argument == "-f" && i+1 < len(args) && strings.HasSuffix(args[i+1], "digests.override.yml") {
						content, err := os.ReadFile(args[i+1])
						if err != nil || !strings.Contains(string(content), "postgres@"+digestA) {
							t.Errorf("the override file does not pin the digest: %s (%v)", content, err)
						}
					}
				}
			}
			return runner(answers)(ctx, args...)
		},
		Resolver: resolver(map[string]string{"postgres:16": digestA})}}
	if _, err := steady.Deploy(context.Background(), "shop", "services: {}", plan.Digest, plan.ImageDigests()); err != nil {
		t.Fatalf("the same plan was refused: %v", err)
	}
	if !strings.Contains(strings.Join(upArguments, " "), "digests.override.yml") {
		t.Errorf("compose up ran without the override file: %v", upArguments)
	}
}

// A tag nobody can resolve is not planned: a plan with an empty digest
// would approve whatever the registry serves at deployment time.
func TestUnresolvedTagIsNotPlanned(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: runner(map[string]string{"config": configuration, "up": ""}),
		Resolver: resolver(map[string]string{})}
	if _, err := planner.Plan(context.Background(), "shop", "services: {}"); !errors.Is(err, ErrDigestUnresolved) {
		t.Fatalf("a tag without a digest was planned: %v", err)
	}
	// A planner without a resolver plans only pinned references.
	pinnedOnly := Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": `{"services": {"web": {"image": "nginx@` + digestA + `"}}}`, "up": ""})}
	if _, err := pinnedOnly.Plan(context.Background(), "shop", "services: {}"); err != nil {
		t.Fatalf("a pinned reference needs no resolver: %v", err)
	}
}

// The tag is replaced by the digest, and a registry port is not a tag.
func TestPinReferenceKeepsTheRepository(t *testing.T) {
	for image, want := range map[string]string{
		"nginx:alpine":                      "nginx@" + digestA,
		"nginx":                             "nginx@" + digestA,
		"registry.example:5000/shop/web:v2": "registry.example:5000/shop/web@" + digestA,
		"registry.example:5000/shop/web":    "registry.example:5000/shop/web@" + digestA,
		"nginx@" + digestB:                  "nginx@" + digestB,
	} {
		if got := PinReference(image, digestA); got != want {
			t.Errorf("PinReference(%q) = %q, want %q", image, got, want)
		}
	}
}

// The registry answer names one manifest per platform; the plan takes the
// one this host would pull and never an attestation.
func TestDigestIsPickedForTheHostPlatform(t *testing.T) {
	list := `[
	 {"Ref": "nginx:alpine@sha256:1", "Descriptor": {"digest": "` + digestB + `", "platform": {"architecture": "arm64", "os": "linux"}}},
	 {"Ref": "nginx:alpine@sha256:2", "Descriptor": {"digest": "` + digestA + `", "platform": {"architecture": "amd64", "os": "linux"}}},
	 {"Ref": "nginx:alpine@sha256:3", "Descriptor": {"digest": "` + digestB + `", "platform": {"architecture": "unknown", "os": "unknown"}}}
	]`
	if digest, err := digestFromManifest(list, "amd64"); err != nil || digest != digestA {
		t.Errorf("amd64 = %q, %v", digest, err)
	}
	if _, err := digestFromManifest(list, "s390x"); err == nil {
		t.Error("a platform the image lacks resolved to a digest")
	}
	single := `{"Ref": "shop/web:v2", "Descriptor": {"digest": "` + digestA + `"}}`
	if digest, err := digestFromManifest(single, "amd64"); err != nil || digest != digestA {
		t.Errorf("single manifest = %q, %v", digest, err)
	}

	// The local record names the repository with the digest; a bare name
	// is the library namespace on Docker Hub.
	local := `["docker.io/library/nginx@` + digestA + `"]`
	if digest, err := digestFromLocalImage(local, "nginx:alpine"); err != nil || digest != digestA {
		t.Errorf("local digest = %q, %v", digest, err)
	}
	if _, err := digestFromLocalImage(`[]`, "shop/web:v2"); err == nil {
		t.Error("an image built on the host resolved to a digest")
	}
}

// Compose reports the dry run on the diagnostic stream.
func TestChangesAreReadFromBothStreams(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: func(_ context.Context, args ...string) (string, string, error) {
		command := strings.Join(args, " ")
		if strings.Contains(command, "config") {
			return configuration, "", nil
		}
		// The dry run goes only to the diagnostic stream.
		return "", " DRY-RUN MODE -  Container shop-web-1  Creating", nil
	}, Resolver: resolver(map[string]string{"postgres:16": digestA})}
	plan, err := planner.Plan(context.Background(), "shop", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Name != "shop-web-1" {
		t.Fatalf("changes = %+v", plan.Changes)
	}
}
