package compose

import (
	"context"
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

const configuration = `{
  "services": {
    "web": {"image": "nginx@sha256:aaaa", "environment": {"PORT": "80"}},
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

// A manifest with the same services and images may publish a different
// port or run a different command. A digest computed from the service list
// alone would let through the deployment of a plan the operator did not
// see.
func TestDigestCoversWholeManifest(t *testing.T) {
	services := []Service{{Name: "web", Image: "nginx:alpine", Replicas: 1}}
	withPort8083 := `{"services":{"web":{"image":"nginx:alpine","ports":[{"published":"8083"}]}}}`
	withPort8084 := `{"services":{"web":{"image":"nginx:alpine","ports":[{"published":"8084"}]}}}`

	if Digest("shop", withPort8083, services) == Digest("shop", withPort8084, services) {
		t.Error("a port change did not change the plan digest")
	}
}

// The manifest is stored in the panel together with the version history,
// so a value written into it directly stops being a secret. The operator is
// meant to see that before approving, not after the leak.
func TestPlanWarnsAboutSecretsInManifest(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": configuration,
		"up":     " DRY-RUN MODE -  Container shop-web-1  Creating",
	})}
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
	planner := Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": `{"services": {"web": {"image": "nginx@sha256:aaaa"}}}`,
		"up":     "",
	})}
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

// Compose reports every step twice - during and after. A doubled change
// list would suggest to the operator twice as much work as the deployment
// does.
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

// The deployment goes only with the plan the operator approved. A
// different digest means the deployment would bring something else than
// what they viewed.
func TestDeploymentRefusesOnDifferentPlan(t *testing.T) {
	executor := Executor{Planner: Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": configuration,
		"up":     "",
		"ps":     "",
	})}}
	_, err := executor.Deploy(context.Background(), "shop", "services: {}", "0000000000000000")
	if err == nil {
		t.Fatal("the deployment passed despite a different plan")
	}
	if !strings.Contains(err.Error(), "changed since approval") {
		t.Errorf("error = %v", err)
	}
}

// Compose reports the dry run on the diagnostic stream. Reading the output
// alone gave an empty change list, that is a plan saying the deployment
// changes nothing - the worst possible answer.
func TestChangesAreReadFromBothStreams(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: func(_ context.Context, args ...string) (string, string, error) {
		command := strings.Join(args, " ")
		if strings.Contains(command, "config") {
			return configuration, "", nil
		}
		// The dry run goes only to the diagnostic stream.
		return "", " DRY-RUN MODE -  Container shop-web-1  Creating", nil
	}}
	plan, err := planner.Plan(context.Background(), "shop", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Name != "shop-web-1" {
		t.Fatalf("changes = %+v", plan.Changes)
	}
}
