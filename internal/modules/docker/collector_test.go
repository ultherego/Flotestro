package docker

import "testing"

// The summary is meant to answer "does something need attention", not to
// count everything one by one. A container coming up over and over is fine
// at every single moment and broken nevertheless.
func TestSummaryDetectsRestartLoops(t *testing.T) {
	snapshot := Snapshot{Containers: []Container{
		{Name: "calm", State: "running", RestartCount: 1},
		{Name: "comes-up-over-and-over", State: "running", RestartCount: 12},
		{Name: "coming-up-now", State: "restarting"},
	}}
	summary := summarise(snapshot, Summary{})

	if summary.RestartLooping != 2 {
		t.Errorf("restart loops = %d, want 2", summary.RestartLooping)
	}
	if summary.Running != 2 {
		t.Errorf("running = %d, want 2", summary.Running)
	}
	if summary.Stopped != 1 {
		t.Errorf("stopped = %d, want 1 (restarting is not running)", summary.Stopped)
	}
}

// Compose containers are grouped into projects: the operator manages the
// project, not the individual containers Compose created itself.
func TestContainersAreGroupedIntoProjects(t *testing.T) {
	snapshot := Snapshot{Containers: []Container{
		{Name: "shop-web-1", State: "running", Compose: &ComposeMembership{Project: "shop", Service: "web"}},
		{Name: "shop-db-1", State: "exited", Compose: &ComposeMembership{Project: "shop", Service: "db"}},
		{Name: "shop-web-2", State: "running", Compose: &ComposeMembership{Project: "shop", Service: "web"}},
		{Name: "lonely", State: "running"},
	}}
	summary := summarise(snapshot, Summary{})

	if len(summary.Projects) != 1 {
		t.Fatalf("projects = %d, want 1", len(summary.Projects))
	}
	project := summary.Projects[0]
	if project.Name != "shop" || project.Total != 3 || project.Running != 2 {
		t.Errorf("project = %+v", project)
	}
	if len(project.Services) != 2 {
		t.Errorf("services = %v, want two unique ones", project.Services)
	}
}

// An unavailable engine is not the same as a host without containers. An
// empty list without a reason would look like a tidy host.
func TestMissingAdapterCarriesReason(t *testing.T) {
	snapshot := Collect(t.Context(), nil)
	if snapshot.Summary.UnavailableReason == "" {
		t.Error("the missing adapter was not explained")
	}
	if snapshot.Summary.Containers != 0 || snapshot.Containers != nil {
		t.Error("an unread state must not pretend to be an empty list")
	}
}

// A label with a name suggesting a credential is hidden. The inventory is
// durable and visible more widely than the host itself.
func TestLabelsWithCredentialsAreHidden(t *testing.T) {
	result := labelsWithoutSecrets(map[string]string{
		"com.docker.compose.project": "shop",
		"DB_PASSWORD":                "secret",
		"api_key":                    "abc123",
		"description":                "plain label",
	})
	if result["DB_PASSWORD"] != "[hidden]" || result["api_key"] != "[hidden]" {
		t.Errorf("credentials were not hidden: %v", result)
	}
	if result["description"] != "plain label" || result["com.docker.compose.project"] != "shop" {
		t.Errorf("plain labels were changed: %v", result)
	}
}

// Compose marks its containers with labels; a container outside a project
// must not be assigned to any.
func TestComposeMembershipOnlyFromLabels(t *testing.T) {
	if composeMembership(map[string]string{"whatever": "x"}) != nil {
		t.Error("a container without Compose labels was assigned to a project")
	}
	membership := composeMembership(map[string]string{
		"com.docker.compose.project": "shop",
		"com.docker.compose.service": "web",
	})
	if membership == nil || membership.Project != "shop" || membership.Service != "web" {
		t.Errorf("membership = %+v", membership)
	}
}
