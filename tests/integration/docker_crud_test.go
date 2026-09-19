//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Declared containers, networks and volumes on a real engine.

const declarationReason = "integration test of declared engine objects"

// declaredPlan is the plan the host computes; the change carries its
// digest back.
type declaredPlan struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Action  string `json:"action"`
	Exists  bool   `json:"exists"`
	Changes []struct {
		Field   string `json:"field"`
		Current string `json:"current"`
		Desired string `json:"desired"`
	} `json:"changes"`
	Warnings          []string `json:"warnings"`
	ImageDigest       string   `json:"image_digest"`
	DigestSource      string   `json:"digest_source"`
	PinnedImage       string   `json:"pinned_image"`
	Digest            string   `json:"digest"`
	CurrentID         string   `json:"current_id"`
	Detaches          []string `json:"detaches"`
	UnavailableReason string   `json:"unavailable_reason"`
}

// declarationDetail is the typed result the host sends back: the plan of a
// read, or what the change did.
type declarationDetail struct {
	Kind              string       `json:"kind"`
	Payload           declaredPlan `json:"payload"`
	UnavailableReason string       `json:"unavailable_reason"`
}

type declarationAttempt struct {
	Status    string             `json:"status"`
	ErrorCode string             `json:"error_code"`
	Message   string             `json:"message"`
	Detail    *declarationDetail `json:"detail"`
}

// What the test reads back off the host.
type declaredContainer struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Image  string            `json:"image"`
	State  string            `json:"state"`
	Labels map[string]string `json:"labels"`
}

type declaredNetwork struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Driver  string   `json:"driver"`
	Subnets []string `json:"subnets"`
}

type declaredVolume struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
}

type declaredImage struct {
	ID   string   `json:"id"`
	Tags []string `json:"tags"`
}

type declaredState struct {
	Containers []declaredContainer `json:"containers"`
	Networks   []declaredNetwork   `json:"networks"`
	Volumes    []declaredVolume    `json:"volumes"`
	Images     []declaredImage     `json:"images"`
}

// TestDeclaredObjectsAreCreatedAgainstAPlanAndReadBack walks one volume,
// one network and one container through the whole chain.
func TestDeclaredObjectsAreCreatedAgainstAPlanAndReadBack(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000)

	t.Run("volume", func(t *testing.T) {
		name := "flotestro-test-volume-" + suffix
		t.Cleanup(func() { removeEngineObject(h, host, map[string]any{"volume_names": []string{name}}) })

		description := map[string]any{
			"volume": map[string]any{
				"name": name, "driver": "local",
				"labels": map[string]any{"flotestro.test": "declared"},
			},
		}
		plan := declarationPlanOf(t, h, host.ID, description)
		if plan.Action != "create" {
			t.Fatalf("the plan of a volume the host does not have says %q, expected create", plan.Action)
		}
		runDeclaration(t, h, host, "docker.volume.ensure", description, plan.Digest)

		volume := declaredVolumeByName(declaredEngineState(t, h, host.ID).Volumes, name)
		if volume == nil {
			t.Fatalf("the host does not list the volume %s after the change", name)
		}

		// The same description a second time is no change at all: that is
		// what makes a declaration a declaration.
		again := declarationPlanOf(t, h, host.ID, description)
		if again.Action != "no_change" {
			t.Errorf("declaring the same volume twice plans %q, expected no_change: %+v",
				again.Action, again.Changes)
		}

		// A description that differs in something the engine cannot change in place
		// is not carried out silently: recreating a volume empties it, and the order
		// did not say it accepts that.
		conflicting := map[string]any{
			"volume": map[string]any{
				"name": name, "driver": "local",
				"options": map[string]any{"type": "tmpfs"},
			},
		}
		refusal := declarationRefusal(t, h, host.ID, conflicting)
		if refusal.ErrorCode != "docker_object_conflict" {
			t.Errorf("the plan of a conflicting volume answers %q, expected docker_object_conflict (%s)",
				refusal.ErrorCode, refusal.Message)
		}

		removal := map[string]any{"kind": "volume", "name": name}
		gone := declarationPlanOf(t, h, host.ID, removal)
		if gone.Action != "remove" {
			t.Fatalf("the plan of the removal says %q, expected remove", gone.Action)
		}
		runDeclaration(t, h, host, "docker.volume.remove", removal, gone.Digest)
		if declaredVolumeByName(declaredEngineState(t, h, host.ID).Volumes, name) != nil {
			t.Errorf("the host still lists the volume %s after the removal", name)
		}
	})

	t.Run("network", func(t *testing.T) {
		name := "flotestro-test-network-" + suffix
		var created string
		t.Cleanup(func() {
			if created != "" {
				removeEngineObject(h, host, map[string]any{"network_ids": []string{created}})
			}
		})

		description := map[string]any{
			"network": map[string]any{
				"name": name, "driver": "bridge",
				"subnet": "10.244.0.0/24", "gateway": "10.244.0.1",
				"internal": true,
				"labels":   map[string]any{"flotestro.test": "declared"},
			},
		}
		plan := declarationPlanOf(t, h, host.ID, description)
		if plan.Action != "create" {
			t.Fatalf("the plan of a network the host does not have says %q, expected create", plan.Action)
		}
		runDeclaration(t, h, host, "docker.network.ensure", description, plan.Digest)

		network := declaredNetworkByName(declaredEngineState(t, h, host.ID).Networks, name)
		if network == nil {
			t.Fatalf("the host does not list the network %s after the change", name)
		}
		created = network.ID
		if network.Driver != "bridge" {
			t.Errorf("the network %s has the driver %q", name, network.Driver)
		}

		again := declarationPlanOf(t, h, host.ID, description)
		if again.Action != "no_change" {
			t.Errorf("declaring the same network twice plans %q, expected no_change: %+v",
				again.Action, again.Changes)
		}

		removal := map[string]any{"kind": "network", "name": name}
		gone := declarationPlanOf(t, h, host.ID, removal)
		if gone.Action != "remove" {
			t.Fatalf("the plan of the removal says %q, expected remove", gone.Action)
		}
		runDeclaration(t, h, host, "docker.network.remove", removal, gone.Digest)
		if declaredNetworkByName(declaredEngineState(t, h, host.ID).Networks, name) != nil {
			t.Errorf("the host still lists the network %s after the removal", name)
		}
		created = ""
	})

	t.Run("container", func(t *testing.T) {
		image := imageOnHost(t, h, host.ID)
		name := "flotestro-test-container-" + suffix
		t.Cleanup(func() { removeDeclaredContainer(h, host, name) })

		// The container is declared stopped: it exists, and nothing about the test
		// depends on the entry point of whichever image the lab happens to hold.
		description := func(label string) map[string]any {
			return map[string]any{
				"container": map[string]any{
					"name": name, "image": image, "stopped": true,
					"labels": map[string]any{"flotestro.test": label},
				},
			}
		}
		first := description("declared")
		plan := declarationPlanOf(t, h, host.ID, first)
		if plan.Action != "create" {
			t.Fatalf("the plan of a container the host does not have says %q, expected create", plan.Action)
		}
		// The tag is bound to a digest before anything is approved: a deployment of
		// "whatever the registry serves right now" is the one thing a plan must
		// never authorise.
		if plan.ImageDigest == "" || plan.PinnedImage == "" {
			t.Fatalf("the plan did not bind the image to a digest: %+v", plan)
		}

		// A change without the digest of a plan has no basis and is refused
		// before a job is ever queued for it.
		var problem struct {
			Code string `json:"code"`
		}
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "docker.container.ensure", "reason": declarationReason,
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"docker_ensure": first},
		}, &problem, http.StatusBadRequest)
		if problem.Code != "invalid_payload" {
			t.Errorf("a declaration without a plan answers %q, expected invalid_payload", problem.Code)
		}

		runDeclaration(t, h, host, "docker.container.ensure", first, plan.Digest)

		container := declaredContainerByName(declaredEngineState(t, h, host.ID).Containers, name)
		if container == nil {
			t.Fatalf("the host does not list the container %s after the change", name)
		}
		if container.Labels["io.flotestro.spec"] == "" {
			t.Errorf("the container %s does not carry the digest of the description it was created from", name)
		}

		again := declarationPlanOf(t, h, host.ID, first)
		if again.Action != "no_change" {
			t.Errorf("declaring the same container twice plans %q, expected no_change: %+v",
				again.Action, again.Changes)
		}

		// A container that differs is replaced, and the plan says which setting
		// brought that about: a verdict without the list behind it would ask the
		// operator to approve a word.
		second := description("changed")
		replacement := declarationPlanOf(t, h, host.ID, second)
		if replacement.Action != "replace" {
			t.Fatalf("a changed description plans %q, expected replace", replacement.Action)
		}
		if len(replacement.Changes) == 0 {
			t.Fatal("a replacement without a change list")
		}

		// The digest of the first plan no longer describes the host, and a change
		// carrying it is refused rather than carried out against a state nobody
		// approved.
		stale := declarationOrder(t, h, host, "docker.container.ensure", second, plan.Digest)
		if stale.State == "succeeded" {
			t.Fatal("a change bound to a plan that no longer holds was carried out")
		}
		if stale.ResultErrorCode != "stale_plan" {
			t.Errorf("a stale plan answers %q, expected stale_plan (%s)",
				stale.ResultErrorCode, stale.ResultMessage)
		}

		runDeclaration(t, h, host, "docker.container.ensure", second, replacement.Digest)
		replaced := declaredContainerByName(declaredEngineState(t, h, host.ID).Containers, name)
		if replaced == nil {
			t.Fatalf("the host does not list the container %s after the replacement", name)
		}
		if replaced.Labels["flotestro.test"] != "changed" {
			t.Errorf("the container %s carries the label %q after the replacement",
				name, replaced.Labels["flotestro.test"])
		}
		if replaced.ID == container.ID {
			t.Error("the container was edited rather than replaced; the engine changes only a handful of settings in place")
		}
	})
}

// declarationPlanOf orders the plan of a declared object and returns it. A
// plan is a read: it changes nothing and needs no approval of its own.
func declarationPlanOf(t *testing.T, h *harness, hostID string, section map[string]any) declaredPlan {
	t.Helper()
	attempt := declarationRun(t, h, hostID, section)
	if attempt.Status != "succeeded" {
		t.Fatalf("the plan did not succeed: %s %s", attempt.ErrorCode, attempt.Message)
	}
	if attempt.Detail == nil {
		t.Fatal("the host sent no plan back")
	}
	if attempt.Detail.Payload.UnavailableReason != "" {
		t.Skipf("the container engine is unavailable: %s", attempt.Detail.Payload.UnavailableReason)
	}
	if attempt.Detail.Payload.Digest == "" {
		t.Fatalf("the plan carries no digest to bind a change to: %+v", attempt.Detail.Payload)
	}
	return attempt.Detail.Payload
}

// declarationRefusal orders a plan that is expected to be refused and
// returns the attempt.
func declarationRefusal(t *testing.T, h *harness, hostID string, section map[string]any) declarationAttempt {
	t.Helper()
	attempt := declarationRun(t, h, hostID, section)
	if attempt.Status == "succeeded" {
		t.Fatalf("a plan that was to be refused succeeded: %+v", attempt.Detail)
	}
	return attempt
}

func declarationRun(t *testing.T, h *harness, hostID string, section map[string]any) declarationAttempt {
	t.Helper()
	job := h.createOperation(hostID, map[string]any{
		"action": "docker.plan", "reason": declarationReason,
		"payload": map[string]any{"docker_ensure": section},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	h.awaitTerminal(job.ID, 3*time.Minute)

	var result struct {
		Items []declarationAttempt `json:"items"`
	}
	h.get("/api/v1/jobs/"+job.ID+"/attempts", &result)
	if len(result.Items) == 0 {
		t.Fatalf("the job %s has no attempt", job.ID)
	}
	return result.Items[len(result.Items)-1]
}

// declarationOrder carries a plan out and returns the finished job, whatever
// it ended as.
func declarationOrder(t *testing.T, h *harness, host hostView,
	action string, section map[string]any, digest string) jobView {
	t.Helper()
	ordered := map[string]any{}
	for key, value := range section {
		ordered[key] = value
	}
	ordered["plan_digest"] = digest

	job := h.createOperation(host.ID, map[string]any{
		"action": action, "reason": declarationReason,
		"target_confirmation": host.Hostname,
		"payload":             map[string]any{"docker_ensure": ordered},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	if job.CollectedApprovals < job.RequiredApprovals {
		second := h.withToken(h.createPrincipal(uniqueSubject("approver-declared"),
			[]map[string]string{
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))
		second.approve(job.ID, job.PayloadHash)
	}
	return h.awaitTerminal(job.ID, 5*time.Minute)
}

// runDeclaration carries a plan out and requires that the host confirmed the
// state afterwards.
func runDeclaration(t *testing.T, h *harness, host hostView,
	action string, section map[string]any, digest string) {
	t.Helper()
	final := declarationOrder(t, h, host, action, section, digest)
	if final.State != "succeeded" {
		t.Fatalf("%s: state = %s, %s (%s)", action, final.State,
			final.ResultErrorCode, lastMessage(h.attempts(final.ID)))
	}
}

// imageOnHost picks an image the host already holds.
func imageOnHost(t *testing.T, h *harness, hostID string) string {
	t.Helper()
	for _, image := range declaredEngineState(t, h, hostID).Images {
		for _, tag := range image.Tags {
			if tag != "" && tag != "<none>:<none>" {
				return tag
			}
		}
	}
	t.Skip("the host holds no tagged image to declare a container from")
	return ""
}

// removeEngineObject cleans up through the operation that exists for it.
func removeEngineObject(h *harness, host hostView, prune map[string]any) {
	job := h.createOperation(host.ID, map[string]any{
		"action": "docker.prune", "reason": declarationReason,
		"target_confirmation": host.Hostname,
		"payload":             map[string]any{"docker_prune": prune},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	if job.CollectedApprovals < job.RequiredApprovals {
		second := h.withToken(h.createPrincipal(uniqueSubject("approver-declared-cleanup"),
			[]map[string]string{
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))
		second.approve(job.ID, job.PayloadHash)
	}
	h.awaitJobState(job.ID, 3*time.Minute, "succeeded", "failed", "timed_out", "canceled", "expired")
}

// removeDeclaredContainer takes the test container away by the identifier
// the host reports for the name.
func removeDeclaredContainer(h *harness, host hostView, name string) {
	var fragment struct {
		Payload declaredState `json:"payload"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/containers.full",
		nil, &fragment, http.StatusOK)
	container := declaredContainerByName(fragment.Payload.Containers, name)
	if container == nil {
		return
	}
	job := h.createOperation(host.ID, map[string]any{
		"action": "docker.container.remove", "reason": declarationReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{
			"docker_container": map[string]any{"container_id": container.ID, "name": name},
		},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	if job.CollectedApprovals < job.RequiredApprovals {
		second := h.withToken(h.createPrincipal(uniqueSubject("approver-declared-container"),
			[]map[string]string{
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))
		second.approve(job.ID, job.PayloadHash)
	}
	h.awaitJobState(job.ID, 3*time.Minute, "succeeded", "failed", "timed_out", "canceled", "expired")
}

// declaredEngineState reads the host again and returns what it holds.
func declaredEngineState(t *testing.T, h *harness, hostID string) declaredState {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "docker.read", "reason": declarationReason,
		"payload": map[string]any{"docker_read": map[string]any{}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("engine read: state = %s, %s", job.State, lastMessage(attempts))
	}
	var fragment struct {
		Payload           declaredState `json:"payload"`
		UnavailableReason string        `json:"unavailable_reason"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/containers.full",
		nil, &fragment, http.StatusOK)
	if fragment.UnavailableReason != "" {
		t.Skipf("the container engine is unavailable: %s", fragment.UnavailableReason)
	}
	return fragment.Payload
}

func declaredContainerByName(list []declaredContainer, name string) *declaredContainer {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func declaredNetworkByName(list []declaredNetwork, name string) *declaredNetwork {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func declaredVolumeByName(list []declaredVolume, name string) *declaredVolume {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}
