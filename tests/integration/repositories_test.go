//go:build integration

package integration

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const sourceReason = "integration test of the package sources"

type repositoryView struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	URL               string `json:"url"`
	Enabled           bool   `json:"enabled"`
	Signed            bool   `json:"signed"`
	Username          string `json:"username"`
	SecretName        string `json:"secret_name"`
	Managed           bool   `json:"managed"`
	Path              string `json:"path"`
	UnavailableReason string `json:"unavailable_reason"`
}

type packagesFragmentView struct {
	Manager      string `json:"manager"`
	Repositories struct {
		Repositories []repositoryView `json:"repositories"`
		Known        bool             `json:"repositories_known"`
		Reason       string           `json:"repositories_unavailable_reason"`
	} `json:"repositories"`
}

// sourceKey composes public key material in an ASCII armour.
//
// The packet is minimal but real: version 4, a timestamp, the algorithm and
// the material. The host computes its fingerprint the same way it would for
// a vendor key - and the test source is disabled, so nobody verifies
// anything with this key.
func sourceKey() string {
	packet := append([]byte{4, 0x66, 0x00, 0x00, 0x00, 1}, make([]byte, 20)...)
	frame := append([]byte{0xc0 | 6, byte(len(packet))}, packet...)
	return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" +
		base64.StdEncoding.EncodeToString(frame) +
		"\n-----END PGP PUBLIC KEY BLOCK-----\n"
}

// hostSources reads the package sources from the host inventory.
func hostSources(h *harness, hostID string) packagesFragmentView {
	h.t.Helper()
	var fragment struct {
		Payload packagesFragmentView `json:"payload"`
	}
	h.get("/api/v1/hosts/"+hostID+"/inventory/packages", &fragment)
	return fragment.Payload
}

func findSource(sources []repositoryView, id string) *repositoryView {
	for i := range sources {
		if sources[i].ID == id {
			return &sources[i]
		}
	}
	return nil
}

// TestPackageSourceWithAPasswordFromTheStore walks the whole path of the
// operation: writing a source together with a key and a password, reading
// it from the inventory, the rollback after a failed metadata fetch and
// removal.
func TestPackageSourceWithAPasswordFromTheStore(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	id := fmt.Sprintf("flotestro-test-%d", time.Now().UnixNano()%100000)
	password := fmt.Sprintf("source-password-%d", time.Now().UnixNano())
	secret := newSecret(t, h, password)

	description := map[string]any{
		"id": id, "name": "Test source",
		"url": "https://packages.example.test/debian",
		// A disabled source: the host writes the files but does not try to
		// fetch metadata from an address this network does not have.
		"suites": []string{"stable"}, "components": []string{"main"},
		"enabled": false, "gpg_key": sourceKey(),
		"username": "fleet", "password_secret": map[string]any{"name": secret.Name},
	}
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "packages.repository.set", "reason": sourceReason,
			"payload": map[string]any{"repository": map[string]any{"id": id, "remove": true}},
		}, 3*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.repository.set", "reason": sourceReason,
		"payload": map[string]any{"repository": description},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("writing the source ended in state %s: %+v", job.State, attempts)
	}

	fragment := hostSources(h, host.ID)
	if !fragment.Repositories.Known {
		t.Fatalf("the host did not read the sources: %s", fragment.Repositories.Reason)
	}
	written := findSource(fragment.Repositories.Repositories, id)
	if written == nil {
		t.Fatalf("source %s is not in the inventory: %+v", id, fragment.Repositories.Repositories)
	}
	if !written.Managed {
		t.Error("a source written by the panel is not marked as managed")
	}
	if written.Enabled {
		t.Error("a disabled source was written as enabled")
	}
	if !written.Signed {
		t.Error("a source with signature checking was written without it")
	}
	// The panel sees the secret name and the username; the password value
	// is seen by nobody but the store and the host at write time.
	if written.SecretName != secret.Name || written.Username != "fleet" {
		t.Errorf("the secret binding described as %+v", written)
	}
	assertValueAbsent(t, h, password)

	// Enabling a source that cannot be fetched must leave the host in the
	// state before the change: a source that does not answer would block
	// every following package operation.
	broken := map[string]any{}
	for key, value := range description {
		broken[key] = value
	}
	broken["enabled"] = true
	failed, _ := h.runOperation(host.ID, map[string]any{
		"action": "packages.repository.set", "reason": sourceReason,
		"payload": map[string]any{"repository": broken},
	}, 5*time.Minute)
	if failed.State == "succeeded" {
		t.Fatal("a source that cannot be fetched was accepted")
	}
	after := findSource(hostSources(h, host.ID).Repositories.Repositories, id)
	if after == nil || after.Enabled {
		t.Fatalf("after the failed change the source looks like this: %+v", after)
	}

	// Removal takes the source away together with the key and the password.
	removal, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.repository.set", "reason": sourceReason,
		"payload": map[string]any{"repository": map[string]any{"id": id, "remove": true}},
	}, 3*time.Minute)
	if removal.State != "succeeded" {
		t.Fatalf("removing the source ended in state %s: %+v", removal.State, attempts)
	}
	if remaining := findSource(hostSources(h, host.ID).Repositories.Repositories, id); remaining != nil {
		t.Fatalf("the source remained after removal: %+v", remaining)
	}
}

// TestUnreachableSourceRollsBackTheChange guards the rollback on both
// families.
//
// Neither apt nor dnf reports a failed metadata fetch with the exit status:
// both end with zero and a message about the cache being built. A source
// that does not answer would nevertheless block every following package
// operation - so the panel has to read what the tool wrote and undo the
// change.
func TestUnreachableSourceRollsBackTheChange(t *testing.T) {
	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(family)
			id := fmt.Sprintf("flotestro-unreachable-%d", time.Now().UnixNano()%100000)

			description := map[string]any{
				"id": id, "url": "https://packages.example.test/repo",
				"enabled": false, "gpg_key": sourceKey(),
			}
			if family == "debian" {
				description["suites"] = []string{"stable"}
				description["components"] = []string{"main"}
			}
			t.Cleanup(func() {
				h.runOperation(host.ID, map[string]any{
					"action": "packages.repository.set", "reason": sourceReason,
					"payload": map[string]any{"repository": map[string]any{"id": id, "remove": true}},
				}, 3*time.Minute)
			})

			job, attempts := h.runOperation(host.ID, map[string]any{
				"action": "packages.repository.set", "reason": sourceReason,
				"payload": map[string]any{"repository": description},
			}, 3*time.Minute)
			if job.State != "succeeded" {
				t.Fatalf("writing the disabled source ended in state %s: %+v",
					job.State, attempts)
			}

			enabled := map[string]any{}
			for key, value := range description {
				enabled[key] = value
			}
			enabled["enabled"] = true
			failed, attempts := h.runOperation(host.ID, map[string]any{
				"action": "packages.repository.set", "reason": sourceReason,
				"payload": map[string]any{"repository": enabled},
			}, 5*time.Minute)
			if failed.State == "succeeded" {
				t.Fatal("a source that cannot be fetched was accepted")
			}
			if len(attempts) == 0 || !strings.Contains(attempts[len(attempts)-1].Message, "was restored") {
				t.Fatalf("the refusal does not mention the rollback: %+v", attempts)
			}
			after := findSource(hostSources(h, host.ID).Repositories.Repositories, id)
			if after == nil || after.Enabled {
				t.Fatalf("after the failed change the source looks like this: %+v", after)
			}
		})
	}
}

// TestPackageSourceGuardsTrust guards the boundaries of the operation: a
// source is a decision about whose packages the host accepts, so a bad
// order is to fall out when ordered, not on the host.
func TestPackageSourceGuardsTrust(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	bad := map[string]map[string]any{
		"no key and no consent": {
			"id": "flotestro-no-key", "url": "https://packages.example.test/debian",
			"suites": []string{"stable"}, "enabled": true,
		},
		"unsigned over http": {
			"id": "flotestro-http", "url": "http://packages.example.test/debian",
			"suites": []string{"stable"}, "enabled": true, "allow_unsigned": true,
		},
		"material that is not a key": {
			"id": "flotestro-bad-key", "url": "https://packages.example.test/debian",
			"suites": []string{"stable"}, "enabled": true,
			"gpg_key": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		},
		"identifier escaping the directory": {
			"id": "../../etc/apt/sources.list", "url": "https://packages.example.test/debian",
			"suites": []string{"stable"}, "enabled": true, "allow_unsigned": true,
		},
		"password over http": {
			"id": "flotestro-password-http", "url": "http://packages.example.test/debian",
			"suites": []string{"stable"}, "enabled": true, "allow_unsigned": true,
			"username": "fleet", "password_secret": map[string]any{"name": "no.such.secret"},
		},
	}
	for name, description := range bad {
		t.Run(name, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
				"action": "packages.repository.set", "reason": sourceReason,
				"payload": map[string]any{"repository": description},
			}, nil, http.StatusBadRequest)
		})
	}

	// A source without signature checking is admissible only as the
	// operator's explicit consent - and only over https.
	t.Run("explicit consent over https", func(t *testing.T) {
		var job jobView
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "packages.repository.set", "reason": sourceReason,
			"payload": map[string]any{"repository": map[string]any{
				"id": "flotestro-consent", "url": "https://packages.example.test/debian",
				"suites": []string{"stable"}, "enabled": false, "allow_unsigned": true,
			}},
		}, &job, http.StatusCreated)
		// The job is not executed: the ordering boundary is checked, not
		// the write.
		h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel", nil, nil, 0)
	})
}

// TestSourcesInTheInventoryAreRead guards that an empty list and an unread
// list are two different answers.
func TestSourcesInTheInventoryAreRead(t *testing.T) {
	h := newHarness(t)
	for _, family := range []string{"debian", "rhel"} {
		fragment := hostSources(h, h.hostByFamily(family).ID)
		if !fragment.Repositories.Known {
			t.Errorf("%s: sources not read (%s)", family, fragment.Repositories.Reason)
			continue
		}
		if len(fragment.Repositories.Repositories) == 0 {
			t.Errorf("%s: the host reports no package source at all", family)
		}
		// Distribution sources are not managed by the panel and are to look
		// that way.
		for _, source := range fragment.Repositories.Repositories {
			if source.Managed {
				t.Errorf("%s: the distribution source %s described as managed", family, source.ID)
			}
		}
	}
}
