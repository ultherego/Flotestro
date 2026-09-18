package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/systemd"
)

// The verifiers are checked against a host made of stub readers: every case
// says what the host shows, and the test asks what the verifier makes of
// it. Three answers matter and each is checked separately - a match, a
// state other than the one ordered, and a host that could not be read,
// which is never a pass and never a failure of the change.

func expectVerified(t *testing.T, found observation) {
	t.Helper()
	if !found.verified {
		t.Fatalf("the state matches and the verifier says otherwise: expected %q, observed %q, reason %q",
			found.expected, found.observed, found.reason)
	}
	if found.reason != "" {
		t.Fatalf("a verified observation carries a reason: %q", found.reason)
	}
}

func expectMismatch(t *testing.T, found observation) {
	t.Helper()
	if found.verified {
		t.Fatalf("the state differs and the verifier passed it: expected %q, observed %q",
			found.expected, found.observed)
	}
	if strings.HasPrefix(found.reason, "the verifier could not read the host") {
		t.Fatalf("a difference was reported as an unread host: %q", found.reason)
	}
	if found.reason == "" {
		t.Fatal("a mismatch without a reason says nothing to the operator")
	}
}

func expectUnreadable(t *testing.T, found observation) {
	t.Helper()
	if found.verified {
		t.Fatalf("a host that could not be read was passed as verified: %q", found.observed)
	}
	if found.observed != "unknown" {
		t.Fatalf("an unread host observed %q instead of unknown", found.observed)
	}
	if !strings.HasPrefix(found.reason, "the verifier could not read the host") {
		t.Fatalf("an unread host is not named as one: %q", found.reason)
	}
}

func TestVerifyingTheStateOfAUnit(t *testing.T) {
	in := verifyInput{
		action:  opspec.ActionUnitRestart,
		payload: opspec.Payload{Unit: &opspec.UnitPayload{Unit: "nginx.service"}},
	}
	state := func(active, sub string) *hostReaders {
		return &hostReaders{unit: func(context.Context, string) (systemd.UnitState, error) {
			return systemd.UnitState{Name: "nginx.service", LoadState: "loaded",
				ActiveState: active, SubState: sub}, nil
		}}
	}

	expectVerified(t, verifyUnitState(context.Background(), state("active", "running"), in))
	expectMismatch(t, verifyUnitState(context.Background(), state("failed", "failed"), in))
	expectMismatch(t, verifyUnitState(context.Background(), state("active", "auto-restart"), in))

	broken := &hostReaders{unit: func(context.Context, string) (systemd.UnitState, error) {
		return systemd.UnitState{}, errors.New("systemctl is not on this host")
	}}
	expectUnreadable(t, verifyUnitState(context.Background(), broken, in))
	expectUnreadable(t, verifyUnitState(context.Background(), &hostReaders{}, in))
}

func TestVerifyingTheStopOfAUnit(t *testing.T) {
	in := verifyInput{
		action:  opspec.ActionUnitStop,
		payload: opspec.Payload{Unit: &opspec.UnitPayload{Unit: "nginx.service"}},
	}
	stopped := &hostReaders{unit: func(context.Context, string) (systemd.UnitState, error) {
		return systemd.UnitState{LoadState: "loaded", ActiveState: "inactive", SubState: "dead"}, nil
	}}
	running := &hostReaders{unit: func(context.Context, string) (systemd.UnitState, error) {
		return systemd.UnitState{LoadState: "loaded", ActiveState: "active", SubState: "running"}, nil
	}}
	expectVerified(t, verifyUnitState(context.Background(), stopped, in))
	expectMismatch(t, verifyUnitState(context.Background(), running, in))
}

func TestVerifyingTheContentOfAFile(t *testing.T) {
	content := "server 10.0.0.1\n"
	in := verifyInput{
		action: opspec.ActionFileEnsure,
		payload: opspec.Payload{File: &opspec.FilePayload{
			Path: "/etc/resolv.conf", Content: content, Mode: "0644", Owner: "root",
		}},
	}
	host := func(state fileState, err error) *hostReaders {
		return &hostReaders{file: func(context.Context, string) (fileState, error) {
			return state, err
		}}
	}

	written := fileState{exists: true, sha256: contentDigest(content), mode: "0644", owner: "root"}
	expectVerified(t, verifyFileContent(context.Background(), host(written, nil), in))

	somebodyElse := fileState{exists: true, sha256: contentDigest("server 10.0.0.2\n"), mode: "0644", owner: "root"}
	expectMismatch(t, verifyFileContent(context.Background(), host(somebodyElse, nil), in))
	expectMismatch(t, verifyFileContent(context.Background(), host(fileState{}, nil), in))

	wrongMode := fileState{exists: true, sha256: contentDigest(content), mode: "0600", owner: "root"}
	expectMismatch(t, verifyFileContent(context.Background(), host(wrongMode, nil), in))

	expectUnreadable(t, verifyFileContent(context.Background(),
		host(fileState{}, errors.New("the helper did not answer")), in))

	// The digest of the content never travels whole and the content never
	// travels at all.
	found := verifyFileContent(context.Background(), host(written, nil), in)
	if strings.Contains(found.expected+found.observed, content) {
		t.Fatal("the observation carries the content of the file")
	}
	if len(found.observed) > 32 {
		t.Fatalf("the observation carries more than a short digest: %q", found.observed)
	}
}

func TestVerifyingTheRemovalOfAFile(t *testing.T) {
	in := verifyInput{
		action:  opspec.ActionFileRemove,
		payload: opspec.Payload{File: &opspec.FilePayload{Path: "/etc/motd"}},
	}
	gone := &hostReaders{file: func(context.Context, string) (fileState, error) {
		return fileState{}, nil
	}}
	there := &hostReaders{file: func(context.Context, string) (fileState, error) {
		return fileState{exists: true, sha256: contentDigest("hello")}, nil
	}}
	expectVerified(t, verifyFileContent(context.Background(), gone, in))
	expectMismatch(t, verifyFileContent(context.Background(), there, in))
}

func TestVerifyingThePackageVersions(t *testing.T) {
	in := verifyInput{
		action: opspec.ActionPackageInstall,
		payload: opspec.Payload{PackageChange: &opspec.PackageChangePayload{
			Packages: []string{"bind9"},
			Plan: &opspec.PlanReference{Changes: []opspec.PlanChangeEntry{
				{Name: "bind9", CandidateVersion: "3.0.16-1~deb12u1", Action: "install"},
			}},
		}},
	}
	host := func(list packages.InstalledList) *hostReaders {
		return &hostReaders{installed: func(context.Context) packages.InstalledList { return list }}
	}

	at := packages.InstalledList{Manager: "apt", Packages: []packages.InstalledPackage{
		{Name: "bind9", Version: "3.0.16", Release: "1~deb12u1"},
	}}
	expectVerified(t, verifyPackageVersions(context.Background(), host(at), in))

	older := packages.InstalledList{Manager: "apt", Packages: []packages.InstalledPackage{
		{Name: "bind9", Version: "3.0.15", Release: "1~deb12u1"},
	}}
	expectMismatch(t, verifyPackageVersions(context.Background(), host(older), in))
	expectMismatch(t, verifyPackageVersions(context.Background(),
		host(packages.InstalledList{Manager: "apt"}), in))

	expectUnreadable(t, verifyPackageVersions(context.Background(),
		host(packages.InstalledList{UnavailableReason: "the package database was not read"}), in))
}

func TestVerifyingTheRemovalOfAPackage(t *testing.T) {
	in := verifyInput{
		action: opspec.ActionPackageRemove,
		payload: opspec.Payload{PackageChange: &opspec.PackageChangePayload{
			Packages:         []string{"telnet"},
			ExpectedRemovals: []string{"telnet"},
		}},
	}
	empty := &hostReaders{installed: func(context.Context) packages.InstalledList {
		return packages.InstalledList{Manager: "apt"}
	}}
	still := &hostReaders{installed: func(context.Context) packages.InstalledList {
		return packages.InstalledList{Manager: "apt", Packages: []packages.InstalledPackage{
			{Name: "telnet", Version: "0.17"},
		}}
	}}
	expectVerified(t, verifyPackageVersions(context.Background(), empty, in))
	expectMismatch(t, verifyPackageVersions(context.Background(), still, in))
}

func TestVerifyingTheHostName(t *testing.T) {
	in := verifyInput{
		action:  opspec.ActionSystemHostnameSet,
		payload: opspec.Payload{Hostname: &opspec.HostnamePayload{Hostname: "web01.example.test"}},
	}
	host := func(name string, err error) *hostReaders {
		return &hostReaders{hostname: func() (string, error) { return name, err }}
	}
	expectVerified(t, verifyHostname(host("web01.example.test", nil), in))
	// A host that reports only its first label carries the same name.
	expectVerified(t, verifyHostname(host("web01", nil), in))
	expectMismatch(t, verifyHostname(host("web02.example.test", nil), in))
	expectUnreadable(t, verifyHostname(host("", errors.New("the name was not read")), in))
	expectUnreadable(t, verifyHostname(&hostReaders{}, in))
}

func TestVerifyingTheKernelSettings(t *testing.T) {
	in := verifyInput{
		action: opspec.ActionSysctlEnsure,
		payload: opspec.Payload{Kernel: &opspec.KernelPayload{Settings: map[string]string{
			"net.ipv4.ip_forward":         "1",
			"net.ipv4.conf.all.rp_filter": "1",
		}}},
	}
	host := func(values map[string]string, err error) *hostReaders {
		return &hostReaders{sysctl: func(key string) (string, error) {
			if err != nil {
				return "", err
			}
			// The host writes its values with whatever whitespace it likes.
			return " " + values[key] + "\t", nil
		}}
	}
	expectVerified(t, verifySysctl(host(map[string]string{
		"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "1",
	}, nil), in))
	expectMismatch(t, verifySysctl(host(map[string]string{
		"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.rp_filter": "1",
	}, nil), in))
	expectUnreadable(t, verifySysctl(host(nil, errors.New("/proc/sys is not there")), in))
	expectUnreadable(t, verifySysctl(&hostReaders{}, in))
}

func TestVerifyingAMountPoint(t *testing.T) {
	in := verifyInput{
		action: opspec.ActionMountEnsure,
		payload: opspec.Payload{Storage: &opspec.StoragePayload{
			Target: "/srv", Source: "UUID=6f0c", FSType: "ext4", Persist: true,
		}},
	}
	host := func(snapshot storage.Snapshot) *hostReaders {
		return &hostReaders{storage: func(context.Context) storage.Snapshot { return snapshot }}
	}

	mounted := storage.Snapshot{Mounts: []storage.Mount{{
		Target: "/srv", Source: "UUID=6f0c", FSType: "ext4", Mounted: true, InFstab: true,
	}}}
	expectVerified(t, verifyMountState(context.Background(), host(mounted), in))

	notMounted := storage.Snapshot{Mounts: []storage.Mount{{
		Target: "/srv", Source: "UUID=6f0c", FSType: "ext4", Mounted: false, InFstab: true,
	}}}
	expectMismatch(t, verifyMountState(context.Background(), host(notMounted), in))

	notInFstab := storage.Snapshot{Mounts: []storage.Mount{{
		Target: "/srv", Source: "UUID=6f0c", FSType: "ext4", Mounted: true, InFstab: false,
	}}}
	expectMismatch(t, verifyMountState(context.Background(), host(notInFstab), in))
	expectMismatch(t, verifyMountState(context.Background(), host(storage.Snapshot{}), in))

	expectUnreadable(t, verifyMountState(context.Background(),
		host(storage.Snapshot{UnavailableReason: "the disk space was not read"}), in))
}

func TestVerifyingALocalAccount(t *testing.T) {
	locked, unlocked := true, false
	in := verifyInput{
		action:  opspec.ActionLocalUserLock,
		payload: opspec.Payload{LocalUser: &opspec.LocalUserPayload{Name: "smith"}},
	}
	host := func(account *LocalAccount) *hostReaders {
		return &hostReaders{account: func(context.Context, string) *LocalAccount { return account }}
	}

	expectVerified(t, verifyLocalAccount(context.Background(),
		host(&LocalAccount{Name: "smith", Locked: &locked}), in))
	expectMismatch(t, verifyLocalAccount(context.Background(),
		host(&LocalAccount{Name: "smith", Locked: &unlocked}), in))
	// An account that is not there at all is a change that did not land.
	expectMismatch(t, verifyLocalAccount(context.Background(), host(nil), in))
	// A lock state nobody could read is unknown, not unlocked.
	expectUnreadable(t, verifyLocalAccount(context.Background(),
		host(&LocalAccount{Name: "smith", UnavailableReason: "helper_unavailable"}), in))
	expectUnreadable(t, verifyLocalAccount(context.Background(), &hostReaders{}, in))
}

func TestVerifyingTheDeletionOfAnAccount(t *testing.T) {
	in := verifyInput{
		action:  opspec.ActionLocalUserDelete,
		payload: opspec.Payload{LocalUser: &opspec.LocalUserPayload{Name: "smith"}},
	}
	gone := &hostReaders{account: func(context.Context, string) *LocalAccount { return nil }}
	there := &hostReaders{account: func(context.Context, string) *LocalAccount {
		return &LocalAccount{Name: "smith"}
	}}
	expectVerified(t, verifyLocalAccount(context.Background(), gone, in))
	expectMismatch(t, verifyLocalAccount(context.Background(), there, in))
}

func TestVerifyingTheServicesOfAProject(t *testing.T) {
	in := verifyInput{
		action: opspec.ActionComposeDeploy,
		payload: opspec.Payload{Compose: &opspec.ComposePayload{
			Project:      "shop",
			ImageDigests: map[string]string{"web": "sha256:9f86", "db": "sha256:1b4f"},
		}},
	}
	host := func(snapshot docker.Snapshot) *hostReaders {
		return &hostReaders{docker: func(context.Context) (docker.Snapshot, error) {
			return snapshot, nil
		}}
	}
	container := func(service, state, image string) docker.Container {
		return docker.Container{
			ID: "c-" + service, Name: "shop-" + service + "-1", Image: image,
			State: state, Compose: &docker.ComposeMembership{Project: "shop", Service: service},
		}
	}

	running := docker.Snapshot{Containers: []docker.Container{
		container("web", "running", "registry.test/web@sha256:9f86"),
		container("db", "running", "registry.test/db@sha256:1b4f"),
	}}
	expectVerified(t, verifyComposeServices(context.Background(), host(running), in))

	oneDown := docker.Snapshot{Containers: []docker.Container{
		container("web", "running", "registry.test/web@sha256:9f86"),
		container("db", "exited", "registry.test/db@sha256:1b4f"),
	}}
	expectMismatch(t, verifyComposeServices(context.Background(), host(oneDown), in))

	otherImage := docker.Snapshot{Containers: []docker.Container{
		container("web", "running", "registry.test/web@sha256:0000"),
		container("db", "running", "registry.test/db@sha256:1b4f"),
	}}
	expectMismatch(t, verifyComposeServices(context.Background(), host(otherImage), in))
	expectMismatch(t, verifyComposeServices(context.Background(), host(docker.Snapshot{}), in))

	unavailable := docker.Snapshot{Summary: docker.Summary{UnavailableReason: "no container engine"}}
	expectUnreadable(t, verifyComposeServices(context.Background(), host(unavailable), in))
	expectUnreadable(t, verifyComposeServices(context.Background(), &hostReaders{}, in))
}

func TestAnUnknownVerifierIsNeverASuccess(t *testing.T) {
	executor := &TaskExecutor{verifyReaders: &hostReaders{}}
	found := executor.observe(context.Background(), opspec.Verifier("something_new"), verifyInput{})
	expectUnreadable(t, found)
}
