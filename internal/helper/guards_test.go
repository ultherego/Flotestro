package helper

import (
	"context"
	"testing"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

func TestAGuardIsHeldByOneTaskAtATime(t *testing.T) {
	var g guards

	release, refusal := g.hold(GuardStorage, "task-1")
	if refusal != nil {
		t.Fatalf("a free guard was refused: %s", refusal.GetMessage())
	}

	// A second task in the same class is refused, not queued: the agent has
	// its own queue, and a collision here has to be visible right away.
	if _, refusal := g.hold(GuardStorage, "task-2"); refusal == nil {
		t.Fatal("a held guard was given out a second time")
	}
	// A different class is a different resource and does not wait.
	otherRelease, refusal := g.hold(GuardKernel, "task-3")
	if refusal != nil {
		t.Fatalf("a guard of another class was refused: %s", refusal.GetMessage())
	}
	otherRelease()

	release()
	// The release is idempotent, so a guard given back twice cannot take away
	// what the next task holds.
	release()
	again, refusal := g.hold(GuardStorage, "task-4")
	if refusal != nil {
		t.Fatalf("a released guard stayed held: %s", refusal.GetMessage())
	}
	release()
	if _, refusal := g.hold(GuardStorage, "task-5"); refusal == nil {
		t.Fatal("a stale release freed the guard of another task")
	}
	again()
}

func TestAnEmptyClassTakesNoGuard(t *testing.T) {
	// A read names no class. It must neither refuse nor block anything, so a
	// handler that decides the class per operation has one code path.
	var g guards
	release, refusal := g.hold(GuardFiles, "writer")
	if refusal != nil {
		t.Fatal(refusal.GetMessage())
	}
	defer release()

	readRelease, refusal := g.hold("", "reader")
	if refusal != nil {
		t.Fatalf("a read was refused: %s", refusal.GetMessage())
	}
	readRelease()
	if _, refusal := g.hold(GuardFiles, "another writer"); refusal == nil {
		t.Fatal("the release of a read freed the guard of the writer")
	}
}

func TestTheBusyRefusalNamesTheClassAndTheHolder(t *testing.T) {
	var g guards
	release, _ := g.hold(GuardNetwork, "task-7")
	defer release()

	_, refusal := g.hold(GuardNetwork, "task-8")
	if refusal == nil {
		t.Fatal("no refusal")
	}
	if refusal.GetAccepted() || refusal.GetErrorCode() != ErrorLocked || refusal.GetExitCode() != -1 {
		t.Fatalf("refusal = accepted %v, code %q, exit %d", refusal.GetAccepted(),
			refusal.GetErrorCode(), refusal.GetExitCode())
	}
	// The response has no field for the class, so the message is the contract:
	// the agent reads the class back with BusyResource.
	if class := BusyResource(refusal.GetMessage()); class != GuardNetwork {
		t.Fatalf("class read from %q = %q, expected %q", refusal.GetMessage(), class, GuardNetwork)
	}
	if want := "the resource network is busy with the task task-7"; refusal.GetMessage() != want {
		t.Fatalf("message = %q, expected %q", refusal.GetMessage(), want)
	}
}

func TestBusyResourceIgnoresOtherLockedMessages(t *testing.T) {
	// The lock of a package manager held by an administrator is also reported
	// as locked, but it names no class of the helper.
	for _, message := range []string{
		"", "the package manager is busy (/var/lib/dpkg/lock)", "resource units is busy",
	} {
		if class := BusyResource(message); class != "" {
			t.Errorf("%q gave the class %q", message, class)
		}
	}
	if class := BusyResource(rejectBusy(GuardUnits, "").GetMessage()); class != GuardUnits {
		t.Fatalf("a refusal without a holder gave the class %q", class)
	}
}

func TestTheHelperRefusesAHeldClassBeforeTouchingTheHost(t *testing.T) {
	// The refusal comes before systemctl runs, so the test needs no root and
	// no unit: the collision is decided on the guard alone.
	server := testServer()
	release, _ := server.guards.hold(GuardUnits, "task-earlier")
	defer release()

	response := server.handle(context.Background(), unitRequest("nginx.service", nil), nil)
	if response.GetAccepted() {
		t.Fatal("a unit operation ran next to another one")
	}
	if response.GetErrorCode() != ErrorLocked {
		t.Fatalf("code = %q, expected %q", response.GetErrorCode(), ErrorLocked)
	}
	if class := BusyResource(response.GetMessage()); class != GuardUnits {
		t.Fatalf("class = %q, expected %q", class, GuardUnits)
	}
}

func TestReadsAndPlansTakeNoGuard(t *testing.T) {
	// Two state reads can run side by side, also next to a mutation of the
	// same family. Only the mutations name a class.
	if class := storageGuard(helperv1.StorageRequest_OPERATION_READ_LVM); class != "" {
		t.Errorf("the LVM read takes %q", class)
	}
	if class := storageGuard(helperv1.StorageRequest_OPERATION_MOUNT_PLAN); class != "" {
		t.Errorf("the mount plan takes %q", class)
	}
	if class := storageGuard(helperv1.StorageRequest_OPERATION_DISK_WIPE); class != GuardStorage {
		t.Errorf("the disk wipe takes %q", class)
	}

	if class := fileGuard(helperv1.FileRequest_OPERATION_PLAN); class != "" {
		t.Errorf("the file plan takes %q", class)
	}
	if class := fileGuard(helperv1.FileRequest_OPERATION_ENSURE); class != GuardFiles {
		t.Errorf("the file write takes %q", class)
	}

	if class := kernelGuard(helperv1.KernelRequest_OPERATION_READ); class != "" {
		t.Errorf("the kernel read takes %q", class)
	}
	if class := kernelGuard(helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE); class != GuardKernel {
		t.Errorf("the sysctl write takes %q", class)
	}

	if class := timeGuard(helperv1.TimeRequest_OPERATION_PLAN); class != "" {
		t.Errorf("the time plan takes %q", class)
	}
	if class := timeGuard(helperv1.TimeRequest_OPERATION_TIMEZONE_SET); class != GuardTime {
		t.Errorf("the timezone change takes %q", class)
	}

	if class := securityGuard(helperv1.SecurityRequest_OPERATION_FACTS); class != "" {
		t.Errorf("the security facts take %q", class)
	}
	if class := securityGuard(helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD); class != GuardSecurity {
		t.Errorf("the audit reload takes %q", class)
	}

	if class := firewallGuard(helperv1.FirewallRequest_OPERATION_PLAN); class != "" {
		t.Errorf("the firewall plan takes %q", class)
	}
	if class := firewallGuard(helperv1.FirewallRequest_OPERATION_RESTORE); class != GuardNetwork {
		t.Errorf("the firewall restore takes %q", class)
	}
	if class := networkGuard(helperv1.NetworkRequest_OPERATION_READ); class != "" {
		t.Errorf("the network read takes %q", class)
	}
	if class := networkGuard(helperv1.NetworkRequest_OPERATION_CONFIRM); class != GuardNetwork {
		t.Errorf("the network confirmation takes %q", class)
	}

	if class := sshGuard(helperv1.SshRequest_OPERATION_PLAN); class != "" {
		t.Errorf("the sshd plan takes %q", class)
	}
	if class := sshGuard(helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY); class != GuardUnits {
		t.Errorf("the host key rotation takes %q", class)
	}

	if class := backupGuard(helperv1.BackupRequest_OPERATION_PLAN); class != "" {
		t.Errorf("the backup plan takes %q", class)
	}
	if class := backupGuard(helperv1.BackupRequest_OPERATION_RESTORE); class != GuardBackup {
		t.Errorf("the restore takes %q", class)
	}
}

func TestAnAuthoritativeCertificateFactsReadTakesTheGuard(t *testing.T) {
	// An ordinary facts read looks and takes nothing. An authoritative one
	// replaces the registry, so it is a write and must not run next to a
	// deployment that writes the registry as well.
	facts := &helperv1.CertificateRequest{Operation: helperv1.CertificateRequest_OPERATION_FACTS}
	if class := certificateGuard(facts); class != "" {
		t.Errorf("an ordinary facts read takes %q", class)
	}
	facts.Authoritative = true
	if class := certificateGuard(facts); class != GuardCertificates {
		t.Errorf("an authoritative facts read takes %q", class)
	}
	plan := &helperv1.CertificateRequest{Operation: helperv1.CertificateRequest_OPERATION_TRUST_PLAN}
	if class := certificateGuard(plan); class != "" {
		t.Errorf("the trust plan takes %q", class)
	}
	deploy := &helperv1.CertificateRequest{Operation: helperv1.CertificateRequest_OPERATION_DEPLOY}
	if class := certificateGuard(deploy); class != GuardCertificates {
		t.Errorf("the deployment takes %q", class)
	}
}

func TestTheTimeLimitStaysWithinTheCapOfTheFamily(t *testing.T) {
	cases := []struct {
		name    string
		seconds uint32
		want    time.Duration
	}{
		// An order without a limit gets the fallback of the family.
		{"no limit", 0, 5 * time.Minute},
		{"within the cap", 90, 90 * time.Second},
		// An order asking for more than the family allows gets the cap: a
		// hung tool must not hold the guard longer than that.
		{"over the cap", 7200, 30 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := &helperv1.HelperRequest{TimeoutSeconds: tc.seconds}
			if got := timeLimit(request, 5*time.Minute, 30*time.Minute); got != tc.want {
				t.Fatalf("limit = %s, expected %s", got, tc.want)
			}
		})
	}
}

func TestTheDeadlineBindsTheContext(t *testing.T) {
	request := &helperv1.HelperRequest{TimeoutSeconds: 1}
	ctx, cancel := deadline(context.Background(), request, time.Minute, time.Hour)
	defer cancel()
	until, set := ctx.Deadline()
	if !set {
		t.Fatal("the context has no deadline")
	}
	if remaining := time.Until(until); remaining > time.Second || remaining < 0 {
		t.Fatalf("the deadline is %s away, expected about a second", remaining)
	}
}
