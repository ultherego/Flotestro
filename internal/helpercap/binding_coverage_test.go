package helpercap

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A capability names one operation on one target, and a rule comparing the
// request with the payload it binds is what keeps it from authorising every
// other operation of that kind. This walks the whole request union so that a
// kind added later cannot arrive without that decision: without a rule the
// helper refuses, and this test names what is missing before a fleet does.
func TestEveryMutatingRequestIsComparedWithTheBoundPayload(t *testing.T) {
	reflected := (&helperv1.HelperRequest{}).ProtoReflect()
	union := reflected.Descriptor().Oneofs().ByName("action")
	if union == nil {
		t.Fatal("the helper request carries no action union")
	}
	for i := 0; i < union.Fields().Len(); i++ {
		field := union.Fields().Get(i)
		request := &helperv1.HelperRequest{}
		message := request.ProtoReflect()
		message.Set(field, message.NewField(field))
		expectation := Expect(request)
		if !expectation.Mutating {
			continue
		}
		if CodeOf(CheckBinding(request, &BoundPayload{}, nil)) == ErrorPayloadUnchecked {
			t.Errorf("%T (%s) changes the host and nothing compares it with the bound payload",
				request.GetAction(), expectation.Kind)
		}
	}
}

// The default is a refusal. A request the helper holds no rule for is not
// carried out on the strength of a signature alone.
func TestARequestNothingComparesIsRefused(t *testing.T) {
	code := CodeOf(CheckBinding(&helperv1.HelperRequest{}, &BoundPayload{}, nil))
	if code != ErrorPayloadUnchecked {
		t.Fatalf("a request nothing compares was answered with %q, expected %q",
			code, ErrorPayloadUnchecked)
	}
}

// The rollback of an unverified sysctl change sends the host's previous
// readings under the capability of the order that made it, and that is why the
// rule used to bind the keys and not their values - so a signed consent to set
// dmesg_restrict to 1 could be carried out as 0. The values are compared now,
// and the only other set this capability authorizes is the one the helper
// itself read before the change (audit of 6c38561, CR-09).
func TestTheSysctlRollbackIsTheHelpersOwnReadingAndNothingElse(t *testing.T) {
	ordered := map[string]string{"net.ipv4.ip_forward": "1", "kernel.dmesg_restrict": "1"}
	bound := &BoundPayload{Payload: opspec.Payload{Kernel: &opspec.KernelPayload{Settings: ordered}}}
	request := func(settings map[string]string) *helperv1.HelperRequest {
		return &helperv1.HelperRequest{
			TaskId: "task-1",
			Action: &helperv1.HelperRequest_Kernel{Kernel: &helperv1.KernelRequest{
				Operation: helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE,
				Settings:  settings,
			}}}
	}
	// What the helper wrote down before it applied the change.
	before := PriorSysctl(func(string) map[string]string {
		return map[string]string{"net.ipv4.ip_forward": "0", "kernel.dmesg_restrict": "0"}
	})

	// The change itself passes.
	if err := CheckBinding(request(ordered), bound, before); err != nil {
		t.Fatalf("the change the panel ordered was refused: %v", err)
	}
	// So does the rollback, and a rollback of a subset: the baseline drops the
	// keys the unprivileged agent could not read.
	if err := CheckBinding(request(map[string]string{"net.ipv4.ip_forward": "0"}), bound, before); err != nil {
		t.Fatalf("the rollback of a change the panel ordered was refused: %v", err)
	}

	// A third value is neither the change nor its rollback.
	if err := CheckBinding(request(map[string]string{"net.ipv4.ip_forward": "2"}), bound, before); err == nil {
		t.Error("a value that is neither the order nor the previous state was accepted")
	}
	// Without a record there is nothing to say those values were ever there,
	// so only the order is authorized. This is the hole as it was: 0 under a
	// capability that says 1.
	if err := CheckBinding(request(map[string]string{"kernel.dmesg_restrict": "0"}), bound, nil); err == nil {
		t.Error("a value the panel never signed was accepted with no record of the previous state")
	}
	// Half back and half forward is neither operation.
	mixed := map[string]string{"net.ipv4.ip_forward": "1", "kernel.dmesg_restrict": "0"}
	if err := CheckBinding(request(mixed), bound, before); err == nil {
		t.Error("a request that sets one key and puts another back was accepted")
	}
	// A key the order never named is another change under the same capability.
	if err := CheckBinding(request(map[string]string{"kernel.modules_disabled": "0"}), bound, before); err == nil {
		t.Error("a kernel setting the order never named was accepted")
	}
}

// A firewall capability named one zone and one set of ports, and said nothing
// about which: the same signature opened any port of that zone.
func TestTheCapabilityBindsWhatAFirewallOrderWouldOpen(t *testing.T) {
	approved := &opspec.FirewallPayload{Zone: "public", Protocol: "tcp",
		Ports: []string{"443"}, Enable: true}
	bound := &BoundPayload{Payload: opspec.Payload{Firewall: approved}}
	zoneRequest := func(change func(*helperv1.FirewallRequest)) *helperv1.HelperRequest {
		request := &helperv1.FirewallRequest{
			Operation: helperv1.FirewallRequest_OPERATION_ZONE_PORT,
			Zone:      approved.Zone, Protocol: approved.Protocol,
			Ports: []string{"443"}, Enable: true,
			// The agent's own knowledge of the channel it answers on.
			ManagementAddress: "10.0.0.2", ManagementPort: 8443,
		}
		change(request)
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Firewall{Firewall: request}}
	}
	if err := CheckBinding(zoneRequest(func(*helperv1.FirewallRequest) {}), bound, nil); err != nil {
		t.Fatalf("the change the panel approved was refused: %v", err)
	}
	if err := CheckBinding(zoneRequest(func(r *helperv1.FirewallRequest) {
		r.Ports = []string{"22"}
	}), bound, nil); err == nil {
		t.Error("another port of the approved zone was accepted")
	}
	if err := CheckBinding(zoneRequest(func(r *helperv1.FirewallRequest) {
		r.Zone = "trusted"
	}), bound, nil); err == nil {
		t.Error("another zone was accepted")
	}
	if err := CheckBinding(zoneRequest(func(r *helperv1.FirewallRequest) {
		r.BreakGlass = true
	}), bound, nil); err == nil {
		t.Error("stepping over the protection of the management channel was accepted")
	}
}

// A container capability named the container and not what would happen to its
// volumes: the same signature took the data with it.
func TestTheCapabilityBindsWhatBecomesOfTheContainersVolumes(t *testing.T) {
	approved := &opspec.DockerContainerPayload{ContainerID: "9f2c1ab4de77", TimeoutSeconds: 10}
	bound := &BoundPayload{Payload: opspec.Payload{DockerContainer: approved}}
	removal := func(change func(*helperv1.DockerActionRequest)) *helperv1.HelperRequest {
		request := &helperv1.DockerActionRequest{
			Operation:   helperv1.DockerActionRequest_OPERATION_REMOVE,
			ContainerId: approved.ContainerID, TimeoutSeconds: approved.TimeoutSeconds,
		}
		change(request)
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_DockerAction{DockerAction: request}}
	}
	if err := CheckBinding(removal(func(*helperv1.DockerActionRequest) {}), bound, nil); err != nil {
		t.Fatalf("the removal the panel approved was refused: %v", err)
	}
	if err := CheckBinding(removal(func(r *helperv1.DockerActionRequest) {
		r.RemoveVolumes = true
	}), bound, nil); err == nil {
		t.Error("taking the volumes with the container was accepted")
	}
	if err := CheckBinding(removal(func(r *helperv1.DockerActionRequest) {
		r.ContainerId = "0011223344ff"
	}), bound, nil); err == nil {
		t.Error("another container was accepted")
	}
}
