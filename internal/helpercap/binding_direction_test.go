package helpercap

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Enabling and disabling a unit are one action, and so are masking and
// unmasking: the direction travels in the operation. A capability approved to
// start a unit at boot authorised keeping it from starting, on the same
// signature and the same unit name.
func TestTheCapabilityBindsWhichWayAUnitIsToggled(t *testing.T) {
	toggle := func(operation helperv1.UnitActionRequest_Operation) *helperv1.HelperRequest {
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_UnitAction{
			UnitAction: &helperv1.UnitActionRequest{Operation: operation, Unit: "nginx.service"},
		}}
	}
	approved := func(on bool) *BoundPayload {
		return &BoundPayload{Payload: opspec.Payload{
			UnitToggle: &opspec.UnitToggle{Unit: "nginx.service", Enabled: on}}}
	}
	for _, test := range []struct {
		name      string
		request   helperv1.UnitActionRequest_Operation
		signedFor bool
		refuse    bool
	}{
		{"enable under an approval to enable", helperv1.UnitActionRequest_OPERATION_ENABLE, true, false},
		{"disable under an approval to enable", helperv1.UnitActionRequest_OPERATION_DISABLE, true, true},
		{"disable under an approval to disable", helperv1.UnitActionRequest_OPERATION_DISABLE, false, false},
		{"enable under an approval to disable", helperv1.UnitActionRequest_OPERATION_ENABLE, false, true},
		{"mask under an approval to mask", helperv1.UnitActionRequest_OPERATION_MASK, true, false},
		{"mask under an approval to unmask", helperv1.UnitActionRequest_OPERATION_MASK, false, true},
		{"unmask under an approval to mask", helperv1.UnitActionRequest_OPERATION_UNMASK, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := CheckBinding(toggle(test.request), approved(test.signedFor))
			if test.refuse && err == nil {
				t.Error("the request was carried out under a capability for the other direction")
			}
			if !test.refuse && err != nil {
				t.Errorf("the request the capability was signed for was refused: %v", err)
			}
		})
	}
	// A toggle whose payload says nothing about a unit is not a toggle anybody
	// approved.
	if err := CheckBinding(toggle(helperv1.UnitActionRequest_OPERATION_ENABLE),
		&BoundPayload{Payload: opspec.Payload{Unit: &opspec.UnitPayload{Unit: "nginx.service"}}}); err == nil {
		t.Error("a toggle passed under a payload that describes no toggle")
	}
}

// A capability for one disk must not reach another, and the device path is not
// an identity: every field of a storage order is compared, because the agent
// builds the request out of the payload field for field.
func TestTheCapabilityBindsEveryFieldOfAStorageOrder(t *testing.T) {
	mount := func(change func(*helperv1.StorageRequest)) *helperv1.HelperRequest {
		request := &helperv1.StorageRequest{
			Operation: helperv1.StorageRequest_OPERATION_MOUNT_ENSURE,
			Source:    "UUID=1111", Target: "/srv/data", FsType: "ext4",
			Options: "defaults", Persist: true,
		}
		change(request)
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Storage{Storage: request}}
	}
	bound := &BoundPayload{Payload: opspec.Payload{Storage: &opspec.StoragePayload{
		Source: "UUID=1111", Target: "/srv/data", FSType: "ext4", Options: "defaults", Persist: true}}}

	if err := CheckBinding(mount(func(*helperv1.StorageRequest) {}), bound); err != nil {
		t.Fatalf("the mount the capability was signed for was refused: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*helperv1.StorageRequest)
	}{
		{"another filesystem", func(r *helperv1.StorageRequest) { r.Source = "UUID=2222" }},
		{"another place", func(r *helperv1.StorageRequest) { r.Target = "/etc" }},
		{"another type", func(r *helperv1.StorageRequest) { r.FsType = "xfs" }},
		{"other options", func(r *helperv1.StorageRequest) { r.Options = "rw,exec,suid" }},
		{"not written to fstab after all", func(r *helperv1.StorageRequest) { r.Persist = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckBinding(mount(test.change), bound); err == nil {
				t.Error("the changed order was accepted under the same capability")
			}
		})
	}

	// The layers above a bare disk name themselves by identity, not by path.
	extend := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Storage{
		Storage: &helperv1.StorageRequest{
			Operation: helperv1.StorageRequest_OPERATION_LVM_EXTEND,
			Group:     "data", Volume: "logs", Size: "+10G",
			ExpectedVolumeUuid: "aaaa-bbbb",
		}}}
	volume := &BoundPayload{Payload: opspec.Payload{Storage: &opspec.StoragePayload{
		Group: "data", Volume: "logs", Size: "+10G", ExpectedVolumeUUID: "aaaa-bbbb"}}}
	if err := CheckBinding(extend, volume); err != nil {
		t.Fatalf("the volume the capability named was refused: %v", err)
	}
	other := &BoundPayload{Payload: opspec.Payload{Storage: &opspec.StoragePayload{
		Group: "data", Volume: "database", Size: "+10G", ExpectedVolumeUUID: "cccc-dddd"}}}
	if err := CheckBinding(extend, other); err == nil {
		t.Error("a capability for one logical volume extended another")
	}
	// A storage order under a payload that describes no storage at all.
	if err := CheckBinding(extend, &BoundPayload{}); err == nil {
		t.Error("a storage order passed under a payload that describes no storage")
	}
	// A read takes no capability and has nothing to compare.
	read := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Storage{
		Storage: &helperv1.StorageRequest{Operation: helperv1.StorageRequest_OPERATION_READ_LVM}}}
	if err := CheckBinding(read, &BoundPayload{}); err != nil {
		t.Errorf("a read was refused: %v", err)
	}
}

// The trust store decides which panel this host believes, and a renewal decides
// which certificate is replaced. Neither had a rule.
func TestTheCapabilityBindsARenewalAndATrustChange(t *testing.T) {
	trust := func(anchor string) *helperv1.HelperRequest {
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Certificate{
			Certificate: &helperv1.CertificateRequest{
				Operation: helperv1.CertificateRequest_OPERATION_TRUST_REMOVE, AnchorId: anchor,
			}}}
	}
	bound := &BoundPayload{Payload: opspec.Payload{
		Certificate: &opspec.CertificatePayload{AnchorID: "panel-2026"}}}
	if err := CheckBinding(trust("panel-2026"), bound); err != nil {
		t.Fatalf("the anchor the capability named was refused: %v", err)
	}
	if err := CheckBinding(trust("panel-2025"), bound); err == nil {
		t.Error("a capability for one trust anchor removed another")
	}

	renew := func(request string) *helperv1.HelperRequest {
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Certificate{
			Certificate: &helperv1.CertificateRequest{
				Operation: helperv1.CertificateRequest_OPERATION_RENEW, Request: request,
			}}}
	}
	one := &BoundPayload{Payload: opspec.Payload{
		Certificate: &opspec.CertificatePayload{Request: "20260927000000"}}}
	if err := CheckBinding(renew("20260927000000"), one); err != nil {
		t.Fatalf("the renewal the capability named was refused: %v", err)
	}
	if err := CheckBinding(renew("20260101000000"), one); err == nil {
		t.Error("a capability for one renewal renewed another certificate")
	}
}

// A reload of the audit rules and a change of the protection mode are two
// different changes; the reload had no rule, so one signature did both.
func TestTheCapabilityForAnAuditReloadIsNotOneForTheProtectionMode(t *testing.T) {
	reload := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Security{
		Security: &helperv1.SecurityRequest{Operation: helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD}}}
	if err := CheckBinding(reload, &BoundPayload{}); err != nil {
		t.Fatalf("a reload under a capability for a reload was refused: %v", err)
	}
	mode := &BoundPayload{Payload: opspec.Payload{Security: &opspec.SecurityPayload{Mode: "permissive"}}}
	if err := CheckBinding(reload, mode); err == nil {
		t.Error("a capability signed for the protection mode reloaded the audit rules")
	}
}
