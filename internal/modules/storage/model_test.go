package storage

import "testing"

// Every layer asks this one question, so this one function answers it: a device
// is named by a path or by a durable identifier, and ValidateSource takes all of
// them wherever a device is named. It did not: the mount plans resolved the
// forms, the device plans compared paths, the helper's apply had a third rule
// and the verifier after a change had a fourth - so one order by label planned
// on one host, was refused on another and, once that was fixed, was reported as
// a change that had not happened (audit of 6c38561, WŁ-13, and the two
// regressions of its fix).
func TestADeviceIsFoundByEveryNameAnOrderMayUse(t *testing.T) {
	snapshot := Snapshot{Devices: []Device{
		{Path: "/dev/sdb", FSType: "ext4", UUID: "7C9E-4F1A", Label: "spare", PartUUID: "abcd-01"},
		{Path: "/dev/sdc", FSType: "xfs", UUID: "0000-0000", Label: "other"},
	}}
	for _, named := range []string{
		"/dev/sdb", "UUID=7C9E-4F1A", "uuid-is-case-insensitive", "LABEL=spare", "PARTUUID=abcd-01",
	} {
		source := named
		if named == "uuid-is-case-insensitive" {
			// A UUID is hexadecimal and blkid prints it in either case; fstab
			// of one distribution carries one, the panel's order the other.
			source = "UUID=7c9e-4f1a"
		}
		found := snapshot.DeviceAt(source)
		if found == nil || found.Path != "/dev/sdb" {
			t.Errorf("%s resolved to %+v", source, found)
		}
		// SourceDevice is the same question under the name the mount plans use.
		if snapshot.SourceDevice(source) != snapshot.DeviceAt(source) {
			t.Errorf("%s resolves differently through SourceDevice", source)
		}
	}
	// A label nothing carries is not a device, and an empty label does not
	// match a device without one.
	for _, named := range []string{"LABEL=nowhere", "LABEL=", "UUID=", "/dev/sdz"} {
		if found := snapshot.DeviceAt(named); found != nil {
			t.Errorf("%s resolved to %s", named, found.Path)
		}
	}
}
