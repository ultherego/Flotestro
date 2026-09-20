package packages

import "testing"

// An upgrade that resolves a conflict by dropping a package is a removal the
// operator has to see: the Remv line used to be read only after an Inst line
// matched, which no Remv line ever does, so no upgrade plan ever had one.
func TestTheSimulationReadsWhatItWouldRemoveAsWellAsWhatItInstalls(t *testing.T) {
	const output = `Reading package lists...
Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable [amd64])
Remv libfoo-old [1.2-3]
Inst curl [7.88.1-10] (7.88.1-10+deb12u5 Debian:12.5/stable [amd64])
Conf libssl3 (3.0.11-1~deb12u2 Debian-Security:12/stable [amd64])
`
	changes, removals := parseAptSimulation(output)
	if len(changes) != 2 || changes[0].Name != "libssl3" || changes[1].Name != "curl" {
		t.Fatalf("the installs read as %+v", changes)
	}
	if len(removals) != 1 || removals[0] != "libfoo-old" {
		t.Fatalf("the removals read as %v", removals)
	}
	if !changes[0].Security || changes[1].Security {
		t.Errorf("the security origin was not read: %+v", changes)
	}
	// The removals are what the protected check is asked about; an upgrade
	// used to hand it an empty list whatever it was about to drop.
	if len(ProtectedInSet(removals)) != 0 {
		t.Errorf("an ordinary package was taken for a protected one")
	}
}

// A plan whose removal is a package the host cannot lose is stopped before
// the transaction, and that only works when the removals are read at all.
func TestAProtectedRemovalIsSeenInASimulation(t *testing.T) {
	_, removals := parseAptSimulation("Remv systemd [252-1]\nInst bash [5.2] (5.3 Debian:12/stable [amd64])\n")
	if protected := ProtectedInSet(removals); len(protected) != 1 || protected[0] != "systemd" {
		t.Fatalf("systemd was not recognised as protected: %v", protected)
	}
}
