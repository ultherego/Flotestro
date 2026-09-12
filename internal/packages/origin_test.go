package packages

import "testing"

// TestPolicyRecognisesTheOrigin guards the rule the coverage of the
// vulnerability assessment rests on for the APT family.
//
// dpkg does not record the vendor with the package - only APT knows it from
// the package lists. Without that a package from a foreign repository would
// look like a package of the distribution and would count as covered by its
// findings, although the vendor has nothing to say about it.
func TestPolicyRecognisesTheOrigin(t *testing.T) {
	output := `openssl:
  Installed: 3.0.15-1~deb12u1
  Candidate: 3.0.15-1~deb12u1
  Version table:
 *** 3.0.15-1~deb12u1 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
        100 /var/lib/dpkg/status
     3.0.11-1~deb12u2 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
nginx:
  Installed: 1.27.0-1~bookworm
  Candidate: 1.27.0-1~bookworm
  Version table:
 *** 1.27.0-1~bookworm 500
        500 http://nginx.org/packages/debian bookworm/nginx amd64 Packages
        100 /var/lib/dpkg/status
own-agent:
  Installed: 0.9.1
  Candidate: 0.9.1
  Version table:
 *** 0.9.1 100
        100 /var/lib/dpkg/status
linux-image-6.12.43+deb13-amd64:
  Installed: 6.12.43-1
  Candidate: 6.12.43-1
  Version table:
 *** 6.12.43-1 100
        100 /var/lib/dpkg/status
linux-image-amd64:
  Installed: 6.12.43-1
  Candidate: 6.12.48-1
  Version table:
     6.12.48-1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
 *** 6.12.43-1 100
        100 /var/lib/dpkg/status
absent:
  Installed: (none)
  Candidate: 1.0-1
  Version table:
     1.0-1 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
`
	result := ParseAPTPolicy(output)

	expected := map[string]OriginEntry{
		"openssl":   {Origin: "http://deb.debian.org/debian", Class: OriginDistribution},
		"nginx":     {Origin: "http://nginx.org/packages/debian", Class: OriginThirdParty},
		"own-agent": {Origin: "/var/lib/dpkg/status", Class: OriginLocal},
		// A version withdrawn from a repository looks in policy exactly like a
		// package built locally - and it is an old kernel lying on disk after
		// an upgrade. Pushed outside the coverage it would hide exactly the
		// vulnerabilities that most need to be seen.
		"linux-image-amd64": {Origin: "http://deb.debian.org/debian",
			Class: OriginDistribution},
	}
	for name, want := range expected {
		if result[name] != want {
			t.Errorf("%s: origin = %+v, expected %+v", name, result[name], want)
		}
	}
	// A package that is not installed has no installed version, so it has no
	// origin either - and must not get one from the line of somebody else's
	// version.
	if _, ok := result["absent"]; ok {
		t.Errorf("a package that is not installed got an origin: %+v", result["absent"])
	}
	// A package none of whose versions is in the repositories any more stays
	// local: there is nothing to tell where it came from.
	versioned := result["linux-image-6.12.43+deb13-amd64"]
	if versioned.Class != OriginLocal {
		t.Errorf("a package without a single source = %+v", versioned)
	}
}

// TestAMissingOriginIsUnknown guards that an origin that was not read stays
// unknown rather than becoming a package of the distribution.
func TestAMissingOriginIsUnknown(t *testing.T) {
	if entry := APTSourceClass(""); entry.Class != OriginUnknown {
		t.Errorf("an empty source line = %+v", entry)
	}
	if entry := APTSourceClass("500 http://ppa.example.net/x ./ Packages"); entry.Class != OriginThirdParty {
		t.Errorf("a foreign repository = %+v", entry)
	}
}
