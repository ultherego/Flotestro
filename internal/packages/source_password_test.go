package packages

import (
	"strings"
	"testing"
)

// The password of a source is interpolated into the description of it and was
// never checked: Validate looks at the address and the user name, and it never
// sees this value, because the panel does not read the secret - only the host
// does, right before the write.
//
// A line break in it is not a password but another section of the file: for DNF
// a second repository with gpgcheck off, for APT another machine line in the
// netrc. Whoever may write a secret would otherwise gain "add an unsigned
// source to every host that uses this one".
func TestAPasswordWithALineBreakIsRefused(t *testing.T) {
	repo := Repository{
		ID: "lab", Name: "lab", URL: "https://packages.example/lab",
		Suites: []string{"stable"}, Components: []string{"main"},
		Username: "reader", Signed: true,
	}
	for _, name := range []string{"apt", "dnf"} {
		for _, password := range []string{
			"x\n[evil]\nbaseurl=http://nowhere/\ngpgcheck=0\nenabled=1",
			"x\rmachine evil login root password root",
			"x\n",
			"x\x00y",
		} {
			if _, err := SourceFiles(repo, name, "", []byte(password)); err == nil {
				t.Errorf("%s accepted a password carrying %q", name, strings.TrimSpace(password))
			}
		}
	}
}

// The apt credentials file is a run of whitespace-separated tokens, so a space
// or a tab in the password ends that token and the rest of the value is read as
// further keywords. The check for a line break let this through, and the
// resulting file names a second host whose credentials the operator never
// entered (audit of 6c38561, PKG-03).
func TestAnAPTPasswordThatIsNotOneTokenIsRefused(t *testing.T) {
	repo := Repository{
		ID: "lab", Name: "lab", URL: "https://packages.example/lab",
		Suites: []string{"stable"}, Components: []string{"main"},
		Username: "reader", Signed: true,
	}
	for _, password := range []string{
		"x machine evil.example login attacker password y",
		"x\tmachine evil.example login attacker password y",
		"x\vy",
		"x\fy",
		"trailing ",
	} {
		files, err := SourceFiles(repo, "apt", "", []byte(password))
		if err == nil {
			t.Errorf("apt accepted a password of several tokens: %q -> %+v", password, files)
		}
	}
	// A password cannot be refused for a format that holds it: DNF reads its
	// ini value to the end of the line, so a space there is one character.
	if _, err := SourceFiles(repo, "dnf", "", []byte("x machine evil.example login attacker")); err != nil {
		t.Errorf("dnf refused a password its own format carries: %v", err)
	}
}

// The user name stands in the same token run, and on an ini line of its own,
// so the separators of both formats are forbidden in it.
func TestAUserNameCarryingASeparatorIsRefused(t *testing.T) {
	for _, name := range []string{"reader root", "reader\troot", "reader\rx", "reader\nx", "reader\x00x", "a:b"} {
		repo := Repository{
			ID: "lab", Name: "lab", URL: "https://packages.example/lab",
			Suites: []string{"stable"}, Components: []string{"main"},
			Username: name, Signed: true,
		}
		if err := ValidateRepository(repo, "apt", true); err == nil {
			t.Errorf("the user name %q was accepted", name)
		}
	}
}

// A password that is a password still goes through, on both managers.
func TestAPasswordWithoutALineBreakIsWritten(t *testing.T) {
	repo := Repository{
		ID: "lab", Name: "lab", URL: "https://packages.example/lab",
		Suites: []string{"stable"}, Components: []string{"main"},
		Username: "reader", Signed: true,
	}
	for _, name := range []string{"apt", "dnf"} {
		files, err := SourceFiles(repo, name, "", []byte("a-real-password"))
		if err != nil {
			t.Fatalf("%s refused an ordinary password: %v", name, err)
		}
		var carried bool
		for _, file := range files {
			if strings.Contains(string(file.Content), "a-real-password") {
				carried = true
			}
		}
		if !carried {
			t.Errorf("%s wrote no file carrying the password", name)
		}
	}
}
