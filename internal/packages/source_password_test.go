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
