package authz_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// PrincipalBySubject returns a principal together with ErrGroupsUnavailable
// when the directory could not say which groups the identity is in. Both go
// back on purpose: a group can add a right and never take one away, so a
// caller whose operation is already carried by a hand-granted binding has no
// question left to answer.
//
// The cost of that shape is that a caller which discards the error still gets a
// usable principal - with the narrow side of the rights, silently. That is the
// opposite of the rule this change exists to serve, which is that an
// unanswered question pauses the work instead of narrowing it. The compiler
// says nothing about a discarded error, so this does.
func TestNoCallerOfPrincipalBySubjectDiscardsTheGroupAnswer(t *testing.T) {
	discarded := regexp.MustCompile(`, +_ +:?= +[\w.]*PrincipalBySubject\(`)
	root := filepath.Join("..", "..")
	var offences []string
	checked := 0
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, tree), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.Contains(string(content), "PrincipalBySubject(") {
				return nil
			}
			checked++
			for number, line := range strings.Split(string(content), "\n") {
				if discarded.MatchString(line) {
					offences = append(offences, filepath.ToSlash(path)+":"+itoa(number+1)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", tree, err)
		}
	}
	if checked == 0 {
		t.Fatal("no file names PrincipalBySubject; this check read nothing")
	}
	for _, offence := range offences {
		t.Errorf("the group answer is discarded, so the work would run on narrowed rights: %s", offence)
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
