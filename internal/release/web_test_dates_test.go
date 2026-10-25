package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A panel test must not depend on the day it is run on.
//
// The screens print how long ago a fixture was, and the fixtures carry fixed dates.
// On 25.10 a group written on 15.10 read "10d ago", and a test that asked the whole
// row for the digit 0 - to prove that an unknown size is not shown as nought - failed
// the gate on a day nothing had changed. A global clock for the tests was tried and
// broke nine others, so the rule is smaller: a test does not ask an element for a
// single digit as a substring unless the element is one that prints no age.
//
// An element that is a tile or a summary cell is one of those, and says so by its
// name; anything else is asked for the text "0" as the whole text of a cell
// (queryByText), which "10d ago" is not.
var digitNotSubstring = regexp.MustCompile(`not\.toHaveTextContent\("[0-9]"\)`)

// printsNoAge are the receivers of such a line that are known to hold a figure and
// nothing else: the tiles (kpi-, tile, fl-kpi-value), a fact of a card (fl-fact), a
// summary cell, the count on the bell and the counts of the unresolved and the findings.
// A line that only continues the one above it is read together with that one.
var printsNoAge = regexp.MustCompile(`kpi-|\btile\b|fl-kpi-value|fl-fact|\bsummary\b|\bhosts\b|\bunreadable\b|\bfindings\b|"bell"`)

func TestNoPanelTestAsksAnElementWithAnAgeForADigit(t *testing.T) {
	root := repositoryRoot(t)
	var offenders []string
	checked := 0
	err := filepath.Walk(filepath.Join(root, "web", "src"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".test.tsx") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for number, line := range lines {
			if !digitNotSubstring.MatchString(line) {
				continue
			}
			checked++
			receiver := line
			if number > 0 && strings.HasPrefix(strings.TrimSpace(line), ".not") {
				receiver = lines[number-1] + line
			}
			if !printsNoAge.MatchString(receiver) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel+":"+strconv.Itoa(number+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no such assertion was found in the panel tests, so this guard looked at nothing")
	}
	for _, offender := range offenders {
		t.Errorf("a digit asked of an element that may print how long ago something was (it passes "+
			"until the calendar reaches a day with that digit in it); ask the cell for the text with "+
			"within(...).queryByText: %s", offender)
	}
}
