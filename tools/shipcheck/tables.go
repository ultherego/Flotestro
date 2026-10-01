package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A browser decides for itself whether a <table> carries data or only arranges a
// layout, and a short table whose headers declare nothing is taken for layout:
// its <th> then stop being column headers in the accessibility tree, and a
// screen reader reads each cell without saying which column it is in. Measured
// on the tags page of a running panel - five headers in the markup, zero column
// headers exposed - and the same five came back the moment they said scope.
//
// The panel had 265 headers and not one scope. The sweep that fixed them is
// worth nothing by itself: the next table written without scope would be the
// same defect again, and the only thing that caught the first one was a browser
// test on a page that happened to be short that day.
const panelSource = "web/src"

var (
	tableHeadOpen  = regexp.MustCompile(`<thead[\s>]`)
	tableHeadClose = regexp.MustCompile(`</thead>`)
	// <th> or <th className=...>, but not <thead> and not one that already says
	// scope. The attribute may sit anywhere inside the tag.
	headerCell = regexp.MustCompile(`<th(?:\s[^>]*)?/?>|<th>`)
)

// tableHeadersDeclareScope reads the panel's sources and reports every column
// header inside a <thead> that does not say which direction it heads.
func tableHeadersDeclareScope(root string) ([]finding, error) {
	var findings []finding
	dir := filepath.Join(root, panelSource)

	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		// Tests draw tables of their own to check components with; what ships is
		// what the pages render.
		if strings.HasSuffix(path, ".test.tsx") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		where, err := filepath.Rel(root, path)
		if err != nil {
			where = path
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		depth, line := 0, 0
		for scanner.Scan() {
			line++
			text := scanner.Text()
			opens := len(tableHeadOpen.FindAllString(text, -1))
			// A header row handed to a component as a property is still a header
			// row: it is written as head={<tr><th>…</th></tr>} and never appears
			// between a <thead> and its close.
			inProperty := strings.Contains(text, "head={<tr>")
			if depth > 0 || opens > 0 || inProperty {
				for _, cell := range headerCell.FindAllString(text, -1) {
					if strings.Contains(cell, "scope=") {
						continue
					}
					findings = append(findings, finding{
						place: fmt.Sprintf("%s:%d", where, line),
						said:  "a column header without scope: " + strings.TrimSpace(cell),
					})
				}
			}
			depth += opens
			depth -= len(tableHeadClose.FindAllString(text, -1))
			if depth < 0 {
				depth = 0
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}
