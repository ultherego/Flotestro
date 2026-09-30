package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The site is hand-written HTML copied to the publishing branch with no build
// step, so nothing at all stands between an English page added alone and that
// page being published. The panel has the same rule and a test of its own
// (web/src/i18n/i18n.test.ts); the site had neither.
const (
	siteRoot     = "docs/site"
	polishPrefix = "pl/"
)

// siteLanguages compares the English pages of the site with the Polish ones in
// both directions.
func siteLanguages(root string) ([]finding, error) {
	site := filepath.Join(root, siteRoot)
	english := map[string]bool{}
	polish := map[string]bool{}
	var findings []finding

	err := filepath.WalkDir(site, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(site, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !translatablePage(relative) {
			return nil
		}
		if after, ok := strings.CutPrefix(relative, polishPrefix); ok {
			// A second language directory inside pl/ would make every page
			// under it look like an English page whose name begins with a
			// language code, and the comparison below would ask for a
			// translation of a translation.
			if strings.HasPrefix(after, polishPrefix) {
				findings = append(findings, finding{
					place: siteRoot + "/" + relative,
					said:  "sits under a second " + polishPrefix + " directory, which the language mapping cannot read",
				})
				return nil
			}
			polish[after] = true
			return nil
		}
		english[relative] = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", siteRoot, err)
	}

	// Nothing read is not agreement. A move of the site, or an extension
	// nobody taught this check about, must fail here rather than pass.
	if len(english) == 0 || len(polish) == 0 {
		return append(findings, finding{
			place: siteRoot,
			said: fmt.Sprintf("holds %d English and %d Polish pages, so this check compared nothing",
				len(english), len(polish)),
		}), nil
	}

	for _, page := range sorted(english) {
		if !polish[page] {
			findings = append(findings, finding{
				place: siteRoot + "/" + page,
				said:  "has no Polish counterpart at " + siteRoot + "/" + polishPrefix + page,
			})
		}
	}
	for _, page := range sorted(polish) {
		if !english[page] {
			findings = append(findings, finding{
				place: siteRoot + "/" + polishPrefix + page,
				said:  "has no English counterpart at " + siteRoot + "/" + page,
			})
		}
	}
	return findings, nil
}

// translatablePage decides what carries words. The stylesheet and the images are
// shared by both languages on purpose - the Polish pages reference them by a
// relative path - so asking for a translation of them would be asking for a
// second copy of a file that is right as it is.
func translatablePage(relative string) bool {
	if strings.HasPrefix(relative, "img/") || strings.Contains(relative, "/img/") {
		return false
	}
	switch strings.ToLower(filepath.Ext(relative)) {
	case ".html", ".htm", ".md":
		return true
	}
	return false
}
