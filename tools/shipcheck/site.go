package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

// siteLinks follows every link the site makes to itself. The pages are written
// by hand and copied to the publishing branch with no build step, so a heading
// renamed in one chapter and referred to from another is published broken, and
// the only way anybody learns is by clicking it.
//
// Two kinds of link are checked: a file this repository should carry, and an
// anchor that file should declare. A link to something the release pipeline
// writes - the package repository under packages/ - is not this tree's to
// resolve, and is listed as such rather than ignored by accident.
func siteLinks(root string) ([]finding, error) {
	site := filepath.Join(root, siteRoot)
	pages := map[string]string{}
	err := filepath.WalkDir(site, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(site, path)
		if err != nil {
			return err
		}
		pages[filepath.ToSlash(relative)] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(pages) == 0 {
		return []finding{{
			place: siteRoot,
			said:  "no page of the site was read, so this check would pass over nothing",
		}}, nil
	}

	identifiers := map[string]map[string]bool{}
	for page, text := range pages {
		found := map[string]bool{}
		for _, match := range htmlIdentifier.FindAllStringSubmatch(text, -1) {
			found[match[1]] = true
		}
		identifiers[page] = found
	}

	var findings []finding
	for page, text := range pages {
		base := path.Dir(page)
		for _, match := range htmlHref.FindAllStringSubmatch(text, -1) {
			href := match[1]
			if href == "" || strings.HasPrefix(href, "http://") ||
				strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "mailto:") {
				continue
			}
			file, fragment, _ := strings.Cut(href, "#")
			target := page
			if file != "" {
				target = path.Clean(path.Join(base, file))
				if strings.HasSuffix(file, "/") {
					target = path.Clean(path.Join(base, file, "index.html"))
				}
				if _, ok := pages[target]; !ok {
					// The package repository is written by the release, onto the
					// publishing branch; this tree has no copy of it.
					if strings.HasPrefix(target, "packages/") {
						continue
					}
					// A stylesheet, an image, anything that is not a page: it is
					// a file of the site all the same, and it has to be there.
					if _, err := os.Stat(filepath.Join(site, filepath.FromSlash(target))); err == nil {
						continue
					}
					findings = append(findings, finding{
						place: path.Join(siteRoot, page),
						said:  fmt.Sprintf("links to %q, which this site does not carry", href),
					})
					continue
				}
			}
			if fragment != "" && !identifiers[target][fragment] {
				findings = append(findings, finding{
					place: path.Join(siteRoot, page),
					said: fmt.Sprintf("links to %q, and %s declares no such identifier",
						href, target),
				})
			}
		}
	}
	return findings, nil
}

var (
	htmlIdentifier = regexp.MustCompile(`\sid="([^"]+)"`)
	htmlHref       = regexp.MustCompile(`href="([^"]*)"`)
)
