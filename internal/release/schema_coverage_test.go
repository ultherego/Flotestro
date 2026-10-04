package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A column the code writes and no migration creates.
//
// Twice on 04.10: a relay's identifier written into a column with a foreign key
// to hosts, and boot_id_before written into a table that has no such column.
// The second one answered every read of the remediation plans with "column
// boot_id_before does not exist", made its endpoint return 500 - and the
// compiler, go vet and every unit test said nothing, because a unit test has no
// database and never runs the insert. The gate found it an hour into the suite.
//
// This test is the same question asked in milliseconds: every column an insert
// or an update names has to exist in db/migrations. It reads the two sides of a
// change that is written in two places and is therefore easy to finish in one.
//
// What it deliberately does not do: parse SQL. It takes the shapes this
// repository writes - "insert into <table> (<columns>)" and "update <table> set
// <column> = " - because a parser for everything would have to be right about
// everything, and these two shapes are where both faults were.

var (
	// The column list of an insert, as this repository writes it: the table,
	// then a parenthesised list that may run over several lines.
	insertColumns = regexp.MustCompile(`(?is)insert\s+into\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)`)
	// The assignments of an update, up to the clause that ends them.
	updateAssignments = regexp.MustCompile(`(?is)update\s+([a-z_][a-z0-9_]*)\s+set\s+(.*?)(?:\swhere\s|\sreturning\s|\sfrom\s|` + "`" + `|$)`)
	// One assignment: a column, then "=".
	assignedColumn = regexp.MustCompile(`(?i)([a-z_][a-z0-9_]*)\s*=`)
	// create table <name> ( ... ), and the columns inside it.
	createTable = regexp.MustCompile(`(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?([a-z_][a-z0-9_]*)\s*\((.*?)\n\)\s*;`)
	// alter table <name> add column [if not exists] <column>
	addColumn = regexp.MustCompile(`(?is)alter\s+table\s+([a-z_][a-z0-9_]*)([^;]*);`)
	addOne    = regexp.MustCompile(`(?is)add\s+column\s+(?:if\s+not\s+exists\s+)?([a-z_][a-z0-9_]*)`)
	renameOne = regexp.MustCompile(`(?is)rename\s+column\s+([a-z_][a-z0-9_]*)\s+to\s+([a-z_][a-z0-9_]*)`)
	// alter table <old> rename to <new>: the columns go with the name. The
	// table of the enrollment requests is the table of the enrollment tokens
	// under its later name, and every column of it would otherwise read as
	// missing.
	renameTable = regexp.MustCompile(`(?is)alter\s+table\s+(?:if\s+exists\s+)?([a-z_][a-z0-9_]*)\s+rename\s+to\s+([a-z_][a-z0-9_]*)`)
)

func TestEveryColumnTheCodeWritesExistsInTheMigrations(t *testing.T) {
	root := repositoryRoot(t)
	schema := columnsOfMigrations(t, filepath.Join(root, "db", "migrations"))
	if len(schema) < 20 {
		t.Fatalf("the migrations describe %d tables; the directory was not read", len(schema))
	}

	type reference struct{ table, column, file string }
	var missing []reference
	for _, path := range goFilesUnder(t, filepath.Join(root, "internal")) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(body)
		for _, match := range insertColumns.FindAllStringSubmatch(source, -1) {
			table := strings.ToLower(match[1])
			columns, known := schema[table]
			if !known {
				// A table this test does not know is a table the migrations do
				// not create: a temporary one, or a name built at runtime.
				// Saying nothing about it is the honest answer - the next
				// check would be a guess.
				continue
			}
			for _, column := range splitColumns(match[2]) {
				if !columns[column] {
					missing = append(missing, reference{table, column, path})
				}
			}
		}
		for _, match := range updateAssignments.FindAllStringSubmatch(source, -1) {
			table := strings.ToLower(match[1])
			columns, known := schema[table]
			if !known {
				continue
			}
			for _, assignment := range strings.Split(match[2], ",") {
				column := assignedName(assignment)
				if column == "" {
					continue
				}
				if !columns[column] {
					missing = append(missing, reference{table, column, path})
				}
			}
		}
	}

	for _, item := range missing {
		t.Errorf("%s writes %s.%s, which no migration creates",
			relativeTo(root, item.file), item.table, item.column)
	}
	if len(missing) > 0 {
		t.Log("a column the code writes and the migrations do not create is a missing migration; " +
			"the database answers 42703 and the endpoint answers 500")
	}
}

// columnsOfMigrations reads the schema the migrations describe: the columns of
// every create table, plus the ones later migrations add.
func columnsOfMigrations(t *testing.T, dir string) map[string]map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	// In order: a column added by 0142 is not in the table 0025 created, and
	// the order of application is the order of the names.
	sortStrings(names)

	schema := map[string]map[string]bool{}
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		// The comments go first. A semicolon inside one of them - "the holder
		// renews the lease while it works; a dead holder loses it" - ended the
		// statement for this parser and hid the three columns written after
		// it. A comment is not SQL, so it is not parsed as SQL.
		sql := withoutSQLComments(string(body))
		for _, match := range renameTable.FindAllStringSubmatch(sql, -1) {
			from, to := strings.ToLower(match[1]), strings.ToLower(match[2])
			if schema[to] == nil {
				schema[to] = map[string]bool{}
			}
			for column := range schema[from] {
				schema[to][column] = true
			}
		}
		for _, match := range createTable.FindAllStringSubmatch(sql, -1) {
			table := strings.ToLower(match[1])
			if schema[table] == nil {
				schema[table] = map[string]bool{}
			}
			for _, line := range strings.Split(match[2], "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "--") {
					continue
				}
				first := strings.ToLower(strings.Trim(strings.Fields(line)[0], ",()"))
				switch first {
				case "primary", "unique", "foreign", "check", "constraint", "exclude":
					continue
				}
				if columnName.MatchString(first) {
					schema[table][first] = true
				}
			}
		}
		for _, match := range addColumn.FindAllStringSubmatch(sql, -1) {
			table := strings.ToLower(match[1])
			if schema[table] == nil {
				schema[table] = map[string]bool{}
			}
			for _, added := range addOne.FindAllStringSubmatch(match[2], -1) {
				schema[table][strings.ToLower(added[1])] = true
			}
			for _, renamed := range renameOne.FindAllStringSubmatch(match[2], -1) {
				schema[table][strings.ToLower(renamed[2])] = true
			}
		}
	}
	return schema
}

var columnName = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// withoutSQLComments removes what follows "--" on every line. The marker inside
// a string literal would be removed too; no migration of this repository writes
// one, and a parser that tries to tell them apart is a parser that has to be
// right about quoting.
func withoutSQLComments(sql string) string {
	lines := strings.Split(sql, "\n")
	for i, line := range lines {
		if index := strings.Index(line, "--"); index >= 0 {
			lines[i] = line[:index]
		}
	}
	return strings.Join(lines, "\n")
}

// assignedName reads the column of one assignment of an update. The name has to
// stand outside any parentheses: "now() + make_interval(secs => $3)" is one
// value, and secs is an argument of a function rather than a column of the
// table.
func assignedName(assignment string) string {
	equals := strings.Index(assignment, "=")
	if equals < 0 {
		return ""
	}
	before := assignment[:equals]
	if strings.Count(before, "(") != strings.Count(before, ")") {
		return ""
	}
	names := assignedColumn.FindStringSubmatch(assignment)
	if names == nil {
		return ""
	}
	return strings.ToLower(names[1])
}

// splitColumns reads the column list of an insert.
func splitColumns(list string) []string {
	var columns []string
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		// A comment inside the list, which this repository writes.
		if index := strings.Index(part, "--"); index >= 0 {
			part = strings.TrimSpace(part[:index])
		}
		part = strings.TrimSpace(strings.Trim(part, "\n\t "))
		name := strings.ToLower(part)
		if columnName.MatchString(name) {
			columns = append(columns, name)
		}
	}
	return columns
}

func goFilesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("reading the sources: %v", err)
	}
	return files
}

// repositoryRoot finds the root by the directory every checkout has.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "db", "migrations")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	// Not a skip. Every checkout of this repository has db/migrations, so not
	// finding it means this test cannot do its job - and a check that stops
	// running quietly is the shape of defect it was written to catch.
	t.Fatal("db/migrations was not found above the package directory; this check cannot run")
	return ""
}

func relativeTo(root, path string) string {
	if relative, err := filepath.Rel(root, path); err == nil {
		return relative
	}
	return path
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
