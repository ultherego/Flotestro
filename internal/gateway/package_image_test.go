package gateway

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/vuln"
)

// The key of the table of packages is name, architecture, version and release; a
// list that repeats it would be refused whole.
func TestAPackageListedTwiceIsKeptOnce(t *testing.T) {
	list := []packages.InstalledPackage{
		{Name: "gpg-pubkey", Architecture: "noarch", Version: "1", Release: "a", Epoch: "0"},
		{Name: "gpg-pubkey", Architecture: "noarch", Version: "1", Release: "a", Epoch: "1"},
		{Name: "gpg-pubkey", Architecture: "noarch", Version: "1", Release: "b"},
		{Name: "tree", Architecture: "amd64", Version: "2.2", Release: "1"},
		{Name: "tree", Architecture: "arm64", Version: "2.2", Release: "1"},
	}
	kept := dedupePackages(list)
	if len(kept) != 4 {
		t.Fatalf("%d of 5 entries kept, want 4: %+v", len(kept), kept)
	}
	if kept[0].Epoch != "0" {
		t.Errorf("the first of two equal keys was not the one kept: %+v", kept[0])
	}
	if len(dedupePackages(nil)) != 0 {
		t.Error("nothing became something")
	}
}

func TestAFindingRepeatedForAPackageIsKeptOnce(t *testing.T) {
	list := []vuln.HostAdvisory{
		{AdvisoryID: "A-1", PackageName: "openssl", Architecture: "amd64"},
		{AdvisoryID: "A-1", PackageName: "openssl", Architecture: "amd64", Severity: "high"},
		{AdvisoryID: "A-1", PackageName: "openssl", Architecture: "arm64"},
		{AdvisoryID: "A-2", PackageName: "openssl", Architecture: "amd64"},
	}
	if kept := dedupeAdvisories(list); len(kept) != 3 {
		t.Fatalf("%d of 4 findings kept, want 3: %+v", len(kept), kept)
	}
}

// A list the database refuses for what is in it will be refused again; one it
// refuses for a reason that passes is redelivered.
func TestOnlyAListRefusedForItsContentSettlesWithoutIt(t *testing.T) {
	for code, want := range map[string]bool{
		"23505": true,  // unique_violation
		"23502": true,  // not_null_violation
		"22021": true,  // character_not_in_repertoire (a NUL in a text)
		"22P02": true,  // invalid_text_representation
		"40001": false, // serialization_failure
		"08006": false, // connection_failure
		"57014": false, // query_canceled
		"53300": false, // too_many_connections
	} {
		err := fmt.Errorf("writing: %w", &pgconn.PgError{Code: code})
		if got := listRefusedByItsData(err); got != want {
			t.Errorf("%s: refused for its data = %v, want %v", code, got, want)
		}
	}
	if listRefusedByItsData(errors.New("the connection is gone")) {
		t.Error("an error that is not the database's was taken for a refusal of the data")
	}
}
