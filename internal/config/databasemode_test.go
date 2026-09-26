package config

import (
	"strings"
	"testing"
)

// The deployment used to infer the kind of database from whether a file
// happened to be there. An installation on a database somebody else runs now
// says so, and is then held to what an installation of that kind promises.
func TestAnExternalDatabaseIsHeldToAVerifiedWriter(t *testing.T) {
	const host = "postgresql://flotestro:secret@db.example.org:5432/flotestro"
	good := host + "?sslmode=verify-full&target_session_attrs=read-write"
	if err := CheckDatabaseDSN(DatabaseModeExternal, good); err != nil {
		t.Fatalf("a verified writer was refused: %v", err)
	}
	// The quickstart is on one host and an internal network, and says so.
	if err := CheckDatabaseDSN(DatabaseModeQuickstart, host+"?sslmode=disable"); err != nil {
		t.Fatalf("the quickstart DSN was refused: %v", err)
	}

	for name, dsn := range map[string]string{
		"no TLS at all":      host + "?sslmode=disable&target_session_attrs=read-write",
		"TLS without a name": host + "?sslmode=require&target_session_attrs=read-write",
		"no writer promised": host + "?sslmode=verify-full",
		"a reader":           host + "?sslmode=verify-full&target_session_attrs=any",
	} {
		err := CheckDatabaseDSN(DatabaseModeExternal, dsn)
		if err == nil {
			t.Errorf("%s was accepted for an external database", name)
			continue
		}
		// The refusal explains itself and never carries the DSN: it holds the
		// password.
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the refusal carries the password: %v", name, err)
		}
	}
}

// The key=value form is the other way a driver takes a DSN, and it has to be
// read the same way.
func TestTheKeyValueFormIsReadToo(t *testing.T) {
	dsn := "host=db.example.org user=flotestro password=secret dbname=flotestro " +
		"sslmode=verify-full target_session_attrs=read-write"
	if err := CheckDatabaseDSN(DatabaseModeExternal, dsn); err != nil {
		t.Fatalf("a verified writer in the key=value form was refused: %v", err)
	}
	if err := CheckDatabaseDSN(DatabaseModeExternal, strings.Replace(dsn, "verify-full", "require", 1)); err == nil {
		t.Error("sslmode=require in the key=value form was accepted")
	}
}

func TestTheModeIsQuickstartUntilSomebodySaysOtherwise(t *testing.T) {
	for value, want := range map[string]DatabaseMode{
		"": DatabaseModeQuickstart, "quickstart": DatabaseModeQuickstart,
		"external": DatabaseModeExternal, " External ": DatabaseModeExternal,
	} {
		mode, err := ParseDatabaseMode(value)
		if err != nil || mode != want {
			t.Errorf("%q gave %q (%v), want %q", value, mode, err, want)
		}
	}
	if _, err := ParseDatabaseMode("managed"); err == nil {
		t.Error("an unknown mode was accepted")
	}
}
