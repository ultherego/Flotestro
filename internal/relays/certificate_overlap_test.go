package relays

// The two sides of a renewal: what the panel recognises a relay by, and what it
// is allowed to write once it has signed.

import (
	"regexp"
	"strings"
	"testing"
)

// A fingerprint column compared against a parameter.
var comparedFingerprint = regexp.MustCompile(`(?:previous_)?fingerprint_sha256\s*=\s*\$\d+`)

// A renewal reads the row, decides the relay may renew, signs - and writes a
// moment later under the condition it decided on. The condition has to be the
// one the decision was made with: the lookup recognises a relay by its current
// certificate or by the one it replaced, and a write that accepts only the
// current one refuses exactly the relay that needs the renewal most - the one
// whose last renewal answer was lost and which therefore still holds the
// previous certificate. It was refused with "revoked or replaced while the
// renewal was being signed" until its certificate expired, and then it was
// unknown and gone from the fleet.
func TestTheRenewalWriteAcceptsEveryCertificateTheLookupDoes(t *testing.T) {
	recognised := fingerprintColumns(t, lookupCertificateQuery)
	if len(recognised) != 2 {
		t.Fatalf("the lookup recognises a relay by %v; this test reads the wrong statement", recognised)
	}
	written := fingerprintColumns(t, saveCertificateQuery)
	for column := range recognised {
		if !written[column] {
			t.Errorf("the lookup accepts a relay by %s and the write of the renewal does not; "+
				"a relay recognised that way can never renew", column)
		}
	}
}

// fingerprintColumns are the fingerprint columns the condition of a statement
// compares against a parameter.
func fingerprintColumns(t *testing.T, query string) map[string]bool {
	t.Helper()
	at := strings.Index(query, " where ")
	if at < 0 {
		t.Fatalf("the statement has no condition to read:\n%s", query)
	}
	columns := map[string]bool{}
	for _, match := range comparedFingerprint.FindAllString(query[at:], -1) {
		columns[strings.TrimSpace(strings.Split(match, "=")[0])] = true
	}
	return columns
}
