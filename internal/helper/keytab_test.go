package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

func keytabRequest(principal string) *helperv1.HelperRequest {
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-keytab",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  60,
		Action: &helperv1.HelperRequest_KeytabRenew{
			KeytabRenew: &helperv1.KeytabRenewRequest{Principal: principal},
		},
	}
}

// keytabCall is one tool run: the argv and the environment the helper asked
// for, because the credential cache travels in the environment and not in
// argv.
type keytabCall struct {
	argv []string
	env  []string
}

// keytabEntry is one key in the modelled keytab: a version and a principal,
// which is what klist -k prints of it.
type keytabEntry struct {
	vno       uint32
	principal string
}

// keytabTool stands in for klist, kinit, ipa-rmkeytab, ipa-getkeytab and
// kdestroy over a keytab it keeps as a list of entries, so the tools change the
// file instead of a test naming the listing that comes out. Three laws of the
// real host are modelled, all three measured on agent-ubuntu on 2026-09-30:
// ipa-getkeytab appends rather than replaces; the directory hands out the
// version in nextVersion, which after a retire is 1 and therefore below what the
// file already holds; and a Kerberos lookup takes the highest version in the
// file, so a stale entry above the fetched one makes kinit fail
// preauthentication.
type keytabTool struct {
	calls   []keytabCall
	entries []keytabEntry
	// nextVersion is the version the directory gives the next fetch. A retire
	// removed the principal's keys and the counter with them, so it is 1.
	nextVersion uint32
	// live is the version the directory accepts for the principal last fetched.
	live       map[string]uint32
	unreadable bool
	// unreadableAfterFetch models a listing that reads before the fetch and not
	// after it: the versions before are known and the proof is not.
	unreadableAfterFetch bool
	fetched              bool
	fetchFails           bool
	kinitFails           bool
	rmFails              bool
	// noFetch models a tool that reports success and writes nothing.
	noFetch bool
	// cache is the path the last kinit was told to write the ticket to.
	cache string
}

func (f *keytabTool) listing() string {
	rendered := "Keytab name: FILE:/etc/krb5.keytab\nKVNO Principal\n---- ----\n"
	for _, entry := range f.entries {
		rendered += fmt.Sprintf("%4d %s\n", entry.vno, entry.principal)
	}
	return rendered
}

// highestIn is the version a Kerberos lookup would take for a principal.
func (f *keytabTool) highestIn(principal string) (uint32, bool) {
	return highestKVNO(f.listing(), principal)
}

func (f *keytabTool) run(ctx context.Context, _ time.Duration, tool string, args ...string) (string, string, error) {
	f.calls = append(f.calls, keytabCall{argv: append([]string{tool}, args...), env: toolEnvFrom(ctx)})
	switch tool {
	case "klist":
		if f.unreadable || (f.unreadableAfterFetch && f.fetched) {
			return "", "klist: Key table file '/etc/krb5.keytab' not found", errors.New("exit status 1")
		}
		return f.listing(), "", nil
	case "kinit":
		principal := args[len(args)-1]
		if f.kinitFails {
			return "", "kinit: Keytab contains no suitable keys for " + principal +
				" while getting initial credentials", errors.New("exit status 1")
		}
		if !strings.HasPrefix(strings.ToLower(principal), "host/") {
			// The proof: the key the file offers for the principal is the one with
			// the highest version, and only the version the directory holds works.
			offered, found := f.highestIn(principal)
			if !found || f.live[strings.ToLower(principal)] != offered {
				return "", "kinit: Preauthentication failed while getting initial credentials",
					errors.New("exit status 1")
			}
		}
		f.cache = cachePathIn(toolEnvFrom(ctx))
		if f.cache == "" {
			return "", "kinit: no credential cache was named", errors.New("exit status 1")
		}
		if err := os.WriteFile(f.cache, []byte("ticket"), 0o600); err != nil {
			return "", err.Error(), err
		}
		return "", "", nil
	case "ipa-rmkeytab":
		if f.rmFails {
			return "", "Failed to open keytab '/etc/krb5.keytab'.", errors.New("exit status 1")
		}
		principal := args[len(args)-1]
		f.entries = slices.DeleteFunc(f.entries, func(entry keytabEntry) bool {
			return strings.EqualFold(entry.principal, principal)
		})
		return "", "", nil
	case "ipa-getkeytab":
		if f.fetchFails {
			return "", "Failed to parse result: PrincipalName not found.", errors.New("exit status 1")
		}
		principal := args[len(args)-1]
		// The fetch resets the principal's secret in the directory whatever else
		// happens, so the version it hands out is the only one that authenticates.
		if f.live == nil {
			f.live = map[string]uint32{}
		}
		f.live[strings.ToLower(principal)] = f.nextVersion
		f.fetched = true
		if !f.noFetch {
			for range 2 {
				f.entries = append(f.entries, keytabEntry{vno: f.nextVersion, principal: principal})
			}
		}
		return "Keytab successfully retrieved and stored in: /etc/krb5.keytab", "", nil
	case "kdestroy":
		if cache := cachePathIn(toolEnvFrom(ctx)); cache != "" {
			_ = os.Remove(cache)
		}
		return "", "", nil
	}
	return "", "", errors.New("unexpected tool " + tool)
}

// cachePathIn reads the cache KRB5CCNAME names out of a tool environment.
func cachePathIn(env []string) string {
	for _, entry := range env {
		if path, ok := strings.CutPrefix(entry, "KRB5CCNAME=FILE:"); ok {
			return path
		}
	}
	return ""
}

// keytabServer is a helper whose credential cache lives in the test's own
// directory: a unit test may not write under /var/lib.
func keytabServer(t *testing.T, tool *keytabTool) (*Server, string) {
	t.Helper()
	server := testServer()
	server.accountTool = tool.run
	directory := t.TempDir()
	server.ticketCacheDir = directory
	return server, directory
}

// argvOf renders the argv of the calls, so a failure says what really ran.
func argvOf(calls []keytabCall) []string {
	rendered := make([]string, 0, len(calls))
	for _, call := range calls {
		rendered = append(rendered, joinedCall(call.argv))
	}
	return rendered
}

const hostPrincipalOfWeb1 = "host/web1.flotestro.test@FLOTESTRO.TEST"
const servicePrincipalOfWeb1 = "HTTP/web1.flotestro.test@FLOTESTRO.TEST"

// beforeARenewal is the file the host carries when a rotation reaches it: its
// own key, and version 2 of the service whose keytab the directory just
// retired.
func beforeARenewal() []keytabEntry {
	return []keytabEntry{
		{vno: 3, principal: hostPrincipalOfWeb1},
		{vno: 3, principal: hostPrincipalOfWeb1},
		{vno: 2, principal: servicePrincipalOfWeb1},
		{vno: 2, principal: servicePrincipalOfWeb1},
	}
}

// retiredKeytab is the host after the directory retired the service keytab with
// service_disable: the counter went with the keys, so the next fetch gives 1.
func retiredKeytab() *keytabTool {
	return &keytabTool{entries: beforeARenewal(), nextVersion: 1}
}

const listingBefore = "Keytab name: FILE:/etc/krb5.keytab\nKVNO Principal\n---- ----\n" +
	"   3 host/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   3 host/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   2 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   2 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n"

const listingAfter = listingBefore +
	"   3 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   3 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n"

// ipa-getkeytab binds over GSSAPI: -k is the file it writes into, not a
// credential. So the renewal takes a ticket of the host principal out of the
// host's own keytab first, clears the principal's older entries, runs the
// fetch with that ticket, proves the fetched key authenticates and gives every
// ticket back afterwards.
func TestKeytabRenewalTakesAHostTicketAndGivesItBack(t *testing.T) {
	tool := retiredKeytab()
	server, directory := keytabServer(t, tool)

	response := server.handle(context.Background(), keytabRequest(servicePrincipalOfWeb1), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	expected := []string{
		"klist -k /etc/krb5.keytab",
		"kinit -k -t /etc/krb5.keytab " + hostPrincipalOfWeb1,
		"ipa-rmkeytab -k /etc/krb5.keytab -p " + servicePrincipalOfWeb1,
		"ipa-getkeytab -k /etc/krb5.keytab -p " + servicePrincipalOfWeb1,
		"klist -k /etc/krb5.keytab",
		"kinit -k -t /etc/krb5.keytab " + servicePrincipalOfWeb1,
		"kdestroy",
		"kdestroy",
	}
	if argv := argvOf(tool.calls); !slices.Equal(argv, expected) {
		t.Fatalf("calls = %v, expected %v", argv, expected)
	}
	// The ticket the fetch used is the one kinit took, in a cache of the
	// helper's own: not the cache of whoever is logged in on the host.
	cache := cachePathIn(tool.calls[1].env)
	if cache == "" || !strings.HasPrefix(cache, directory+string(filepath.Separator)) {
		t.Fatalf("kinit wrote the ticket to %q, which is not under %s", cache, directory)
	}
	for _, index := range []int{2, 3} {
		if got := cachePathIn(tool.calls[index].env); got != cache {
			t.Errorf("%s ran with the cache %q, kinit filled %q",
				joinedCall(tool.calls[index].argv), got, cache)
		}
	}
	// The proof is a ticket of the service itself and belongs in a cache of its
	// own: the host ticket is still needed while it runs.
	proof := cachePathIn(tool.calls[5].env)
	if proof == "" || proof == cache || !strings.HasPrefix(proof, directory+string(filepath.Separator)) {
		t.Errorf("the proof ran with the cache %q and the fetch with %q", proof, cache)
	}
	// The klist runs carry no cache: they read a file, and a listing has no
	// business with a ticket.
	for _, index := range []int{0, 4} {
		if got := cachePathIn(tool.calls[index].env); got != "" {
			t.Errorf("the listing ran with the cache %q", got)
		}
	}
	for _, path := range []string{cache, proof} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("the credential cache %s outlived the renewal: %v", path, err)
		}
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Errorf("the cache directory holds %v (err %v) after the renewal", entries, err)
	}

	result := response.GetKeytabRenewResult()
	if result.GetPrincipal() != servicePrincipalOfWeb1 {
		t.Errorf("principal = %q", result.GetPrincipal())
	}
	// The version went DOWN and the renewal stands: the directory reset the
	// counter when it retired the keytab. This is the whole point.
	if !result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 2 || result.GetKvnoAfter() != 1 {
		t.Errorf("versions = %+v, expected 2 known -> 1", result)
	}
}

// The repair, pinned as a shape: the principal's older entries go before the
// fetch, and the file ends with the fetched version alone. ipa-getkeytab
// appends, a lookup takes the highest version, and after a retire the fetched
// version is the lowest - so an entry left behind shadows the new key and the
// service cannot authenticate with it.
func TestKeytabRenewalRemovesTheOldEntriesBeforeTheFetch(t *testing.T) {
	tool := retiredKeytab()
	server, _ := keytabServer(t, tool)

	response := server.handle(context.Background(), keytabRequest(servicePrincipalOfWeb1), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	remove, fetch := -1, -1
	for index, call := range tool.calls {
		switch call.argv[0] {
		case "ipa-rmkeytab":
			remove = index
		case "ipa-getkeytab":
			fetch = index
		}
	}
	if remove < 0 || fetch < 0 || remove > fetch {
		t.Fatalf("the old entries were not removed before the fetch: %v", argvOf(tool.calls))
	}
	versions := map[uint32]int{}
	for _, entry := range tool.entries {
		if strings.EqualFold(entry.principal, servicePrincipalOfWeb1) {
			versions[entry.vno]++
		}
	}
	if len(versions) != 1 || versions[1] == 0 {
		t.Errorf("the keytab holds %v for %s, expected version 1 alone",
			versions, servicePrincipalOfWeb1)
	}
}

// A ticket taken from the host's own key must not outlive the fetch it was
// taken for, whether the fetch worked or not.
func TestKeytabRenewalGivesTheTicketBackWhenTheFetchFails(t *testing.T) {
	tool := retiredKeytab()
	tool.fetchFails = true
	server, directory := keytabServer(t, tool)

	response := server.handle(context.Background(), keytabRequest(servicePrincipalOfWeb1), nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorExecFailed {
		t.Fatalf("accepted=%v code=%q", response.GetAccepted(), response.GetErrorCode())
	}
	expected := []string{
		"klist -k /etc/krb5.keytab",
		"kinit -k -t /etc/krb5.keytab " + hostPrincipalOfWeb1,
		"ipa-rmkeytab -k /etc/krb5.keytab -p " + servicePrincipalOfWeb1,
		"ipa-getkeytab -k /etc/krb5.keytab -p " + servicePrincipalOfWeb1,
		"kdestroy",
	}
	if argv := argvOf(tool.calls); !slices.Equal(argv, expected) {
		t.Fatalf("calls = %v, expected %v", argv, expected)
	}
	if _, err := os.Stat(tool.cache); !os.IsNotExist(err) {
		t.Errorf("the credential cache %s outlived the failed fetch: %v", tool.cache, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Errorf("the cache directory holds %v (err %v) after the failed fetch", entries, err)
	}
}

// A host whose keytab holds no host key cannot authenticate at all, and the
// operator has to read that rather than an exec failure of a tool. Nothing is
// written: no ticket is taken and no fetch runs.
func TestKeytabRenewalRefusesWhenTheHostHasNoKeyOfItsOwn(t *testing.T) {
	serviceOnly := &keytabTool{nextVersion: 1, entries: []keytabEntry{
		{vno: 2, principal: servicePrincipalOfWeb1},
	}}
	unreadable := retiredKeytab()
	unreadable.unreadable = true
	refused := retiredKeytab()
	refused.kinitFails = true
	for name, tool := range map[string]*keytabTool{
		"the keytab lists no host principal": serviceOnly,
		"the keytab could not be read":       unreadable,
		"kinit refused the host key":         refused,
	} {
		t.Run(name, func(t *testing.T) {
			server, directory := keytabServer(t, tool)
			response := server.handle(context.Background(), keytabRequest("HTTP/web1.flotestro.test"), nil)
			if response.GetAccepted() || response.GetErrorCode() != ErrorHostKerberosKeyUnusable {
				t.Fatalf("accepted=%v code=%q message=%q",
					response.GetAccepted(), response.GetErrorCode(), response.GetMessage())
			}
			for _, call := range tool.calls {
				if call.argv[0] == "ipa-getkeytab" || call.argv[0] == "ipa-rmkeytab" {
					t.Errorf("the keytab was touched without a ticket: %v", argvOf(tool.calls))
				}
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Errorf("the cache directory holds %v (err %v) after the refusal", entries, err)
			}
		})
	}
}

// A principal with no key in the file yet is not a version of zero: the number
// before is reported as unknown, nothing is removed, and the fetch still counts
// when the file lists the principal afterwards.
func TestKeytabRenewalOfAFreshPrincipalReportsNoVersionBefore(t *testing.T) {
	tool := &keytabTool{nextVersion: 1, entries: []keytabEntry{
		{vno: 3, principal: hostPrincipalOfWeb1},
	}}
	server, _ := keytabServer(t, tool)
	response := server.handle(context.Background(), keytabRequest("nfs/web1.flotestro.test"), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	for _, call := range tool.calls {
		if call.argv[0] == "ipa-rmkeytab" {
			t.Errorf("a principal with no key in the file was removed: %v", argvOf(tool.calls))
		}
	}
	result := response.GetKeytabRenewResult()
	if result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 0 || result.GetKvnoAfter() != 1 {
		t.Errorf("versions = %+v, expected unknown before and 1 after", result)
	}
}

// A renewal is a success only when the key the file now holds authenticates
// against the directory, whatever the tool's exit code said. The version number
// cannot answer that: after a retire it goes down.
func TestKeytabRenewalRefusesWhenTheFetchedKeyDoesNotAuthenticate(t *testing.T) {
	wroteNothing := retiredKeytab()
	wroteNothing.noFetch = true
	removalFailed := retiredKeytab()
	removalFailed.rmFails = true
	listingLost := retiredKeytab()
	listingLost.unreadableAfterFetch = true
	for name, tool := range map[string]*keytabTool{
		"the tool wrote nothing":        wroteNothing,
		"the removal failed":            removalFailed,
		"the listing could not be read": listingLost,
	} {
		t.Run(name, func(t *testing.T) {
			server, directory := keytabServer(t, tool)
			response := server.handle(context.Background(), keytabRequest(servicePrincipalOfWeb1), nil)
			if response.GetAccepted() || response.GetErrorCode() != ErrorExecFailed {
				t.Fatalf("accepted=%v code=%q message=%q",
					response.GetAccepted(), response.GetErrorCode(), response.GetMessage())
			}
			// The versions read so far travel with the refusal: the
			// operator learns what the file held.
			if result := response.GetKeytabRenewResult(); result == nil ||
				!result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 2 {
				t.Errorf("the refusal carries %+v", response.GetKeytabRenewResult())
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Errorf("the cache directory holds %v (err %v) after the refusal", entries, err)
			}
		})
	}
}

// A principal that is not a service's, or is the host's own, never reaches a
// tool: the host keytab is replaced by a re-join, and a shape that is not
// service/host cannot be a principal ipa-getkeytab would take.
func TestKeytabRenewalRefusesABadPrincipalBeforeAnyTool(t *testing.T) {
	tool := retiredKeytab()
	server, _ := keytabServer(t, tool)
	for _, principal := range []string{"", "HTTP", "HTTP/web1", "host/web1.flotestro.test", "HTTP/web1.flotestro.test -x", "HTTP/web1.flotestro.test;id"} {
		response := server.handle(context.Background(), keytabRequest(principal), nil)
		if response.GetAccepted() || response.GetErrorCode() != ErrorMalformed {
			t.Errorf("%q: accepted=%v code=%q", principal, response.GetAccepted(), response.GetErrorCode())
		}
	}
	if len(tool.calls) != 0 {
		t.Fatalf("a tool ran for a refused principal: %v", argvOf(tool.calls))
	}
}

// The host principal comes out of the host's own keytab listing, realm and
// all: the helper never builds it out of a hostname of its own.
func TestHostPrincipalInReadsTheListing(t *testing.T) {
	principal, found := hostPrincipalIn(listingAfter)
	if !found || principal != "host/web1.flotestro.test@FLOTESTRO.TEST" {
		t.Errorf("principal = %q %v", principal, found)
	}
	if _, found := hostPrincipalIn("KVNO Principal\n---- ----\n   2 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n"); found {
		t.Error("a service principal was taken for the host's own")
	}
	// The header of the listing has two fields as well, and "Principal" is not
	// a key version number.
	if _, found := hostPrincipalIn("KVNO Principal\nhost/web1.flotestro.test x\n"); found {
		t.Error("a line that is not a key was read as one")
	}
}

// The listing is read for the highest version of the principal named,
// with or without the realm, and never for another principal's.
func TestHighestKVNOReadsTheListing(t *testing.T) {
	version, found := highestKVNO(listingAfter, "HTTP/web1.flotestro.test")
	if !found || version != 3 {
		t.Errorf("without a realm: %d %v", version, found)
	}
	version, found = highestKVNO(listingAfter, "HTTP/web1.flotestro.test@FLOTESTRO.TEST")
	if !found || version != 3 {
		t.Errorf("with the realm: %d %v", version, found)
	}
	if _, found := highestKVNO(listingAfter, "HTTP/web1.flotestro.test@OTHER.TEST"); found {
		t.Error("another realm matched")
	}
	if _, found := highestKVNO(listingAfter, "ldap/web1.flotestro.test"); found {
		t.Error("another service matched")
	}
	if _, found := highestKVNO(strings.ReplaceAll(listingAfter, "HTTP", "HTTP-"), "HTTP/web1.flotestro.test"); found {
		t.Error("a prefix matched")
	}
}
