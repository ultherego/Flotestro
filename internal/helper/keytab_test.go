package helper

import (
	"context"
	"errors"
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

// keytabTool stands in for klist, kinit, ipa-getkeytab and kdestroy: the
// listing it prints is the one before the fetch until the fetch ran, and the
// one after from then on. kinit writes a file where KRB5CCNAME points, so a
// test can see whether the cache is still there afterwards.
type keytabTool struct {
	calls      []keytabCall
	before     string
	after      string
	fetched    bool
	fetchFails bool
	kinitFails bool
	// cache is the path kinit was told to write the ticket to.
	cache string
}

func (f *keytabTool) run(ctx context.Context, _ time.Duration, tool string, args ...string) (string, string, error) {
	f.calls = append(f.calls, keytabCall{argv: append([]string{tool}, args...), env: toolEnvFrom(ctx)})
	switch tool {
	case "klist":
		if f.fetched {
			return f.after, "", nil
		}
		return f.before, "", nil
	case "kinit":
		if f.kinitFails {
			return "", "kinit: Keytab contains no suitable keys for host/web1.flotestro.test@FLOTESTRO.TEST while getting initial credentials",
				errors.New("exit status 1")
		}
		f.cache = cachePathIn(toolEnvFrom(ctx))
		if f.cache == "" {
			return "", "kinit: no credential cache was named", errors.New("exit status 1")
		}
		if err := os.WriteFile(f.cache, []byte("ticket"), 0o600); err != nil {
			return "", err.Error(), err
		}
		return "", "", nil
	case "ipa-getkeytab":
		if f.fetchFails {
			return "", "Failed to parse result: PrincipalName not found.", errors.New("exit status 1")
		}
		f.fetched = true
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
// host's own keytab first, runs the fetch with that ticket, and gives it back
// afterwards; the key version number going up is the proof the fetch landed.
func TestKeytabRenewalTakesAHostTicketAndGivesItBack(t *testing.T) {
	tool := &keytabTool{before: listingBefore, after: listingAfter}
	server, directory := keytabServer(t, tool)

	response := server.handle(context.Background(), keytabRequest("HTTP/web1.flotestro.test@FLOTESTRO.TEST"), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	expected := []string{
		"klist -k /etc/krb5.keytab",
		"kinit -k -t /etc/krb5.keytab host/web1.flotestro.test@FLOTESTRO.TEST",
		"ipa-getkeytab -k /etc/krb5.keytab -p HTTP/web1.flotestro.test@FLOTESTRO.TEST",
		"klist -k /etc/krb5.keytab",
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
	for _, index := range []int{2, 4} {
		if got := cachePathIn(tool.calls[index].env); got != cache {
			t.Errorf("%s ran with the cache %q, kinit filled %q",
				joinedCall(tool.calls[index].argv), got, cache)
		}
	}
	// The klist runs carry no cache: they read a file, and a listing has no
	// business with a ticket.
	for _, index := range []int{0, 3} {
		if got := cachePathIn(tool.calls[index].env); got != "" {
			t.Errorf("the listing ran with the cache %q", got)
		}
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Errorf("the credential cache %s outlived the renewal: %v", cache, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Errorf("the cache directory holds %v (err %v) after the renewal", entries, err)
	}

	result := response.GetKeytabRenewResult()
	if result.GetPrincipal() != "HTTP/web1.flotestro.test@FLOTESTRO.TEST" {
		t.Errorf("principal = %q", result.GetPrincipal())
	}
	if !result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 2 || result.GetKvnoAfter() != 3 {
		t.Errorf("versions = %+v, expected 2 known -> 3", result)
	}
}

// A ticket taken from the host's own key must not outlive the fetch it was
// taken for, whether the fetch worked or not.
func TestKeytabRenewalGivesTheTicketBackWhenTheFetchFails(t *testing.T) {
	tool := &keytabTool{before: listingBefore, after: listingBefore, fetchFails: true}
	server, directory := keytabServer(t, tool)

	response := server.handle(context.Background(), keytabRequest("HTTP/web1.flotestro.test"), nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorExecFailed {
		t.Fatalf("accepted=%v code=%q", response.GetAccepted(), response.GetErrorCode())
	}
	expected := []string{
		"klist -k /etc/krb5.keytab",
		"kinit -k -t /etc/krb5.keytab host/web1.flotestro.test@FLOTESTRO.TEST",
		"ipa-getkeytab -k /etc/krb5.keytab -p HTTP/web1.flotestro.test",
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
	for name, tool := range map[string]*keytabTool{
		"the keytab lists no host principal": {
			before: "Keytab name: FILE:/etc/krb5.keytab\nKVNO Principal\n---- ----\n" +
				"   2 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n",
		},
		"the keytab could not be read": {before: ""},
		"kinit refused the host key":   {before: listingBefore, kinitFails: true},
	} {
		t.Run(name, func(t *testing.T) {
			server, directory := keytabServer(t, tool)
			response := server.handle(context.Background(), keytabRequest("HTTP/web1.flotestro.test"), nil)
			if response.GetAccepted() || response.GetErrorCode() != ErrorHostKerberosKeyUnusable {
				t.Fatalf("accepted=%v code=%q message=%q",
					response.GetAccepted(), response.GetErrorCode(), response.GetMessage())
			}
			for _, call := range tool.calls {
				if call.argv[0] == "ipa-getkeytab" {
					t.Errorf("the fetch ran without a ticket: %v", argvOf(tool.calls))
				}
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Errorf("the cache directory holds %v (err %v) after the refusal", entries, err)
			}
		})
	}
}

// A principal with no key in the file yet is not a version of zero: the number
// before is reported as unknown, and the fetch still counts when the file
// lists the principal afterwards.
func TestKeytabRenewalOfAFreshPrincipalReportsNoVersionBefore(t *testing.T) {
	tool := &keytabTool{
		before: "KVNO Principal\n---- ----\n   3 host/web1.flotestro.test@FLOTESTRO.TEST\n",
		after:  "KVNO Principal\n---- ----\n   3 host/web1.flotestro.test@FLOTESTRO.TEST\n   1 nfs/web1.flotestro.test@FLOTESTRO.TEST\n",
	}
	server, _ := keytabServer(t, tool)
	response := server.handle(context.Background(), keytabRequest("nfs/web1.flotestro.test"), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	result := response.GetKeytabRenewResult()
	if result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 0 || result.GetKvnoAfter() != 1 {
		t.Errorf("versions = %+v, expected unknown before and 1 after", result)
	}
}

// A fetch that left the version where it was is not a success, whatever the
// tool's exit code said: the service would still hold the key the directory
// retired.
func TestKeytabRenewalRefusesWhenTheVersionDidNotChange(t *testing.T) {
	for name, tool := range map[string]*keytabTool{
		"the tool failed":            {before: listingBefore, after: listingBefore, fetchFails: true},
		"the tool lied":              {before: listingBefore, after: listingBefore},
		"the principal disappeared":  {before: listingBefore, after: "KVNO Principal\n"},
		"the listing could not read": {before: listingBefore, after: ""},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := keytabServer(t, tool)
			response := server.handle(context.Background(), keytabRequest("HTTP/web1.flotestro.test"), nil)
			if response.GetAccepted() || response.GetErrorCode() != ErrorExecFailed {
				t.Fatalf("accepted=%v code=%q message=%q", response.GetAccepted(), response.GetErrorCode(), response.GetMessage())
			}
			// The versions read so far travel with the refusal: the
			// operator learns what the file held.
			if result := response.GetKeytabRenewResult(); result == nil || result.GetKvnoBefore() != 2 {
				t.Errorf("the refusal carries %+v", result)
			}
		})
	}
}

// A principal that is not a service's, or is the host's own, never reaches a
// tool: the host keytab is replaced by a re-join, and a shape that is not
// service/host cannot be a principal ipa-getkeytab would take.
func TestKeytabRenewalRefusesABadPrincipalBeforeAnyTool(t *testing.T) {
	tool := &keytabTool{before: listingBefore, after: listingAfter}
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
