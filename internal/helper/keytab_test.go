package helper

import (
	"context"
	"errors"
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

// keytabTool stands in for klist and ipa-getkeytab: the listing it prints
// is the one before the fetch until the fetch ran, and the one after from
// then on. A fetch that fails leaves the listing where it was, the way the
// real tool leaves the file.
type keytabTool struct {
	calls      [][]string
	before     string
	after      string
	fetched    bool
	fetchFails bool
}

func (f *keytabTool) run(_ context.Context, _ time.Duration, tool string, args ...string) (string, string, error) {
	f.calls = append(f.calls, append([]string{tool}, args...))
	switch tool {
	case "klist":
		if f.fetched {
			return f.after, "", nil
		}
		return f.before, "", nil
	case "ipa-getkeytab":
		if f.fetchFails {
			return "", "Failed to parse result: PrincipalName not found.", errors.New("exit status 1")
		}
		f.fetched = true
		return "Keytab successfully retrieved and stored in: /etc/krb5.keytab", "", nil
	}
	return "", "", errors.New("unexpected tool " + tool)
}

const listingBefore = "Keytab name: FILE:/etc/krb5.keytab\nKVNO Principal\n---- ----\n" +
	"   3 host/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   3 host/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   2 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   2 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n"

const listingAfter = listingBefore +
	"   3 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n" +
	"   3 HTTP/web1.flotestro.test@FLOTESTRO.TEST\n"

// The renewal fetches into the host's own keytab with the host's own
// credentials, and the key version number going up is the proof. The
// principal is the only thing the request contributes to argv.
func TestKeytabRenewalFetchesWithTheHostKeytabAndReportsTheVersions(t *testing.T) {
	tool := &keytabTool{before: listingBefore, after: listingAfter}
	server := testServer()
	server.accountTool = tool.run

	response := server.handle(context.Background(), keytabRequest("HTTP/web1.flotestro.test@FLOTESTRO.TEST"), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	if len(tool.calls) != 3 ||
		joinedCall(tool.calls[0]) != "klist -k /etc/krb5.keytab" ||
		joinedCall(tool.calls[1]) != "ipa-getkeytab -k /etc/krb5.keytab -p HTTP/web1.flotestro.test@FLOTESTRO.TEST" ||
		joinedCall(tool.calls[2]) != "klist -k /etc/krb5.keytab" {
		t.Fatalf("calls = %v", tool.calls)
	}
	result := response.GetKeytabRenewResult()
	if result.GetPrincipal() != "HTTP/web1.flotestro.test@FLOTESTRO.TEST" {
		t.Errorf("principal = %q", result.GetPrincipal())
	}
	if !result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 2 || result.GetKvnoAfter() != 3 {
		t.Errorf("versions = %+v, expected 2 known -> 3", result)
	}
}

// A principal with no key in the file yet is not a version of zero: the
// number before is reported as unknown, and the fetch still counts when
// the file lists the principal afterwards.
func TestKeytabRenewalOfAFreshPrincipalReportsNoVersionBefore(t *testing.T) {
	tool := &keytabTool{
		before: "KVNO Principal\n---- ----\n   3 host/web1.flotestro.test@FLOTESTRO.TEST\n",
		after:  "KVNO Principal\n---- ----\n   3 host/web1.flotestro.test@FLOTESTRO.TEST\n   1 nfs/web1.flotestro.test@FLOTESTRO.TEST\n",
	}
	server := testServer()
	server.accountTool = tool.run
	response := server.handle(context.Background(), keytabRequest("nfs/web1.flotestro.test"), nil)
	if !response.GetAccepted() {
		t.Fatalf("the renewal was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	result := response.GetKeytabRenewResult()
	if result.GetKvnoBeforeKnown() || result.GetKvnoBefore() != 0 || result.GetKvnoAfter() != 1 {
		t.Errorf("versions = %+v, expected unknown before and 1 after", result)
	}
}

// A fetch that left the version where it was is not a success, whatever
// the tool's exit code said: the service would still hold the key the
// directory retired.
func TestKeytabRenewalRefusesWhenTheVersionDidNotChange(t *testing.T) {
	for name, tool := range map[string]*keytabTool{
		"the tool failed":            {before: listingBefore, after: listingBefore, fetchFails: true},
		"the tool lied":              {before: listingBefore, after: listingBefore},
		"the principal disappeared":  {before: listingBefore, after: "KVNO Principal\n"},
		"the listing could not read": {before: listingBefore, after: ""},
	} {
		t.Run(name, func(t *testing.T) {
			server := testServer()
			server.accountTool = tool.run
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

// A principal that is not a service's, or is the host's own, never reaches
// a tool: the host keytab is replaced by a re-join, and a shape that is
// not service/host cannot be a principal ipa-getkeytab would take.
func TestKeytabRenewalRefusesABadPrincipalBeforeAnyTool(t *testing.T) {
	tool := &keytabTool{before: listingBefore, after: listingAfter}
	server := testServer()
	server.accountTool = tool.run
	for _, principal := range []string{"", "HTTP", "HTTP/web1", "host/web1.flotestro.test", "HTTP/web1.flotestro.test -x", "HTTP/web1.flotestro.test;id"} {
		response := server.handle(context.Background(), keytabRequest(principal), nil)
		if response.GetAccepted() || response.GetErrorCode() != ErrorMalformed {
			t.Errorf("%q: accepted=%v code=%q", principal, response.GetAccepted(), response.GetErrorCode())
		}
	}
	if len(tool.calls) != 0 {
		t.Fatalf("a tool ran for a refused principal: %v", tool.calls)
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
