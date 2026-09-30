package helper

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// hostKeytabPath is the one keytab the renewal writes into: the host's own.
const hostKeytabPath = "/etc/krb5.keytab"

// defaultTicketCacheDir is where the renewal keeps the credential cache it
// owns. The helper's state directory is root's alone, so no cache of a human
// or of another service can be read, reused or overwritten by it.
const defaultTicketCacheDir = "/var/lib/flotestro-helper"

// renewKeytab fetches a new key of a service principal into the host's keytab
// with ipa-getkeytab. The -k argument is the file the tool writes into, not a
// credential: without -D/-w the tool binds over GSSAPI from the ticket cache,
// so the helper first takes a ticket of the host principal out of the host's
// own keytab and destroys it again afterwards.
func (s *Server) renewKeytab(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.KeytabRenewRequest) *helperv1.HelperResponse {
	principal := strings.TrimSpace(action.GetPrincipal())
	// The same check the panel and the agent made: the principal reaches
	// argv as one argument, and the shape is the second line of defence.
	if err := opspec.ValidateServicePrincipal(principal); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	// The identity guard: the keytab is what SSSD and every Kerberos
	// client on the host read, and a join or a leave rewrites it.
	release, busy := s.hold(GuardIdentity, request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 2*time.Minute, 5*time.Minute)
	defer cancel()

	result := &helperv1.KeytabRenewResult{Principal: principal}
	// One listing answers both questions: which key version the service holds
	// now, and which host principal the helper may authenticate as.
	listing, listed := s.keytabListing(actionCtx)
	if before, known := highestKVNO(listing, principal); known {
		result.KvnoBeforeKnown = true
		result.KvnoBefore = before
	}

	hostPrincipal, hasHostKey := hostPrincipalIn(listing)
	if !hasHostKey {
		reason := hostKeytabPath + " lists no host principal, so the host has no key of its own to fetch with"
		if !listed {
			reason = "klist did not read " + hostKeytabPath + ", so the host's own key could not be found"
		}
		response := reject(ErrorHostKerberosKeyUnusable, reason)
		response.KeytabRenewResult = result
		return response
	}

	cache, discard, err := s.ticketCache()
	if err != nil {
		response := reject(ErrorHostKerberosKeyUnusable,
			"no credential cache of the helper's own for the fetch: "+err.Error())
		response.KeytabRenewResult = result
		return response
	}
	// Whatever happens below, a ticket taken from the host's own key does not
	// outlive the fetch it was taken for.
	defer discard()

	// KRB5CCNAME points every tool of this operation at that cache: ipa-getkeytab
	// takes no cache argument, and the default cache belongs to whoever is logged
	// in on the host.
	fetchCtx := withToolEnv(actionCtx, "KRB5CCNAME=FILE:"+cache)
	if _, stderr, err := s.tool()(fetchCtx, 60*time.Second,
		"kinit", "-k", "-t", hostKeytabPath, hostPrincipal); err != nil {
		response := reject(ErrorHostKerberosKeyUnusable,
			"kinit -k -t "+hostKeytabPath+" "+hostPrincipal+": "+firstLineOrError(err, stderr))
		response.Stderr = []byte(stderr)
		response.KeytabRenewResult = result
		return response
	}
	defer s.destroyTicket(fetchCtx)

	// ipa-getkeytab adds the new key to the file and leaves the older entries in
	// place, so a ticket issued under the old key still decrypts until it
	// expires; the directory alone retired the old key.
	if _, stderr, err := s.tool()(fetchCtx, timeLimit(request, 2*time.Minute, 5*time.Minute),
		"ipa-getkeytab", "-k", hostKeytabPath, "-p", principal); err != nil {
		response := reject(ErrorExecFailed, "ipa-getkeytab: "+firstLineOrError(err, stderr))
		response.Stderr = []byte(stderr)
		response.KeytabRenewResult = result
		return response
	}

	after, known := s.principalKVNO(actionCtx, principal)
	if !known {
		response := reject(ErrorExecFailed,
			"ipa-getkeytab returned, but "+hostKeytabPath+" lists no key for "+principal)
		response.KeytabRenewResult = result
		return response
	}
	result.KvnoAfter = after
	if result.KvnoBeforeKnown && after <= result.KvnoBefore {
		// The tool said nothing was wrong and the file says nothing changed: the
		// service still holds the key the directory retired, and reporting a success
		// would hide exactly that.
		response := reject(ErrorExecFailed,
			"ipa-getkeytab returned, but the key version of "+principal+" is still "+
				strconv.FormatUint(uint64(after), 10))
		response.KeytabRenewResult = result
		return response
	}

	s.log.Info("the service keytab was renewed", "task_id", request.GetTaskId(),
		"principal", principal, "host_principal", hostPrincipal,
		"kvno_before", result.KvnoBefore,
		"kvno_before_known", result.KvnoBeforeKnown, "kvno_after", result.KvnoAfter)
	return &helperv1.HelperResponse{Accepted: true, KeytabRenewResult: result}
}

// ticketCache makes a credential cache under a directory of its own and
// returns the path and the way to remove it. A cache under a fixed name could
// be a file somebody else put there first.
func (s *Server) ticketCache() (string, func(), error) {
	directory := s.ticketCacheDir
	if directory == "" {
		directory = defaultTicketCacheDir
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", nil, err
	}
	private, err := os.MkdirTemp(directory, "krb5cc-")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(private, "ccache"), func() { _ = os.RemoveAll(private) }, nil
}

// destroyTicket gives the ticket back with kdestroy. The cache is the
// helper's own, so this can reach no ticket of anybody else's.
func (s *Server) destroyTicket(ctx context.Context) {
	// The ticket goes even when the operation's own deadline has passed: a usable
	// ticket left behind is worse than one more tool run.
	if _, stderr, err := s.tool()(context.WithoutCancel(ctx), 15*time.Second, "kdestroy"); err != nil {
		s.log.Warn("the ticket of the keytab renewal was not given back",
			"err", err, "stderr", firstLineOf(stderr))
	}
}

// keytabListing reads the host's keytab with klist -k.
func (s *Server) keytabListing(ctx context.Context) (string, bool) {
	stdout, _, err := s.tool()(ctx, 15*time.Second, "klist", "-k", hostKeytabPath)
	if err != nil {
		return "", false
	}
	return stdout, true
}

// principalKVNO reads the highest key version number of a principal in the
// host's keytab from klist -k.
func (s *Server) principalKVNO(ctx context.Context, principal string) (uint32, bool) {
	listing, listed := s.keytabListing(ctx)
	if !listed {
		return 0, false
	}
	return highestKVNO(listing, principal)
}

// hostPrincipalIn takes the host's own principal out of a klist -k listing:
// the one key on the host the helper may authenticate as without asking
// anybody for a credential.
func hostPrincipalIn(listing string) (string, bool) {
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, err := strconv.ParseUint(fields[0], 10, 32); err != nil {
			continue
		}
		if strings.HasPrefix(strings.ToLower(fields[1]), "host/") {
			return fields[1], true
		}
	}
	return "", false
}

// firstLineOrError names what went wrong with a tool run: what it printed, or
// the error itself where it printed nothing - a missing tool says nothing on
// standard error.
func firstLineOrError(err error, stderr string) string {
	if strings.TrimSpace(stderr) != "" {
		return firstLineOf(stderr)
	}
	if err == nil {
		return "no details"
	}
	return err.Error()
}

// highestKVNO takes the highest key version of a principal out of a klist -k
// listing.
func highestKVNO(listing, principal string) (uint32, bool) {
	wanted := strings.ToLower(principal)
	name, _, hasRealm := strings.Cut(wanted, "@")
	var highest uint32
	found := false
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		listed := strings.ToLower(fields[1])
		if hasRealm {
			if listed != wanted {
				continue
			}
		} else if listedName, _, _ := strings.Cut(listed, "@"); listedName != name {
			continue
		}
		version, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		if !found || uint32(version) > highest {
			highest = uint32(version)
		}
		found = true
	}
	return highest, found
}
