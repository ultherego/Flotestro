package helper

import (
	"context"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// hostKeytabPath is the one keytab the renewal writes into: the host's
// own. The request names no path, so a renewal cannot be pointed at a
// file a service reads that the panel does not manage.
const hostKeytabPath = "/etc/krb5.keytab"

// renewKeytab fetches a new key of a service principal into the host's
// keytab with ipa-getkeytab, authenticated with the host's own keytab (-k
// on a joined host makes the tool take the host credential the way kinit
// -k does; readHostKeytab reads that same file for the probe). The
// directory has already retired the old key, so this fetch is the only
// thing that brings the service back - and the proof it did is the key
// version number of the principal going up in klist -k, read before and
// after. The number before is reported as unknown, not zero, when the
// listing could not be read: a fresh principal has no entry, and that is a
// different fact from a listing that failed.
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
	if before, known := s.principalKVNO(actionCtx, principal); known {
		result.KvnoBeforeKnown = true
		result.KvnoBefore = before
	}

	// ipa-getkeytab adds the new key to the file and leaves the older
	// entries in place, so a ticket issued under the old key still
	// decrypts until it expires; the directory alone retired the old key.
	// The runner is the lenient one, which forgives a non-zero exit: the
	// verdict here is not the exit code but the key version read below,
	// and a fetch that failed leaves the version where it was.
	if _, stderr, err := s.tool()(actionCtx, timeLimit(request, 2*time.Minute, 5*time.Minute),
		"ipa-getkeytab", "-k", hostKeytabPath, "-p", principal); err != nil {
		response := reject(ErrorExecFailed, "ipa-getkeytab: "+firstLineOf(stderr))
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
		// The tool said nothing was wrong and the file says nothing
		// changed: the service still holds the key the directory retired,
		// and reporting a success would hide exactly that.
		response := reject(ErrorExecFailed,
			"ipa-getkeytab returned, but the key version of "+principal+" is still "+
				strconv.FormatUint(uint64(after), 10))
		response.KeytabRenewResult = result
		return response
	}

	s.log.Info("the service keytab was renewed", "task_id", request.GetTaskId(),
		"principal", principal, "kvno_before", result.KvnoBefore,
		"kvno_before_known", result.KvnoBeforeKnown, "kvno_after", result.KvnoAfter)
	return &helperv1.HelperResponse{Accepted: true, KeytabRenewResult: result}
}

// principalKVNO reads the highest key version number of a principal in the
// host's keytab from klist -k. The second value says whether a number was
// read at all: no entry, no file and a listing that failed all come back
// as not known, because the caller compares versions and a zero it did not
// read would compare like a real one.
func (s *Server) principalKVNO(ctx context.Context, principal string) (uint32, bool) {
	stdout, _, err := s.tool()(ctx, 15*time.Second, "klist", "-k", hostKeytabPath)
	if err != nil {
		return 0, false
	}
	return highestKVNO(stdout, principal)
}

// highestKVNO takes the highest key version of a principal out of a klist
// -k listing. The listing names one entry per key, "KVNO Principal", and
// a principal with several keys - one per encryption type, or the old and
// the new one side by side - is listed once per key. The realm is part of
// the name the listing prints, so a request without one matches the name
// before the at sign.
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
