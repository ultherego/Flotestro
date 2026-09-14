package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/identity"
	"github.com/ultherego/flotestro/internal/modules/sudoers"
)

// The effective access: who may enter a host and with what privileges. The
// panel reads the directory's rules and projects them onto one host; the
// verdict for a concrete user comes from the directory's own simulation, so
// the answer is the one the host will apply rather than a reconstruction.

// handleSimulateAccess asks the directory whether a user may use a service
// on a host. It reads and changes nothing, so it needs the policy read
// permission and no plan.
func (s *Server) handleSimulateAccess(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityPolicyRead, authz.GlobalScope, "identity", "access-simulate"); !ok {
		return
	}
	if s.directory == nil {
		problem(w, http.StatusNotImplemented, "directory_disabled",
			"no directory connector is configured")
		return
	}

	var request struct {
		User    string `json:"user"`
		Host    string `json:"host"`
		Service string `json:"service"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	request.User = strings.TrimSpace(request.User)
	request.Host = strings.TrimSpace(request.Host)
	request.Service = strings.TrimSpace(request.Service)
	if request.User == "" || request.Host == "" {
		problem(w, http.StatusBadRequest, "invalid_body", "the simulation requires a user and a host")
		return
	}
	if request.Service == "" {
		// Signing in over SSH is what the question is about nearly always.
		request.Service = "sshd"
	}

	result, err := s.directory.HBACTest(r.Context(), request.User, request.Host, request.Service)
	if err != nil {
		if strings.Contains(err.Error(), "invalid") {
			problem(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
		// A directory failure is a state, not an internal panel error.
		problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// hostAccessView is the effective access of one host: the directory's
// projection and the local sudo policy side by side. The two halves are
// independent - a directory the panel cannot reach says nothing about
// what /etc/sudoers grants - so each says on its own whether it is known.
type hostAccessView struct {
	identity.HostAccess
	Directory directoryState `json:"directory"`
	// LocalSudoers is the state of the local policy: whether the helper
	// read it, when, and from which files.
	LocalSudoers localSudoersState `json:"local_sudoers"`
	// LocalSudoRules are the rules of the local files, each with whether
	// it reaches this host and whom it reaches.
	LocalSudoRules []localSudoRule `json:"local_sudo_rules"`
	// RootEquivalentWarnings is one sentence per local grant that makes
	// somebody root on this host.
	RootEquivalentWarnings []string `json:"root_equivalent_warnings"`
}

// directoryState says whether the directory's half of the view was read.
type directoryState struct {
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Error      string `json:"error,omitempty"`
}

// localSudoersState is the state of the sudoers fragment of the host.
type localSudoersState struct {
	// Read says whether the policy is known. False with a reason is a
	// policy the panel does not know, never a host without sudo.
	Read       bool              `json:"read"`
	Reason     string            `json:"reason,omitempty"`
	ObservedAt *time.Time        `json:"observed_at,omitempty"`
	Revision   string            `json:"revision,omitempty"`
	Files      []sudoers.File    `json:"files,omitempty"`
	Problems   []sudoers.Problem `json:"problems,omitempty"`
	// PasswordlessGlobally marks a global "Defaults !authenticate": every
	// rule is then passwordless, whatever its tags say.
	PasswordlessGlobally bool `json:"passwordless_globally"`
}

// localSudoRule is a local rule together with the way it reaches this
// host and the accounts it reaches, resolved through the local groups.
type localSudoRule struct {
	sudoers.Rule
	// Via says how the rule reaches the host: by covering every host or
	// by naming it. Empty when the rule names other hosts.
	Via         []string `json:"via"`
	ReachesHost bool     `json:"reaches_host"`
	// ReachedUsers are the local accounts the rule's groups and ids
	// resolve to. A netgroup or a name the host does not know stays
	// unresolved and is not in the list.
	ReachedUsers []string `json:"reached_users,omitempty"`
}

// handleHostAccess returns the effective access of one host: its host
// groups and the access and sudo rules that reach it from the directory,
// and the local sudo rules next to them. The directory projection is
// computed from the same short-lived directory reads as the other
// directory views, so it is as fresh as they are and no fresher; the
// local rules come from the inventory the helper read.
func (s *Server) handleHostAccess(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, scope, "host", hostID); !ok {
		return
	}

	view := hostAccessView{
		HostAccess: identity.HostAccess{
			Hostname:   host.Hostname,
			HostGroups: []string{},
			HBACRules:  []identity.HBACAccess{},
			SudoRules:  []identity.SudoAccess{},
		},
		LocalSudoRules:         []localSudoRule{},
		RootEquivalentWarnings: []string{},
	}
	switch {
	case s.directory == nil:
		// No connector is a state of the installation, not an error of the
		// request: the local half is still worth showing.
		view.Detail = "no directory connector is configured; the directory's rules are unknown"
	default:
		view.Directory.Configured = true
		access, err := identity.EffectiveAccess(r.Context(), s.directory, host.Hostname, host.Identity.Domain)
		if err != nil {
			// A directory failure is a state, not an internal panel error,
			// and it does not make the local rules unknown.
			view.Directory.Error = err.Error()
			view.Detail = "the directory did not answer: " + err.Error()
		} else {
			view.Directory.Reachable = true
			view.HostAccess = access
		}
	}
	if err := s.mergeLocalSudoers(r.Context(), host, &view); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// mergeLocalSudoers lays the local sudo policy of the host over the view.
// The rules come from the sudoers fragment, the accounts they reach from
// the accounts fragment; a fragment the host has not sent leaves the
// local half unknown with its reason.
func (s *Server) mergeLocalSudoers(ctx context.Context, host *hosts.Host, view *hostAccessView) error {
	fragment, err := s.inventory.Fragment(ctx, host.ID, "sudoers")
	if err != nil {
		return err
	}
	switch {
	case fragment == nil:
		view.LocalSudoers.Reason = "the host has not reported its sudo policy; an agent from before the sudoers module sends none"
		return nil
	case fragment.UnavailableReason != "":
		observed := fragment.ObservedAt
		view.LocalSudoers.Reason = fragment.UnavailableReason
		view.LocalSudoers.ObservedAt = &observed
		view.LocalSudoers.Revision = fragment.Revision
		return nil
	}
	var policy sudoers.Snapshot
	if err := json.Unmarshal(fragment.Payload, &policy); err != nil {
		view.LocalSudoers.Reason = "the sudo policy the host sent could not be read: " + err.Error()
		return nil
	}
	observed := fragment.ObservedAt
	view.LocalSudoers = localSudoersState{
		Read: true, ObservedAt: &observed, Revision: fragment.Revision,
		Files: policy.Files, Problems: policy.Problems,
		PasswordlessGlobally: policy.PasswordlessGlobally(),
	}

	accounts, err := s.localAccountsOf(ctx, host.ID)
	if err != nil {
		return err
	}
	for _, rule := range policy.Rules {
		local := localSudoRule{Rule: rule, Via: []string{}}
		local.Via = localRuleVia(rule, host.Hostname, host.Identity.Domain)
		local.ReachesHost = len(local.Via) > 0
		local.ReachedUsers = reachedAccounts(rule, accounts)
		view.LocalSudoRules = append(view.LocalSudoRules, local)
		if rule.RootEquivalent && local.ReachesHost {
			view.RootEquivalentWarnings = append(view.RootEquivalentWarnings,
				rootEquivalentWarning(rule, view.LocalSudoers.PasswordlessGlobally))
		}
	}
	return nil
}

// localAccount is what the accounts fragment says about one account, as
// far as resolving a sudo rule needs it.
type localAccount struct {
	Name   string   `json:"name"`
	UID    int64    `json:"uid"`
	GID    int64    `json:"gid"`
	Groups []string `json:"groups"`
}

// localAccountsOf reads the accounts of the host from its inventory. A
// host without the fragment resolves no group: the rules are still shown,
// with their grantees as written.
func (s *Server) localAccountsOf(ctx context.Context, hostID string) ([]localAccount, error) {
	fragment, err := s.inventory.Fragment(ctx, hostID, "accounts")
	if err != nil || fragment == nil || len(fragment.Payload) == 0 {
		return nil, err
	}
	var content struct {
		Accounts []localAccount `json:"accounts"`
	}
	if err := json.Unmarshal(fragment.Payload, &content); err != nil {
		// A fragment the panel cannot read is no reason to refuse the view;
		// the rules simply resolve no group.
		return nil, nil
	}
	return content.Accounts, nil
}

// localRuleVia says how a local rule reaches the host: by covering every
// host, or by naming it by its short name or its FQDN. A rule that names
// only other hosts, a netgroup or a network does not reach it as far as
// the panel can tell.
func localRuleVia(rule sudoers.Rule, hostname, domain string) []string {
	via := []string{}
	short := strings.ToLower(strings.TrimSuffix(hostname, "."))
	fqdn := short
	if !strings.Contains(short, ".") && domain != "" {
		fqdn = short + "." + strings.ToLower(strings.TrimSuffix(domain, "."))
	}
	for _, entry := range rule.Hosts {
		if strings.HasPrefix(entry, "!") {
			continue
		}
		candidate := strings.ToLower(entry)
		switch {
		case candidate == "all":
			via = append(via, "every host")
		case candidate == short, candidate == fqdn:
			via = append(via, "host "+entry)
		}
	}
	return via
}

// reachedAccounts resolves the grantees of a rule through the accounts of
// the host: a group to its members, a gid or a uid to the account that
// has it, a name to itself. A negated grantee takes its accounts out.
func reachedAccounts(rule sudoers.Rule, accounts []localAccount) []string {
	if len(accounts) == 0 {
		return nil
	}
	reached := map[string]bool{}
	resolve := func(grantee string) []string {
		switch {
		case grantee == "ALL":
			names := make([]string, 0, len(accounts))
			for _, account := range accounts {
				names = append(names, account.Name)
			}
			return names
		case strings.HasPrefix(grantee, "%#"):
			gid, err := strconv.ParseInt(grantee[2:], 10, 64)
			if err != nil {
				return nil
			}
			var names []string
			for _, account := range accounts {
				if account.GID == gid {
					names = append(names, account.Name)
				}
			}
			return names
		case strings.HasPrefix(grantee, "%"):
			var names []string
			for _, account := range accounts {
				if slices.Contains(account.Groups, grantee[1:]) {
					names = append(names, account.Name)
				}
			}
			return names
		case strings.HasPrefix(grantee, "#"):
			uid, err := strconv.ParseInt(grantee[1:], 10, 64)
			if err != nil {
				return nil
			}
			for _, account := range accounts {
				if account.UID == uid {
					return []string{account.Name}
				}
			}
			return nil
		case strings.HasPrefix(grantee, "+"):
			// A netgroup lives in the directory or in NIS; the host's own
			// account list does not say who is in it.
			return nil
		}
		return []string{grantee}
	}
	for _, grantee := range rule.Users {
		if strings.HasPrefix(grantee, "!") {
			continue
		}
		for _, name := range resolve(grantee) {
			reached[name] = true
		}
	}
	for _, grantee := range rule.Users {
		if !strings.HasPrefix(grantee, "!") {
			continue
		}
		for _, name := range resolve(grantee[1:]) {
			delete(reached, name)
		}
	}
	names := make([]string, 0, len(reached))
	for name := range reached {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// rootEquivalentWarning puts one root-equivalent grant into a sentence
// with the file and line it comes from, so the operator can go and read
// it.
func rootEquivalentWarning(rule sudoers.Rule, passwordlessGlobally bool) string {
	who := strings.Join(rule.Users, ", ")
	how := "every command as root"
	if len(rule.CriticalReasons) > 0 {
		how = rule.CriticalReasons[0]
	}
	sentence := who + " may run " + how
	switch {
	case rule.NoPasswd:
		sentence += " without a password"
	case passwordlessGlobally:
		sentence += " without a password (a global Defaults line turns authentication off)"
	}
	return fmt.Sprintf("%s (%s:%d)", sentence, rule.Source, rule.Line)
}
