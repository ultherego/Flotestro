package adminapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
)

// Who may sign in to this panel, and where each one's access comes from.
//
// The identities screen answers a narrower question than it looks like it
// answers: it lists the identities the panel has a record of, and a person
// gets a record on their first sign-in. So somebody in a directory group that
// a mapping grants a role to has access and is not on that list, which is
// exactly what the owner found on 15.10 - his directory account held a role
// through a group and the screen showed him rows of leftovers instead.
//
// This joins the three places access comes from: the bindings written by
// hand, the mappings of the identity provider's groups, and the directory's
// own membership. What it cannot read it says it cannot read; a directory
// that will not answer is not a directory with nobody in it.

// holderRole is one role somebody holds, and where it comes from.
type holderRole struct {
	Role  string `json:"role"`
	Scope string `json:"scope"`
	// From is "binding" for a role bound to the identity by hand, or
	// "group" for one a mapping grants; Group names it in the second case.
	From  string `json:"from"`
	Group string `json:"group,omitempty"`
}

// accessHolder is one person or service that may sign in.
type accessHolder struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name,omitempty"`
	Kind        string `json:"kind"`
	// PrincipalID is empty for somebody the panel has never seen: the
	// directory lets them in, and the record is made at their first sign-in.
	PrincipalID string `json:"principal_id,omitempty"`
	// SignedIn says whether the panel has a record of them at all.
	SignedIn bool `json:"signed_in"`
	// Groups are the directory groups of theirs that a mapping names. The
	// groups that grant nothing are left out: this screen is about access.
	Groups []string `json:"groups,omitempty"`
	// DirectoryDisabled is the directory's own lock on the account.
	DirectoryDisabled bool         `json:"directory_disabled,omitempty"`
	Roles             []holderRole `json:"roles"`
}

// directoryReading says what the directory side of the answer is worth.
type directoryReading struct {
	Configured bool   `json:"configured"`
	Read       bool   `json:"read"`
	Reason     string `json:"reason,omitempty"`
	Users      int    `json:"users,omitempty"`
}

// handleAccessHolders answers who may sign in and where their access comes
// from.
func (s *Server) handleAccessHolders(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", ""); !ok {
		return
	}

	mappings, err := s.authz.ListGroupMappings(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	// A group may grant several roles, and the comparison is case-insensitive
	// because a directory and a token spell a group's name as they please.
	byGroup := map[string][]authz.GroupMapping{}
	for _, mapping := range mappings {
		key := strings.ToLower(mapping.GroupName)
		byGroup[key] = append(byGroup[key], mapping)
	}

	principals, err := s.authz.AllPrincipals(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}

	holders := map[string]*accessHolder{}
	keyOf := func(subject string) string { return strings.ToLower(subject) }

	// Every binding of every identity, in one query rather than one each.
	bindingsOf, err := s.authz.BindingsOfMany(r.Context(), principalIDs(principals))
	if err != nil {
		s.fail(w, err)
		return
	}

	// What the panel has a record of, with the roles bound to it by hand.
	for _, principal := range principals {
		bindings := bindingsOf[principal.ID]
		holder := &accessHolder{
			Subject: principal.Subject, DisplayName: principal.DisplayName,
			Kind: principal.Kind, PrincipalID: principal.ID, SignedIn: true,
			Roles: []holderRole{},
		}
		for _, binding := range bindings {
			holder.Roles = append(holder.Roles, holderRole{
				Role: string(binding.Role), Scope: binding.Scope.String(), From: "binding",
			})
		}
		holders[keyOf(principal.Subject)] = holder
	}

	// What the directory would let in. A user is here only if one of their
	// groups is mapped to a role: the directory holds accounts that have
	// nothing to do with this panel.
	reading := directoryReading{Configured: s.directory != nil}
	if s.directory != nil && len(byGroup) > 0 {
		users, err := s.directory.Users(r.Context())
		if err != nil {
			// Not an empty answer: the directory side is unknown, and the
			// screen says so rather than showing the panel's own records as
			// though they were the whole of it.
			reading.Reason = err.Error()
		} else {
			reading.Read = true
			reading.Users = len(users)
			for _, user := range users {
				granted := []holderRole{}
				matched := []string{}
				for _, group := range user.Groups {
					for _, mapping := range byGroup[strings.ToLower(group)] {
						granted = append(granted, holderRole{
							Role: string(mapping.Role),
							Scope: authz.PlacementWithin(mapping.Site, mapping.Environment,
								mapping.Owners, mapping.Tags).String(),
							From: "group", Group: group,
						})
					}
					if len(byGroup[strings.ToLower(group)]) > 0 {
						matched = append(matched, group)
					}
				}
				if len(granted) == 0 {
					continue
				}
				holder, known := holders[keyOf(user.UID)]
				if !known {
					holder = &accessHolder{
						Subject: user.UID, Kind: "user", SignedIn: false, Roles: []holderRole{},
					}
					holders[keyOf(user.UID)] = holder
				}
				if holder.DisplayName == "" {
					holder.DisplayName = user.DisplayName
				}
				holder.DirectoryDisabled = user.Disabled
				holder.Groups = append(holder.Groups, matched...)
				holder.Roles = append(holder.Roles, granted...)
			}
		}
	}

	items := make([]accessHolder, 0, len(holders))
	for _, holder := range holders {
		// Somebody with no role at all is not a holder of access: a record of
		// a sign-in that carries nothing belongs on the identities list, not
		// on the answer to "who may do something here".
		if len(holder.Roles) == 0 {
			continue
		}
		sort.Slice(holder.Roles, func(i, j int) bool {
			if holder.Roles[i].Role != holder.Roles[j].Role {
				return holder.Roles[i].Role < holder.Roles[j].Role
			}
			return holder.Roles[i].Scope < holder.Roles[j].Scope
		})
		items = append(items, *holder)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Subject < items[j].Subject })

	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items), "directory": reading,
	})
}
