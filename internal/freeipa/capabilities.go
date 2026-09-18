package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The reasons a capability could not be confirmed. They are codes rather than
// sentences because the panel blocks an operation on them and an operator
// looks them up: a preserve that the directory would refuse has to be
// refused before the local account is touched, and the reason has to say
// which of the several causes it was.
const (
	// ReasonDirectoryUnreachable: the directory did not answer at all, so
	// nothing about it was verified.
	ReasonDirectoryUnreachable = "directory_unreachable"
	// ReasonPreserveContainerMissing: the container the directory moves a
	// preserved account into is not there or cannot be read. A preserve
	// would have nowhere to move the entry to.
	ReasonPreserveContainerMissing = "preserve_container_missing"
	// ReasonModDNNotPermitted: the directory reported its effective rights
	// and the connector's service account may not move an entry. This is
	// the case the document names: the operation is blocked and the
	// installation gives the service account the minimal ACI for it.
	ReasonModDNNotPermitted = "moddn_not_permitted"
	// ReasonModDNRightsUnknown: the directory did not report entry level
	// rights, so whether the move is allowed could not be proven either
	// way. It is not a permission and it is not a refusal - it is a fact
	// about what this directory tells its clients.
	ReasonModDNRightsUnknown = "moddn_rights_unknown"
	// ReasonNoEntryToCheck: the directory holds no account the rights could
	// be read on, so the preflight had nothing to ask about.
	ReasonNoEntryToCheck = "no_entry_to_check_rights_on"
	// ReasonDNSUnreadable: the DNS zones could not be listed.
	ReasonDNSUnreadable = "dns_zones_unreadable"
)

// DirectoryCapabilities is what the connector verified the directory can do
// for it, and what it could not verify.
//
// Every field is a statement the preflight actually established by reading:
// the connector reached the object and the directory reported the right where
// it reports rights at all. A field left false with a reason beside it is an
// unknown rather than a denial, and the two are told apart by the reason
// codes - never by the bare false, which would turn "the directory does not
// say" into "the directory says no".
type DirectoryCapabilities struct {
	UserCreate     bool      `json:"user_create"`
	UserDisable    bool      `json:"user_disable"`
	UserModDN      bool      `json:"user_moddn"`
	DNSRecordWrite bool      `json:"dns_record_write"`
	CheckedAt      time.Time `json:"checked_at"`
	ReasonCodes    []string  `json:"reason_codes"`
}

// Has says whether the preflight recorded the given reason.
func (c DirectoryCapabilities) Has(reason string) bool {
	for _, code := range c.ReasonCodes {
		if code == reason {
			return true
		}
	}
	return false
}

// PreserveBlocked names the reason a preserve must not be started, or says
// there is none.
//
// Only a proven impediment blocks: a directory nobody could reach, a missing
// preserve container, or a directory that reported its rights and said no.
// Rights the directory does not report are carried in the reason codes and do
// not block, because the operation now asks the directory first and touches
// the local account only after the directory confirmed - a refusal there
// leaves the account exactly as it was, which is the protection an
// unverifiable ACI would otherwise have to provide.
func (c DirectoryCapabilities) PreserveBlocked() (string, bool) {
	for _, reason := range []string{
		ReasonDirectoryUnreachable,
		ReasonPreserveContainerMissing,
		ReasonModDNNotPermitted,
	} {
		if c.Has(reason) {
			return reason, true
		}
	}
	return "", false
}

// Capabilities asks the directory what it can do before anything is ordered.
//
// Nothing here changes the directory: the preflight reads the answer to a
// ping, reads the container of preserved accounts, and reads the effective
// rights the directory reports on an existing account. Provisioning the ACI
// a service account needs is a separate, deliberate step of the installation
// - an ordinary user operation must never widen its own permissions on the
// way to carrying itself out.
func (c *Client) Capabilities(ctx context.Context) (DirectoryCapabilities, error) {
	capabilities := DirectoryCapabilities{CheckedAt: time.Now().UTC(), ReasonCodes: []string{}}
	if _, err := c.Ping(ctx); err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonDirectoryUnreachable)
		return capabilities, fmt.Errorf("the directory did not answer the preflight: %w", err)
	}

	// The container of preserved accounts answers for itself: a directory
	// that lists it has it, and one that refuses the search has nowhere to
	// move an entry to.
	if _, err := c.findWith(ctx, "user_find",
		map[string]any{"preserved": true, "sizelimit": 1}); err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonPreserveContainerMissing)
	}

	if _, err := c.Zones(ctx); err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonDNSUnreadable)
	} else {
		capabilities.DNSRecordWrite = true
	}

	rights, err := c.entryRights(ctx)
	if err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonNoEntryToCheck)
		return capabilities, nil
	}
	capabilities.UserCreate = strings.Contains(rights.entry, "a")
	capabilities.UserDisable = strings.Contains(rights.attribute("nsaccountlock"), "w")
	switch {
	case rights.entry == "":
		// The directory answered but said nothing about the entry itself.
		// That is an unknown, and it is recorded as one.
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonModDNRightsUnknown)
	case strings.Contains(rights.entry, "n"):
		// n is the rename right in the directory's own notation: moving an
		// entry into the container of preserved accounts is a rename.
		capabilities.UserModDN = true
	default:
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonModDNNotPermitted)
	}
	return capabilities, nil
}

// effectiveRights is what the directory reports about what the connector may
// do: letters per attribute and, where the directory reports them, letters
// for the entry as a whole.
type effectiveRights struct {
	entry      string
	attributes map[string]string
}

func (r effectiveRights) attribute(name string) string {
	return r.attributes[strings.ToLower(name)]
}

// entryRights reads the effective rights of the connector on one existing
// account. The account is only a sample: the rights of a service account are
// granted by permission and role rather than per person, so any entry of the
// kind answers the question.
func (c *Client) entryRights(ctx context.Context) (effectiveRights, error) {
	records, err := c.findOptions(ctx, "user_find", false, map[string]any{"sizelimit": 1})
	if err != nil {
		return effectiveRights{}, err
	}
	if len(records) == 0 {
		return effectiveRights{}, errors.New("the directory holds no account to read the rights on")
	}
	uid := first(records[0], "uid")
	if uid == "" {
		return effectiveRights{}, errors.New("the directory returned an account without a name")
	}
	result, err := c.call(ctx, "user_show", []string{uid},
		map[string]any{"all": true, "rights": true})
	if err != nil {
		return effectiveRights{}, err
	}
	var decoded struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return effectiveRights{}, err
	}
	return readRights(decoded.Result), nil
}

// readRights pulls the rights out of the directory's answer.
//
// The directory returns the per-attribute rights as a map and the rights on
// the entry - the ones that decide a move - only on some deployments and only
// under a name of its own. Both spellings are read, and a deployment that
// reports neither leaves the entry rights empty, which the caller treats as
// an unknown rather than as a refusal.
func readRights(record map[string]any) effectiveRights {
	rights := effectiveRights{attributes: map[string]string{}}
	if values, ok := lookup(record, "attributelevelrights").(map[string]any); ok {
		for name, value := range values {
			if text, ok := value.(string); ok {
				rights.attributes[strings.ToLower(name)] = text
			}
		}
	}
	rights.entry = first(record, "entrylevelrights")
	if rights.entry == "" {
		if text, ok := rights.attributes["entrylevelrights"]; ok {
			rights.entry = text
		}
	}
	return rights
}

// ErrEntryNotFound means the directory no longer holds the entry under the
// name the plan was made for. For a preserve that is not an error of the
// connector: somebody removed or preserved the account in the meantime.
var ErrEntryNotFound = errors.New("the directory no longer holds the entry")

// EntryReference identifies one directory entry as it stood when the plan was
// made: where it is, which entry it is, and when it last changed.
//
// The three answer three different questions. The DN says the entry has not
// been moved - a preserved account sits in another container, so a second
// preserve of the same user cannot pass this. The unique identifier says it
// is the same entry rather than a new account of the same name. The modify
// timestamp says nobody changed it between the plan and the execution.
type EntryReference struct {
	DN              string `json:"dn"`
	EntryUUID       string `json:"entry_uuid,omitempty"`
	ModifyTimestamp string `json:"modify_timestamp,omitempty"`
}

// Complete says whether the reference names the entry well enough to be
// bound to. A reference without a DN names nothing.
func (e EntryReference) Complete() bool { return e.DN != "" }

// Moved compares the reference the plan recorded with the entry as the
// directory holds it now and names the first value that differs.
//
// A value the plan recorded and the directory no longer reports counts as a
// difference: not being told is not the same as being told it is unchanged,
// and an execution that treated the two alike would carry out a plan made
// against something it can no longer see.
func (e EntryReference) Moved(now EntryReference) (string, bool) {
	if !strings.EqualFold(e.DN, now.DN) {
		return "the entry is at " + now.DN + " and the plan named " + e.DN, true
	}
	if e.EntryUUID != "" && e.EntryUUID != now.EntryUUID {
		return "the entry has the identifier " + now.EntryUUID +
			" and the plan named " + e.EntryUUID, true
	}
	if e.ModifyTimestamp != "" && e.ModifyTimestamp != now.ModifyTimestamp {
		return "the entry was last changed at " + now.ModifyTimestamp +
			" and the plan named " + e.ModifyTimestamp, true
	}
	return "", false
}

// UserEntry reads the identity of an account's entry: its DN, its unique
// identifier and the moment it last changed.
//
// The read is the friendly one with every attribute asked for. What the
// directory does not report is left empty rather than invented; the plan then
// binds to what there is, and the comparison refuses on whatever the
// directory does report.
func (c *Client) UserEntry(ctx context.Context, uid string) (EntryReference, error) {
	if !userNamePattern.MatchString(uid) {
		return EntryReference{}, fmt.Errorf("invalid account name %q", uid)
	}
	result, err := c.call(ctx, "user_show", []string{uid}, map[string]any{"all": true})
	if err != nil {
		var refusal *DirectoryError
		if errors.As(err, &refusal) && refusal.Name == "NotFound" {
			return EntryReference{}, fmt.Errorf("%w: %s", ErrEntryNotFound, uid)
		}
		return EntryReference{}, err
	}
	var decoded struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return EntryReference{}, err
	}
	return entryFromRecord(decoded.Result), nil
}

// entryFromRecord reads the identity of an entry out of a directory record.
// The directory writes its unique identifier under one of two names
// depending on the object, and the search view returns the DN beside the
// attributes rather than among them.
func entryFromRecord(record map[string]any) EntryReference {
	entry := EntryReference{
		DN:              first(record, "dn"),
		EntryUUID:       first(record, "ipauniqueid"),
		ModifyTimestamp: first(record, "modifytimestamp"),
	}
	if entry.EntryUUID == "" {
		entry.EntryUUID = first(record, "entryuuid")
	}
	return entry
}
