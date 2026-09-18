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
	// Subject is the account whose entry the rights were read on. A
	// preflight that runs for an operation names that operation's account:
	// the rights of a service account come from a permission rather than
	// from the person, but an ACI can be written against a container or a
	// filter, and then the only conclusive answer is the one about the
	// entry the operation is actually about. Empty means the preflight ran
	// at startup and asked about a sample.
	Subject string `json:"subject,omitempty"`
	// Instruction is what an operator does about the first reason that
	// matters. It travels with the answer because the refusal the panel
	// shows has to say what lifts it, and a reason code alone does not.
	Instruction string `json:"instruction,omitempty"`
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
// It reads the rights on a sample account, because it has no operation to
// ask about: this is the preflight of a connector starting up and of the
// identity screen. An operation that has an account of its own asks
// CapabilitiesFor instead, and gets an answer about that entry.
func (c *Client) Capabilities(ctx context.Context) (DirectoryCapabilities, error) {
	return c.CapabilitiesFor(ctx, "")
}

// CapabilitiesFor asks the directory what it can do to one account's entry.
//
// Nothing here changes the directory: the preflight reads the answer to a
// ping, reads the container of preserved accounts, and reads the effective
// rights the directory reports on the entry the operation is about.
// Provisioning the ACI a service account needs is a separate, deliberate
// step - ProvisionPreserveRights - because an ordinary user operation must
// never widen its own permissions on the way to carrying itself out.
//
// The entry matters. An ACI is written against a container, a filter or a
// group as often as against the whole subtree, so the rights on an
// arbitrary account answer a different question from the rights on this
// one. Asking about the account the preserve names is what makes the
// answer conclusive where it can be: an empty directory and a directory
// that says nothing are then the only unknowns left, and both are reported
// as unknowns rather than passed off as permission.
func (c *Client) CapabilitiesFor(ctx context.Context, uid string) (DirectoryCapabilities, error) {
	capabilities := DirectoryCapabilities{
		CheckedAt:   time.Now().UTC(),
		ReasonCodes: []string{},
		Subject:     uid,
	}
	if _, err := c.Ping(ctx); err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonDirectoryUnreachable)
		capabilities.Instruction = instructionFor(ReasonDirectoryUnreachable)
		return capabilities, fmt.Errorf("the directory did not answer the preflight: %w", err)
	}

	// The container of preserved accounts answers for itself: a directory
	// that lists it has it, and one that refuses the search has nowhere to
	// move an entry to. The question is bounded on purpose and the answer is
	// read as bounded: a directory that already holds preserved accounts
	// marks such a search truncated, which says the container is there.
	if _, err := c.findProbe(ctx, "user_find",
		map[string]any{"preserved": true, "sizelimit": 1}); err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonPreserveContainerMissing)
	}

	if _, err := c.Zones(ctx); err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonDNSUnreadable)
	} else {
		capabilities.DNSRecordWrite = true
	}

	rights, err := c.entryRights(ctx, uid)
	if err != nil {
		capabilities.ReasonCodes = append(capabilities.ReasonCodes, ReasonNoEntryToCheck)
		capabilities.Instruction = instructionFor(ReasonNoEntryToCheck)
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
	capabilities.Instruction = capabilities.instruction()
	return capabilities, nil
}

// instruction picks the one thing an operator would do about this answer:
// what blocks comes first, then what is merely unproven.
func (c DirectoryCapabilities) instruction() string {
	if reason, blocked := c.PreserveBlocked(); blocked {
		return instructionFor(reason)
	}
	for _, reason := range []string{ReasonModDNRightsUnknown, ReasonNoEntryToCheck, ReasonDNSUnreadable} {
		if c.Has(reason) {
			return instructionFor(reason)
		}
	}
	return ""
}

// instructionFor says what lifts a reason. Every refusal the panel shows
// carries one of these, because a code an operator cannot act on is only
// half an answer.
func instructionFor(reason string) string {
	switch reason {
	case ReasonModDNNotPermitted:
		return "the directory reports that the connector's service account may not move an entry: " +
			ProvisioningInstruction()
	case ReasonModDNRightsUnknown:
		return "the directory does not report entry level rights, so the move is neither proven nor refused. " +
			"The preserve asks the directory first and touches nothing locally until it confirms; " +
			"if the directory refuses the move, " + ProvisioningInstruction()
	case ReasonPreserveContainerMissing:
		return "the container of preserved accounts could not be read. Check that the directory has " +
			"cn=deleted users,cn=accounts,cn=provisioning under its base and that the connector may search it."
	case ReasonDirectoryUnreachable:
		return "the directory did not answer. Check the connector on the identity screen - " +
			"the keytab, the KDC and the directory itself - before ordering anything."
	case ReasonNoEntryToCheck:
		return "there was no entry to read the rights on, so nothing about the move was proven either way. " +
			"It answers itself once the directory holds the account the operation names."
	case ReasonDNSUnreadable:
		return "the DNS zones could not be listed; the connector's service account may not read them."
	default:
		return ""
	}
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

// entryRights reads the effective rights of the connector on one account.
//
// A named account is read as it stands: that is the entry the operation
// will move, and the directory's answer about it is the answer that
// decides. Without a name the preflight takes a sample - the rights of a
// service account come from a permission and a role rather than from the
// person, so a sample answers the general question a startup check asks -
// and a directory that holds no account at all leaves the question open
// rather than answered.
func (c *Client) entryRights(ctx context.Context, uid string) (effectiveRights, error) {
	if uid == "" {
		sample, err := c.sampleAccount(ctx)
		if err != nil {
			return effectiveRights{}, err
		}
		uid = sample
	}
	if !userNamePattern.MatchString(uid) {
		return effectiveRights{}, fmt.Errorf("invalid account name %q", uid)
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

// sampleAccount names one account of the directory, for a preflight that
// has no operation to ask about. The search is deliberately bounded and the
// directory's truncation flag is the expected answer to it, not a failure:
// asking for one account and being told the list was cut short is the
// directory saying there is at least one.
func (c *Client) sampleAccount(ctx context.Context) (string, error) {
	records, err := c.findProbe(ctx, "user_find", map[string]any{"sizelimit": 1})
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", errors.New("the directory holds no account to read the rights on")
	}
	uid := first(records[0], "uid")
	if uid == "" {
		return "", errors.New("the directory returned an account without a name")
	}
	return uid, nil
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

// The three values a plan can bind to, spelled for a person reading a plan
// or a refusal.
const (
	bindingDN        = "the distinguished name"
	bindingUUID      = "the unique identifier"
	bindingTimestamp = "the modify timestamp"
)

// BoundTo names the values the plan recorded and the execution will check,
// in the order they are checked.
func (e EntryReference) BoundTo() []string {
	var bound []string
	if e.DN != "" {
		bound = append(bound, bindingDN)
	}
	if e.EntryUUID != "" {
		bound = append(bound, bindingUUID)
	}
	if e.ModifyTimestamp != "" {
		bound = append(bound, bindingTimestamp)
	}
	return bound
}

// Unbound names the values this plan has nothing to check, because the
// directory did not report them when the plan was made.
func (e EntryReference) Unbound() []string {
	var missing []string
	if e.DN == "" {
		missing = append(missing, bindingDN)
	}
	if e.EntryUUID == "" {
		missing = append(missing, bindingUUID)
	}
	if e.ModifyTimestamp == "" {
		missing = append(missing, bindingTimestamp)
	}
	return missing
}

// Binding is the sentence the plan and the phase carry: which of the three
// values this plan is bound to, and which the directory does not report.
//
// It is said out loud rather than left to be inferred, because the strength
// of the check differs between deployments: a directory that reports no
// modify timestamp cannot tell an entry somebody edited between the plan
// and the approval from one nobody touched, and an operator approving the
// change is entitled to know that. What is not reported is not invented.
func (e EntryReference) Binding() string {
	bound := e.BoundTo()
	if len(bound) == 0 {
		return "the plan names no value of the entry to bind to"
	}
	sentence := "bound to " + joinNames(bound)
	if missing := e.Unbound(); len(missing) > 0 {
		sentence += "; the directory does not report " + joinNames(missing)
	}
	return sentence
}

// joinNames writes a list the way a sentence does.
func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

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
