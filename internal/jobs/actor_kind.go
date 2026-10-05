package jobs

// ActorKind says what ordered a task: a person, or the panel's own machinery.
//
// It exists because the alternative is reading it off the author's name, and
// that inference was wrong in both directions within one day. Reading the
// absence of an account as "the panel's own" let a blocked operator's queued
// work leave with a signed capability; reading it as "blocked" would have
// stopped every campaign. A prefix list written afterwards carried three
// prefixes nobody writes and missed two that are - and a name is something an
// identity could be given, while this is not.
type ActorKind string

const (
	// ActorUnknown is the zero value: a task written before this column
	// existed, or by a caller that did not say. It is not a licence - the
	// dispatcher treats it as a person, which is the narrow side, so an old
	// row of the panel's own machinery waits for a decision rather than
	// passing as one.
	ActorUnknown ActorKind = ""
	// ActorPerson: somebody ordered it, and their rights are read at dispatch.
	ActorPerson ActorKind = "person"
	// ActorMachinery: the panel's own work - a campaign, a directory change, a
	// vulnerability pass, an agent upgrade. There is no account to read.
	ActorMachinery ActorKind = "machinery"
)

// Valid says whether the kind is one this panel writes.
func (k ActorKind) Valid() bool {
	return k == ActorPerson || k == ActorMachinery
}
