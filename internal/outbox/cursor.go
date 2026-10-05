package outbox

// Where the reader of the trail stands, and why that takes two columns.
//
// outbox_events.id comes from a sequence: the number is taken at the insert and
// becomes visible at the commit. The fence on the inserting transaction keeps
// the reader from passing an event that is still to come, but it answers in the
// order of transactions, and the cursor advanced in the order of identifiers -
// and those two orders cross. A transaction that took its identifier at an
// earlier write (say 100), while another with a later one (101) had already
// reserved a lower event number and stayed open, committed with the higher
// event number: the oldest running transaction was then 101, the event of 100
// passed the fence, the cursor moved past the lower number, and the event of
// 101 committed afterwards and never satisfied "id > cursor" again. It reached
// no webhook and no notification, and nothing said so.
//
// So the cursor stands in the order the fence answers in: the inserting
// transaction first, then the identifier within it. The set of events whose
// transaction is older than every running one is complete and can never grow,
// so an event that arrives later always carries a key above the cursor.

// thisEpoch renders an inserting transaction as this cluster can judge it. A
// null is a row from before the column existed; an identifier at or above the
// next one this cluster will assign is a row restored here from another
// cluster, whose identifiers mean nothing locally. Neither has anything left
// to wait for, and both read as the identifier before every other, so those
// rows are ordered among themselves by their own event identifiers.
func thisEpoch(identifier string) string {
	return `case when ` + identifier + ` is null
	             or ` + identifier + ` >= pg_snapshot_xmax(pg_current_snapshot())
	        then '0'::xid8 else ` + identifier + ` end`
}

// eventKey is the order the trail is read in, for the events aliased as given.
func eventKey(alias string) string {
	return `(` + thisEpoch(alias+`.inserted_xid`) + `, ` + alias + `.id)`
}

// settledTransaction is the condition that no transaction which could still
// insert a lower key is running: the event's own transaction is older than the
// oldest one still open.
func settledTransaction(alias string) string {
	return thisEpoch(alias+`.inserted_xid`) + ` < pg_snapshot_xmin(pg_current_snapshot())`
}

// cursorAt is the cursor as it was read back, for the parameters given. The
// stored identifier is judged by the same rule as the event's: a cursor
// written before a restore names a transaction of the cluster the dump came
// from, and comparing new events against it would hold the whole trail back.
func cursorAt(xid, id string) string {
	return `(` + thisEpoch(xid) + `, ` + id + `)`
}

// UnpassedBySomeConsumer renders "a running consumer has not passed this event
// yet", for the events aliased as given. The retention of the trail asks it,
// because where a consumer stands is the pair and not the identifier alone: an
// event with a lower identifier than the cursor may still be ahead of it.
func UnpassedBySomeConsumer(alias string) string {
	return `exists (select 1 from outbox_consumers c
		 where c.active and ` + cursorAt(`c.last_xid`, `c.last_id`) + ` < ` + eventKey(alias) + `)`
}
