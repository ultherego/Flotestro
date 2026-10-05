package hosts

// Did the host restart: the one question a boot identifier answers.

// RebootShown says whether two boot identifiers show that the host restarted,
// and when they do not, what is missing. A restart is shown by two identifiers
// that are both known and different; an identifier nobody read says nothing
// either way, and a restart nobody can see must not be declared on the
// strength of it.
func RebootShown(before, after string) (bool, string) {
	switch {
	case before == "":
		return false, "the host answers, but the panel holds no boot identifier from before the restart"
	case after == "":
		return false, "the host answers, but reports no boot identifier of its own"
	case before == after:
		return false, "the host answers, but with the same boot identifier"
	}
	return true, ""
}
