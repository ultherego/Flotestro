package logs

import (
	"regexp"
	"strconv"
)

// SuppressionNoticePriority is the syslog priority journald writes its
// rate-limit notice at. A view filtered below it never sees the notice.
const SuppressionNoticePriority = 6

// suppressionNotice is what journald writes about its own rate limit, under
// its own identifier: "Suppressed %i messages from %s".
var suppressionNotice = regexp.MustCompile(
	`(?:^|\s)systemd-journald(?:\[[0-9]+\])?: Suppressed ([0-9]{1,9}) messages from `)

// SuppressedMessages reads journald's rate-limit notice out of a short-iso
// journal line: how many messages the host itself never recorded. The
// identifier is part of the match, so a line quoting the notice is not one.
func SuppressedMessages(line string) (uint32, bool) {
	match := suppressionNotice.FindStringSubmatch(line)
	if match == nil {
		return 0, false
	}
	count, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(count), true
}
