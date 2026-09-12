package packages

import (
	"strings"
	"sync"
)

// maxOutput limits the output of a tool that is kept. A transaction on
// several hundred packages prints megabytes; only the description of the error
// reaches the result anyway, so the rest is a cost without a benefit.
const maxOutput = 256 << 10

// limitedBuffer gathers the output up to a limit and remembers that it cut
// it.
//
// The cut counts from the beginning rather than from the end: the cause of an
// error is usually near the end of the output, so it is the beginning that can
// be given up.
type limitedBuffer struct {
	mu    sync.Mutex
	lines []string
	size  int
	limit int
	cut   bool
}

func (b *limitedBuffer) WriteLine(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
	b.size += len(line) + 1
	for b.size > b.limit && len(b.lines) > 1 {
		b.size -= len(b.lines[0]) + 1
		b.lines = b.lines[1:]
		b.cut = true
	}
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := strings.Join(b.lines, "\n")
	if b.cut {
		return "[the beginning of the output was skipped]\n" + text
	}
	return text
}
