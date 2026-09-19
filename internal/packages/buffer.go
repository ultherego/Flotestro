package packages

import (
	"strings"
	"sync"
)

// maxOutput limits the output of a tool that is kept.
const maxOutput = 256 << 10

// limitedBuffer gathers the output up to a limit and remembers that it cut it.
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
