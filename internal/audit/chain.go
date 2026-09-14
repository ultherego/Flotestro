package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// An export of the trail is a file of JSON lines linked by a hash chain:
// every line carries the digest of the line before it, and a final line
// carries the count and the digest of the last event. A file kept outside
// the panel - on write-once storage, with an auditor - can then be checked
// without the panel: a line changed, removed or inserted breaks the digest
// of every line after it, and a file cut short has no closing line.
//
// The digest is taken over the bytes of the line as written, without the
// newline. That is the canonical form: the verifier hashes what it reads
// and never re-encodes, so it cannot disagree with the writer about the
// order of keys or the spelling of a number.

// ChainEntry is one event as the export writes it.
type ChainEntry struct {
	Record
	// PrevSHA256 is the digest of the previous line; for the first line,
	// the digest of the empty string.
	PrevSHA256 string `json:"prev_sha256"`
}

// ChainTrailer is the closing line of an export.
type ChainTrailer struct {
	Count       int64  `json:"count"`
	SHA256Chain string `json:"sha256_chain"`
}

// ChainWriter writes the export line by line.
type ChainWriter struct {
	out   *bufio.Writer
	prev  [32]byte
	count int64
	// closed refuses further writes after the trailer: a line after the
	// closing one would not be covered by it.
	closed bool
}

// NewChainWriter starts an export. The first line's predecessor is the
// empty string.
func NewChainWriter(out io.Writer) *ChainWriter {
	return &ChainWriter{out: bufio.NewWriter(out), prev: sha256.Sum256(nil)}
}

// Write adds one event to the chain.
func (c *ChainWriter) Write(record Record) error {
	if c.closed {
		return errors.New("the export is closed")
	}
	line, err := json.Marshal(ChainEntry{Record: record, PrevSHA256: hex.EncodeToString(c.prev[:])})
	if err != nil {
		return fmt.Errorf("encoding the event %d: %w", record.ID, err)
	}
	return c.writeLine(line)
}

// Close writes the trailer and flushes. Without it the file is truncated
// by definition, whatever it holds.
func (c *ChainWriter) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	line, err := json.Marshal(ChainTrailer{Count: c.count, SHA256Chain: hex.EncodeToString(c.prev[:])})
	if err != nil {
		return err
	}
	if _, err := c.out.Write(line); err != nil {
		return err
	}
	if err := c.out.WriteByte('\n'); err != nil {
		return err
	}
	return c.out.Flush()
}

func (c *ChainWriter) writeLine(line []byte) error {
	if _, err := c.out.Write(line); err != nil {
		return err
	}
	if err := c.out.WriteByte('\n'); err != nil {
		return err
	}
	c.prev = sha256.Sum256(line)
	c.count++
	return nil
}

// ChainReport is the result of verifying an export.
type ChainReport struct {
	// Count is the number of events the file holds, as counted; the
	// trailer has to agree with it.
	Count int64
	// SHA256Chain is the digest of the last event line, as recomputed.
	SHA256Chain string
	// First and Last are the identifiers of the first and last event, for
	// a report that says which range the file covers.
	First, Last int64
}

// ErrChainBroken means the file does not verify. The message says at
// which line and why.
var ErrChainBroken = errors.New("the audit export does not verify")

// VerifyChain recomputes the chain of an export and compares it with what
// the file says about itself.
func VerifyChain(in io.Reader) (ChainReport, error) {
	reader := bufio.NewReaderSize(in, 1<<20)
	prev := sha256.Sum256(nil)
	var report ChainReport
	var lineNumber int64
	var closed bool
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return report, err
		}
		line = bytes.TrimRight(line, "\r\n")
		lineNumber++
		if len(bytes.TrimSpace(line)) == 0 {
			// A trailing empty line is what an editor leaves; it is not
			// part of the chain.
			continue
		}
		if closed {
			return report, fmt.Errorf("%w: line %d comes after the closing line", ErrChainBroken, lineNumber)
		}

		var probe struct {
			ID          *int64  `json:"id"`
			PrevSHA256  *string `json:"prev_sha256"`
			Count       *int64  `json:"count"`
			SHA256Chain *string `json:"sha256_chain"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return report, fmt.Errorf("%w: line %d is not JSON: %v", ErrChainBroken, lineNumber, err)
		}
		switch {
		case probe.SHA256Chain != nil:
			if probe.Count == nil || *probe.Count != report.Count {
				return report, fmt.Errorf("%w: the closing line counts %v events, the file holds %d",
					ErrChainBroken, deref(probe.Count), report.Count)
			}
			if *probe.SHA256Chain != hex.EncodeToString(prev[:]) {
				return report, fmt.Errorf("%w: the closing digest does not match the last event", ErrChainBroken)
			}
			closed = true
		case probe.PrevSHA256 != nil:
			if *probe.PrevSHA256 != hex.EncodeToString(prev[:]) {
				return report, fmt.Errorf("%w: line %d does not follow the line before it", ErrChainBroken, lineNumber)
			}
			prev = sha256.Sum256(line)
			report.Count++
			if probe.ID != nil {
				if report.Count == 1 {
					report.First = *probe.ID
				}
				report.Last = *probe.ID
			}
		default:
			return report, fmt.Errorf("%w: line %d is neither an event nor the closing line", ErrChainBroken, lineNumber)
		}
	}
	if !closed {
		return report, fmt.Errorf("%w: the closing line is missing; the file is cut short", ErrChainBroken)
	}
	report.SHA256Chain = hex.EncodeToString(prev[:])
	return report, nil
}

func deref(value *int64) any {
	if value == nil {
		return "no"
	}
	return *value
}
