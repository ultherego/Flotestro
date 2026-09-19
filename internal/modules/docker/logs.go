package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The limits of a log read. The defaults apply when the order names none;
// the maxima bound an order regardless of what it asks for.
const (
	DefaultLogLines = 200
	MaxLogLines     = 5000
	// MaxLogBytes is the same limit a log file read has: a container that
	// writes in a loop must not hand the panel its whole history.
	MaxLogBytes = 1 << 20
)

// containerReference allows an identifier or a name.
var containerReference = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// ValidateContainerReference rejects a target that is neither an identifier
// nor a container name.
func ValidateContainerReference(reference string) error {
	if !containerReference.MatchString(reference) || strings.Contains(reference, "..") {
		return fmt.Errorf("invalid container reference %q", reference)
	}
	return nil
}

// logsSince allows the shapes the engine accepts after the panel translates
// them: an RFC 3339 timestamp or a duration such as 15m, 2h, 1d.
var logsSince = regexp.MustCompile(`^(\d+)(s|m|h|d)$`)

// ParseLogsSince turns the "since" of an order into a moment. An empty value
// means no lower bound.
func ParseLogsSince(since string, now time.Time) (time.Time, error) {
	since = strings.TrimSpace(since)
	if since == "" {
		return time.Time{}, nil
	}
	if match := logsSince.FindStringSubmatch(since); match != nil {
		amount, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil || amount <= 0 {
			return time.Time{}, fmt.Errorf("invalid duration %q", since)
		}
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[match[2]]
		if amount > int64((30*24*time.Hour)/unit) {
			return time.Time{}, fmt.Errorf("the log window %q is longer than 30 days", since)
		}
		return now.Add(-time.Duration(amount) * unit), nil
	}
	moment, err := time.Parse(time.RFC3339, since)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid since %q: an RFC 3339 timestamp or a duration like 15m", since)
	}
	return moment, nil
}

// LogsOptions bounds one log read.
type LogsOptions struct {
	// Tail is the number of lines from the end. Zero means DefaultLogLines.
	Tail uint32
	// Since is the lower bound of the read. Zero means the whole tail.
	Since time.Time
	// Timestamps prefixes every line with the engine's timestamp.
	Timestamps bool
	// MaxBytes bounds the read. Zero means MaxLogBytes.
	MaxBytes int64
}

// Logs is the tail of one container's log.
type Logs struct {
	ContainerID   string   `json:"container_id"`
	ContainerName string   `json:"container_name"`
	Lines         []string `json:"lines"`
	// Truncated means a read cut short by the byte limit. A cut list
	// without this marker would look complete.
	Truncated       bool   `json:"truncated,omitempty"`
	TruncatedReason string `json:"truncated_reason,omitempty"`
}

// StderrMarker opens every line the container wrote to its error stream.
const StderrMarker = "[stderr] "

// Logs reads the tail of a container's log.
func (c *Client) Logs(ctx context.Context, reference string, options LogsOptions) (Logs, error) {
	if err := ValidateContainerReference(reference); err != nil {
		return Logs{}, err
	}
	var details struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			TTY bool `json:"Tty"`
		} `json:"Config"`
	}
	if err := c.get(ctx, "/containers/"+reference+"/json", nil, &details); err != nil {
		if strings.Contains(err.Error(), "answered 404") {
			return Logs{}, fmt.Errorf("container %s: %w", reference, ErrNotFound)
		}
		return Logs{}, err
	}
	result := Logs{
		ContainerID:   details.ID,
		ContainerName: strings.TrimPrefix(details.Name, "/"),
		Lines:         []string{},
	}

	tail := options.Tail
	if tail == 0 {
		tail = DefaultLogLines
	}
	if tail > MaxLogLines {
		tail = MaxLogLines
	}
	limit := options.MaxBytes
	if limit <= 0 || limit > MaxLogBytes {
		limit = MaxLogBytes
	}
	query := url.Values{}
	query.Set("stdout", "1")
	query.Set("stderr", "1")
	query.Set("tail", strconv.FormatUint(uint64(tail), 10))
	if options.Timestamps {
		query.Set("timestamps", "1")
	}
	if !options.Since.IsZero() {
		query.Set("since", strconv.FormatInt(options.Since.Unix(), 10))
	}

	target := "http://docker/" + apiVersion + "/containers/" + details.ID + "/logs?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return result, fmt.Errorf("%w: %s", ErrUnavailable, shortenError(err))
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return result, fmt.Errorf("the engine answered %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}

	// One byte past the limit tells a stream that ended from one that was
	// cut: reading exactly the limit could be either.
	body := &countingReader{reader: io.LimitReader(response.Body, limit+1)}
	var lines []string
	if details.Config.TTY {
		lines, err = rawLines(body)
	} else {
		lines, err = demultiplexedLines(body)
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return result, err
	}
	if body.read > limit {
		result.Truncated = true
		result.TruncatedReason = fmt.Sprintf("the read reached the limit of %d bytes; narrow the window or the line count", limit)
		// A raw stream ends in the middle of a line; the frames of the
		// other kind hold a cut line back on their own.
		if details.Config.TTY && len(lines) > 0 {
			lines = lines[:len(lines)-1]
		}
	}
	result.Lines = lines
	return result, nil
}

// countingReader measures what went through it, so the read knows whether
// the stream ended or the limit did.
type countingReader struct {
	reader io.Reader
	read   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.read += int64(n)
	return n, err
}

// rawLines splits the single stream of a TTY container.
func rawLines(body io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 8<<10), 256<<10)
	for scanner.Scan() {
		lines = append(lines, strings.TrimRight(scanner.Text(), "\r"))
	}
	return lines, scanner.Err()
}

// demultiplexedLines reads the frames of a container without a TTY.
func demultiplexedLines(body io.Reader) ([]string, error) {
	var lines []string
	remainders := map[byte]string{}
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(body, header); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// A cut header: the limit fell between frames.
			return lines, io.ErrUnexpectedEOF
		}
		stream := header[0]
		size := binary.BigEndian.Uint32(header[4:])
		if size > MaxLogBytes {
			return lines, fmt.Errorf("the engine sent a frame of %d bytes", size)
		}
		payload := make([]byte, size)
		n, err := io.ReadFull(body, payload)
		if err != nil {
			// A cut frame: the complete lines read so far stand, the cut
			// one is held back and the caller marks the read as truncated.
			payload = payload[:n]
		}
		text := remainders[stream] + string(payload)
		parts := strings.Split(text, "\n")
		remainders[stream] = parts[len(parts)-1]
		for _, part := range parts[:len(parts)-1] {
			lines = append(lines, prefixed(stream, strings.TrimRight(part, "\r")))
		}
		if err != nil {
			return lines, io.ErrUnexpectedEOF
		}
	}
	// A stream that ended without a newline still said something.
	for _, stream := range []byte{1, 2} {
		if rest := remainders[stream]; rest != "" {
			lines = append(lines, prefixed(stream, rest))
		}
	}
	return lines, nil
}

func prefixed(stream byte, line string) string {
	if stream == 2 {
		return StderrMarker + line
	}
	return line
}
