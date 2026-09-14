package docker

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"
)

func frame(stream byte, text string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(text)))
	return append(header, text...)
}

// The two streams of a container without a TTY arrive as frames, in the
// order the engine kept. The read keeps that order and marks the error
// stream, so a line that came from stderr can be told from one that did
// not - without a second list that would lose the order.
func TestDemultiplexedLinesKeepsOrderAndMarksStderr(t *testing.T) {
	var body bytes.Buffer
	body.Write(frame(1, "starting\nlisten"))
	body.Write(frame(2, "warning: no config\n"))
	body.Write(frame(1, "ing on :80\n"))
	body.Write(frame(1, "tail without newline"))

	lines, err := demultiplexedLines(&body)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"starting", StderrMarker + "warning: no config", "listening on :80", "tail without newline"}
	if strings.Join(lines, "|") != strings.Join(expected, "|") {
		t.Fatalf("lines = %q, expected %q", lines, expected)
	}
}

// A frame cut by the byte limit does not turn into a made-up line: the
// complete lines stand, the cut one is held back and the caller learns of
// the cut.
func TestDemultiplexedLinesReportsACutFrame(t *testing.T) {
	full := append(frame(1, "first\n"), frame(1, "second line that is cut\n")...)
	lines, err := demultiplexedLines(bytes.NewReader(full[:len(full)-5]))
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, expected an unexpected end", err)
	}
	if len(lines) != 1 || lines[0] != "first" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestRawLinesSplitsATTYStream(t *testing.T) {
	lines, err := rawLines(strings.NewReader("one\r\ntwo\nthree"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, "|") != "one|two|three" {
		t.Fatalf("lines = %q", lines)
	}
}

// The reference lands in the path of an Engine API request. A name is
// allowed - this is a read and the name is what the operator sees - but
// nothing that changes the path.
func TestContainerReferenceIsChecked(t *testing.T) {
	for _, good := range []string{"5c5b63d3119a", "web", "shop_web-1", "a.b"} {
		if err := ValidateContainerReference(good); err != nil {
			t.Errorf("%q was rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"", "../images/json", "web/json", "web?all=1", "-web", "a..b", "web json"} {
		if err := ValidateContainerReference(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestParseLogsSince(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	moment, err := ParseLogsSince("15m", now)
	if err != nil || !moment.Equal(now.Add(-15*time.Minute)) {
		t.Errorf("15m = %v (%v)", moment, err)
	}
	moment, err = ParseLogsSince("2026-09-13T10:00:00Z", now)
	if err != nil || !moment.Equal(time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp = %v (%v)", moment, err)
	}
	if moment, err := ParseLogsSince("", now); err != nil || !moment.IsZero() {
		t.Errorf("empty = %v (%v)", moment, err)
	}
	for _, bad := range []string{"yesterday", "15", "-15m", "0m", "400d", "15 m"} {
		if _, err := ParseLogsSince(bad, now); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
