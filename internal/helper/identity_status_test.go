package helper

import "testing"

// "offline" contains "online". A parser that looked for the latter anywhere in
// the output answered "online" for every state a domain can be in, and the
// branch for offline was unreachable - while the enrollment of a host counts
// that answer as a required condition.
func TestTheStatusOfADomainIsReadFromItsValue(t *testing.T) {
	for _, c := range []struct {
		name   string
		output string
		want   *bool
	}{
		{
			name:   "a domain that answers",
			output: "Name: example.com\nOnline status: Online\n",
			want:   boolOf(true),
		},
		{
			name:   "a domain that does not",
			output: "Name: example.com\nOnline status: Offline\n",
			want:   boolOf(false),
		},
		{
			name:   "the word offline elsewhere does not decide",
			output: "Name: example.com\nNote: the host was offline yesterday\nOnline status: Online\n",
			want:   boolOf(true),
		},
		{
			name:   "no status line at all",
			output: "Name: example.com\n",
			want:   nil,
		},
		{
			name:   "the tool said nothing",
			output: "",
			want:   nil,
		},
		{
			name:   "spelled differently by another release",
			output: "online status:offline",
			want:   boolOf(false),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := parseOnlineStatus(c.output)
			switch {
			case c.want == nil && got != nil:
				t.Fatalf("got %v, want no answer: an answer that was not given is not offline", *got)
			case c.want == nil:
				return
			case got == nil:
				t.Fatalf("got no answer, want %v", *c.want)
			case *got != *c.want:
				t.Errorf("got %v, want %v", *got, *c.want)
			}
		})
	}
}

func boolOf(value bool) *bool { return &value }
