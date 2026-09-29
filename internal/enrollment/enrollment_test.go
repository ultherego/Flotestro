package enrollment

import "testing"

func TestARepeatedOrderDiffersOnlyInWhatTheCallerAskedFor(t *testing.T) {
	base := func() *Request {
		return &Request{
			ID: "first", Description: "first wording", Site: "lab", Environment: "test",
			Kind: KindAgent, Purpose: PurposeNew, Owner: "platform",
			Tags: []string{"web", "edge"}, MaxUses: 1,
		}
	}
	fifteen, sixty := 900, 3600

	cases := []struct {
		name    string
		change  func(*Request)
		ttl     int
		stored  *int
		differs string
	}{
		{name: "the same order is one order", ttl: 900, stored: &fifteen},
		{name: "a label is not part of the order", ttl: 900, stored: &fifteen,
			change: func(r *Request) { r.Description = "another wording" }},
		{name: "what the panel decided afterwards is not part of the order", ttl: 900, stored: &fifteen,
			change: func(r *Request) { r.Status, r.Uses, r.EnrolledHostID = StatusEnrolled, 1, "host" }},
		{name: "tags are a set", ttl: 900, stored: &fifteen,
			change: func(r *Request) { r.Tags = []string{"edge", "web"} }},
		{name: "a lifetime nobody recorded is not held against the repeat", ttl: 60, stored: nil},
		{name: "another scope", ttl: 900, stored: &fifteen, differs: "scope",
			change: func(r *Request) { r.Environment = "prod" }},
		{name: "another kind", ttl: 900, stored: &fifteen, differs: "kind",
			change: func(r *Request) { r.Kind = KindRelay }},
		{name: "another purpose", ttl: 900, stored: &fifteen, differs: "purpose",
			change: func(r *Request) { r.Purpose = PurposeReplace }},
		{name: "another machine", ttl: 900, stored: &fifteen, differs: "expected machine",
			change: func(r *Request) { r.ExpectedMachineID = "abc" }},
		{name: "another relay", ttl: 900, stored: &fifteen, differs: "relay",
			change: func(r *Request) { r.RelayID = "relay" }},
		{name: "another owner", ttl: 900, stored: &fifteen, differs: "owner or tags",
			change: func(r *Request) { r.Owner = "somebody" }},
		{name: "other tags", ttl: 900, stored: &fifteen, differs: "owner or tags",
			change: func(r *Request) { r.Tags = []string{"web"} }},
		{name: "another number of uses", ttl: 900, stored: &fifteen, differs: "number of uses",
			change: func(r *Request) { r.MaxUses = 5 }},
		{name: "another lifetime", ttl: 900, stored: &sixty, differs: "lifetime"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			existing, want := base(), base()
			if c.change != nil {
				c.change(want)
			}
			if got := orderDiffers(existing, c.stored, want, c.ttl); got != c.differs {
				t.Errorf("orderDiffers = %q, want %q", got, c.differs)
			}
		})
	}
}
