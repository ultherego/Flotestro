package firewall

import "testing"

// The agent connects out to the panel, so a rule that drops the panel's port
// on the way out cuts the management channel as surely as one on the way in -
// and it is the same port number in both directions. The check asked about
// the input chain alone, so output/drop/tcp dport 8443 went through it.
func TestTheManagementChannelIsProtectedInBothDirections(t *testing.T) {
	const port = 8443
	for _, c := range []struct {
		name   string
		rule   RuleSpec
		refuse bool
	}{
		{
			name:   "dropping the panel's port on the way in",
			rule:   RuleSpec{Chain: ChainInput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"8443"}},
			refuse: true,
		},
		{
			name:   "dropping the panel's port on the way out",
			rule:   RuleSpec{Chain: ChainOutput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"8443"}},
			refuse: true,
		},
		{
			name:   "dropping every outgoing connection",
			rule:   RuleSpec{Chain: ChainOutput, Action: ActionDrop, Protocol: "tcp"},
			refuse: true,
		},
		{
			name:   "another port on the way out is not the channel",
			rule:   RuleSpec{Chain: ChainOutput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"25"}},
			refuse: false,
		},
		{
			name:   "accepting the port is not cutting it off",
			rule:   RuleSpec{Chain: ChainOutput, Action: ActionAccept, Protocol: "tcp", Ports: []string{"8443"}},
			refuse: false,
		},
		{
			name:   "a range that covers the port",
			rule:   RuleSpec{Chain: ChainOutput, Action: ActionDrop, Protocol: "tcp", Ports: []string{"8000-9000"}},
			refuse: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := ProtectsManagementChannel(c.rule, "", port)
			if c.refuse && err == nil {
				t.Error("the rule was accepted and it cuts the host off from the panel")
			}
			if !c.refuse && err != nil {
				t.Errorf("the rule was refused: %v", err)
			}
		})
	}
}
