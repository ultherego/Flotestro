package helper

import "testing"

func TestAgentReplacementRecognizesTheAgentPackage(t *testing.T) {
	cases := []struct {
		name     string
		packages []string
		expected bool
		spec     string
	}{
		{"apt with a version", []string{"flotestro-agent=0.6.0"}, true, "flotestro-agent=0.6.0"},
		{"dnf with a version", []string{"flotestro-agent-0.6.0"}, true, "flotestro-agent-0.6.0"},
		{"without a version", []string{"flotestro-agent"}, true, "flotestro-agent"},
		{"a foreign package", []string{"curl=8.0"}, false, ""},
		{"a similar name", []string{"flotestro-agent-tools=1.0"}, false, ""},
		{"the agent in company", []string{"flotestro-agent=0.6.0", "curl"}, false, ""},
		{"empty", nil, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := agentReplacement(tc.packages)
			if ok != tc.expected {
				t.Fatalf("agentReplacement(%v) = %v, expected %v",
					tc.packages, ok, tc.expected)
			}
			if ok && spec != tc.spec {
				t.Fatalf("spec = %q, expected %q", spec, tc.spec)
			}
		})
	}
}
