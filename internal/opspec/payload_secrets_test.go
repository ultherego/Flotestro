package opspec

import (
	"reflect"
	"testing"
)

// Every payload that names a secret has to be reported here: the scheduler
// issues the leases from this list, and a reference it does not see is a host
// refused the value it was ordered to use. A container's variables were
// missing, so that feature did not work at all.
func TestSecretsReportsTheReferencesOfEveryPayloadThatNamesOne(t *testing.T) {
	for _, c := range []struct {
		name    string
		payload Payload
		want    []SecretRef
	}{
		{
			name:    "a file filled from a secret",
			payload: Payload{File: &FilePayload{ContentSecret: &SecretRef{Name: "tls-key", Version: 2}}},
			want:    []SecretRef{{Name: "tls-key", Version: 2}},
		},
		{
			name: "the variables of a container, by variable name",
			payload: Payload{DockerEnsure: &DockerEnsurePayload{
				EnvSecrets: map[string]SecretRef{
					"DB_PASSWORD": {Name: "db-password", Version: 1},
					"API_TOKEN":   {Name: "api-token"},
				},
			}},
			// API_TOKEN before DB_PASSWORD: two identical orders have to issue
			// their leases in the same order.
			want: []SecretRef{{Name: "api-token"}, {Name: "db-password", Version: 1}},
		},
		{
			name:    "a payload that names none",
			payload: Payload{DockerEnsure: &DockerEnsurePayload{}},
			want:    nil,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := c.payload.Secrets()
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Secrets() = %v, want %v", got, c.want)
			}
		})
	}
}
