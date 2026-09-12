package helper

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// TestCleanupRejectsANameWithAPath guards the trust boundary of the helper:
// a volume name lands in the query path of the Engine API, and the helper runs
// as root and cannot trust the content of the message, even though the panel
// has already checked it.
func TestCleanupRejectsANameWithAPath(t *testing.T) {
	cases := []struct {
		name    string
		request *helperv1.DockerActionRequest
	}{
		{"a volume with a path", &helperv1.DockerActionRequest{
			VolumeNames: []string{"../containers/aaaa/kill"}}},
		{"a volume with a slash", &helperv1.DockerActionRequest{
			VolumeNames: []string{"data/../.."}}},
		{"an image without an algorithm", &helperv1.DockerActionRequest{
			ImageIds: []string{"latest"}}},
		{"a network outside hexadecimal", &helperv1.DockerActionRequest{
			NetworkIds: []string{"shop_default"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reason := checkCleanupList(tc.request); reason == "" {
				t.Fatal("the helper accepted a request it should have rejected")
			}
		})
	}
}

func TestCleanupAllowsValidObjects(t *testing.T) {
	request := &helperv1.DockerActionRequest{
		ImageIds:    []string{"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		VolumeNames: []string{"shop_data"},
		NetworkIds:  []string{"2701db76242ee094c5535ecd6ddde9ffea5d38c4ce5de57f13bfd924da4a9a10"},
	}
	if reason := checkCleanupList(request); reason != "" {
		t.Fatalf("a valid request was rejected: %s", reason)
	}
}
