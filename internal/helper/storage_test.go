package helper

import (
	"context"
	"strings"
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

func mountAction(persist bool) *helperv1.StorageRequest {
	return &helperv1.StorageRequest{
		Operation: helperv1.StorageRequest_OPERATION_MOUNT_ENSURE,
		Source:    "UUID=6f1a2b3c-0000-4000-8000-0123456789ab",
		Target:    "/srv/data",
		FsType:    "ext4",
		Options:   "defaults,nofail",
		Persist:   persist,
	}
}

// The command names what was ordered: a mount given only the mount point takes
// its source from /etc/fstab instead.
func TestTheMountCommandNamesTheSourceTheTypeAndTheOptions(t *testing.T) {
	for _, persist := range []bool{false, true} {
		arguments := mountArguments(mountAction(persist))
		want := []string{mountPath, "-t", "ext4", "-o", "defaults,nofail",
			"UUID=6f1a2b3c-0000-4000-8000-0123456789ab", "/srv/data"}
		if strings.Join(arguments, " ") != strings.Join(want, " ") {
			t.Fatalf("persist=%v: mount arguments %v, want %v", persist, arguments, want)
		}
	}
}

// An order without options mounts with the same defaults the fstab entry is
// written with, not with an empty option list.
func TestAMountWithoutOptionsUsesTheSameDefaultAsFstab(t *testing.T) {
	action := mountAction(false)
	action.Options = ""
	arguments := mountArguments(action)
	if got := strings.Join(arguments, " "); !strings.Contains(got, "-o defaults ") {
		t.Fatalf("mount arguments %q do not carry the default options", got)
	}
}

// A mount that carries no plan digest is refused: nothing then compared the
// order with the fstab entry the mount point may already have.
func TestAMountWithoutAPlanDigestIsRefused(t *testing.T) {
	server := &Server{}
	response := server.mount(context.Background(), mountAction(true))
	if response.GetAccepted() {
		t.Fatal("a mount without a plan digest was accepted")
	}
	if response.GetErrorCode() != opspec.RefusalPlanBindingMissing {
		t.Fatalf("refusal code %q, want %q", response.GetErrorCode(), opspec.RefusalPlanBindingMissing)
	}
	if !strings.Contains(response.GetMessage(), "/srv/data") {
		t.Fatalf("the refusal does not name the mount point: %q", response.GetMessage())
	}
}

// The refusal comes before the validation of the order is over: a malformed
// order is still answered with what is wrong with it.
func TestAMalformedMountIsStillReportedAsMalformed(t *testing.T) {
	server := &Server{}
	action := mountAction(false)
	action.Target = "relative/path"
	response := server.mount(context.Background(), action)
	if response.GetErrorCode() != ErrorMalformed {
		t.Fatalf("refusal code %q, want %q", response.GetErrorCode(), ErrorMalformed)
	}
}
