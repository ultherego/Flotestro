package agent

import (
	"testing"

	"github.com/ultherego/flotestro/internal/helper"
)

// A refusal of the request itself - the helper did not read it, does not speak
// its version or does not know the action - is one answer whichever module
// asked.
func TestOnlyAContractRefusalOfTheHelperBecomesHelperRejected(t *testing.T) {
	for _, code := range []string{helper.ErrorMalformed, helper.ErrorUnsupportedVersion, helper.ErrorUnknownAction} {
		if !helperRefusedContract(code) {
			t.Errorf("%s is not mapped to %s", code, RejectHelperRejected)
		}
	}
	for _, code := range []string{helper.ErrorLocked, helper.ErrorPreconditionFailed, helper.ErrorExecFailed,
		helper.ErrorTimeout, helper.ErrorUnsupported, helper.ErrorExpired, helper.ErrorProtectedUnit, ""} {
		if helperRefusedContract(code) {
			t.Errorf("%s would lose its own code under %s", code, RejectHelperRejected)
		}
	}
}
