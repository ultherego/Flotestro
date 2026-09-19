package opspec

import "testing"

// Every guide names a stage, a retry policy and both answers - what happened
// and what to do - and no code appears twice.
func TestErrorGuidesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, guide := range ErrorGuides() {
		if seen[guide.Code] {
			t.Errorf("%s is listed twice", guide.Code)
		}
		seen[guide.Code] = true
		if guide.Stage == "" || guide.Retry == "" || guide.Meaning == "" || guide.Action == "" {
			t.Errorf("%s is missing a stage, a retry policy, a meaning or an action: %+v", guide.Code, guide)
		}
	}
	for _, excluded := range []string{"capability_missing", "maintenance", "offline", "conflict", "quarantined",
		"recovery", "retiring", "retired", "host_retiring",
		"skipped_offline", "offline_deadline", "plan_changed_offline",
		"inventory_stale", "dispatch_ambiguous", "operation_non_cancelable",
		"session_stale", "session_unowned", "session_fence_stale", "boot_filter_unsupported"} {
		guide, ok := ErrorGuideFor(excluded)
		if !ok || guide.CountsAsFailure {
			t.Errorf("%s counts as a failure of the change: %+v (%v)", excluded, guide, ok)
		}
	}
	if _, ok := ErrorGuideFor("something_nobody_wrote"); ok {
		t.Error("an unknown code got a guide")
	}
}

// The campaigns document names a few conditions differently from the code the
// panel reports.
func TestDocumentNamesAreAliasesOfReportedCodes(t *testing.T) {
	for name, reported := range map[string]string{
		"verification_failed":   "health_check_failed",
		"connectivity_rollback": "rolled_back",
		"target_limit_policy":   "selector_too_broad",
	} {
		alias, ok := ErrorGuideFor(name)
		if !ok {
			t.Errorf("the guide does not list %s", name)
			continue
		}
		target, ok := ErrorGuideFor(reported)
		if !ok {
			t.Errorf("the guide does not list %s, which %s stands for", reported, name)
			continue
		}
		if alias.Alias != reported {
			t.Errorf("%s points at %q, want %q", name, alias.Alias, reported)
		}
		if alias.Stage != target.Stage || alias.Retry != target.Retry ||
			alias.Action != target.Action || alias.CountsAsFailure != target.CountsAsFailure {
			t.Errorf("%s gives other advice than %s:\n%+v\n%+v", name, reported, alias, target)
		}
		if target.Alias != "" {
			t.Errorf("%s is itself an alias (%q); a reported code has none", reported, target.Alias)
		}
	}
	// The codes the machinery reports under their own names carry no alias: a
	// reported code pointing at another would send the panel in a circle.
	for _, code := range []string{"helper_rejected", "operation_non_cancelable", "inventory_stale", "dispatch_ambiguous"} {
		guide, ok := ErrorGuideFor(code)
		if !ok || guide.Alias != "" {
			t.Errorf("%s: %+v (%v)", code, guide, ok)
		}
	}
}

// An alias of a code the guide does not list is a mistake in the table
// and fails at start, not at the first operator who asks.
func TestAnAliasOfAnUnknownCodeIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("an alias of a code nobody lists was accepted")
		}
	}()
	withAliases(reportedGuides, []documentAlias{{code: "x", reportedAs: "something_nobody_wrote"}})
}

// The refusals of the schedule user, the root grant, the missing validator and
// the payload permission gate are operator-visible and have advice in the
// guide; a code the panel shows without advice is a dead end.
func TestTheGuideCoversTheScheduleAndValidatorRefusals(t *testing.T) {
	for _, code := range []string{"user_required", "unknown_user", "root_grant_required",
		"validator_unavailable", "payload_permission_missing"} {
		guide, ok := ErrorGuideFor(code)
		if !ok {
			t.Errorf("the guide does not list %s", code)
			continue
		}
		if guide.Action == "" || guide.Meaning == "" {
			t.Errorf("%s has no advice: %+v", code, guide)
		}
	}
	// A refusal of the panel before a job exists is not a failure of any
	// change; the host's refusals are, because the change did not happen.
	if guide, _ := ErrorGuideFor("payload_permission_missing"); guide.CountsAsFailure {
		t.Error("payload_permission_missing counts as a failure of a change")
	}
	if guide, _ := ErrorGuideFor("validator_unavailable"); !guide.CountsAsFailure {
		t.Error("validator_unavailable does not count as a failure of the change")
	}
}
