// Package policy judges the fleet against declared desired state.
//
// A policy is the third model of change the architecture names, next to
// the interactive operation and the campaign: a declaration of what is to
// be true on a dynamic group of hosts, judged continuously. The judgement
// follows the same doctrine as the hardening checks: the host reports
// facts, the panel judges them, and an unknown fact is never a compliant
// one. A policy never touches a host by itself. Where the operator asks
// for a remediation, the drift becomes a campaign of typed steps - each
// the ordinary operation of the module responsible for the thing, with its
// own permission - and the campaign waits for its approval like any other.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/campaigns"
)

// The remediation modes. Report writes verdicts and nothing else; campaign
// turns a drift set into a campaign that waits for approval; automatic
// does the same and approves it with the publication, which is why it is
// a permission of its own.
const (
	ModeReport    = "report"
	ModeCampaign  = "campaign"
	ModeAutomatic = "automatic"
)

// KnownMode says whether the mode exists.
func KnownMode(mode string) bool {
	switch mode {
	case ModeReport, ModeCampaign, ModeAutomatic:
		return true
	}
	return false
}

// The verdicts of one rule on one host. They are the four answers the
// document names; there is no fifth, and "error" is not "compliant".
const (
	VerdictCompliant     = "compliant"
	VerdictDrift         = "drift"
	VerdictError         = "error"
	VerdictNotApplicable = "not_applicable"
)

// The rule kinds of this version. Every kind maps to facts the inventory
// already carries and to one typed operation that removes the drift.
const (
	KindPackageInstalled = "package_installed"
	KindPackageAbsent    = "package_absent"
	KindUnitState        = "unit_state"
	KindFileContent      = "file_content"
	KindSysctl           = "sysctl"
	KindSSHKeyPresent    = "ssh_key_present"
)

// Kinds lists the rule kinds in the order the editor offers them.
var Kinds = []string{
	KindPackageInstalled, KindPackageAbsent, KindUnitState,
	KindFileContent, KindSysctl, KindSSHKeyPresent,
}

// The bounds of a policy.
const (
	// DefaultCheckInterval is how often a policy is judged when the
	// document names no interval.
	DefaultCheckInterval = 15 * time.Minute
	MinCheckInterval     = time.Minute
	MaxCheckInterval     = 24 * time.Hour
	// MaxRules bounds one policy. A policy with more rules than this is
	// several policies; the results table would otherwise stop being
	// readable per host.
	MaxRules = 50
	// MaxNameLength bounds the name the campaigns and the audit quote.
	MaxNameLength = 120
)

// Rule is one typed declaration. Exactly the fields of its kind are set;
// the rest stay empty, and the validation says which are required.
type Rule struct {
	Kind string `json:"kind"`
	// Name is the package of package_installed and package_absent.
	Name string `json:"name,omitempty"`
	// Unit, Enabled and Active describe a unit_state rule. A nil pointer
	// leaves that half of the state undeclared: a rule may say "enabled"
	// without saying anything about "active".
	Unit    string `json:"unit,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
	Active  *bool  `json:"active,omitempty"`
	// Path and SHA256 describe a file_content rule: the managed file and
	// the digest of the version it is to hold.
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	// Key and Value describe a sysctl rule.
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
	// User and Fingerprint describe an ssh_key_present rule: the account
	// and the SHA256 fingerprint of the key, as the host reports it. The
	// optional PublicKey is the material of that key; without it the
	// panel can judge but not fix, because setting the keys of an account
	// replaces the whole list.
	User        string `json:"user,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
}

// Subject names what the rule is about, for the check identifiers and
// the screens: the package, the unit, the path, the key or the account.
func (r Rule) Subject() string {
	switch r.Kind {
	case KindPackageInstalled, KindPackageAbsent:
		return r.Name
	case KindUnitState:
		return r.Unit
	case KindFileContent:
		return r.Path
	case KindSysctl:
		return r.Key
	case KindSSHKeyPresent:
		return r.User + ":" + r.Fingerprint
	}
	return ""
}

// Describe puts the rule in one line for the audit trail and the campaign
// names.
func (r Rule) Describe() string {
	switch r.Kind {
	case KindPackageInstalled:
		return "package " + r.Name + " installed"
	case KindPackageAbsent:
		return "package " + r.Name + " absent"
	case KindUnitState:
		parts := []string{}
		if r.Enabled != nil {
			parts = append(parts, map[bool]string{true: "enabled", false: "disabled"}[*r.Enabled])
		}
		if r.Active != nil {
			parts = append(parts, map[bool]string{true: "active", false: "inactive"}[*r.Active])
		}
		return "unit " + r.Unit + " " + strings.Join(parts, " and ")
	case KindFileContent:
		return "file " + r.Path + " at " + shortDigest(r.SHA256)
	case KindSysctl:
		return "sysctl " + r.Key + " = " + r.Value
	case KindSSHKeyPresent:
		return "key " + r.Fingerprint + " on " + r.User
	}
	return r.Kind
}

// CheckID is the identifier a rule carries as a remediation step: the
// index binds it to the document, the kind and the subject make it
// readable. It is stable for a version, which is what the runner's
// idempotency key and the plan digest need.
func CheckID(index int, rule Rule) string {
	return fmt.Sprintf("rule:%d:%s:%s", index, rule.Kind, rule.Subject())
}

func shortDigest(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// ErrUnsupportedRule is a rule of a kind this version does not judge.
type ErrUnsupportedRule struct {
	Index int
	Kind  string
}

func (e ErrUnsupportedRule) Error() string {
	return fmt.Sprintf("rule %d: the kind %q is not supported; the kinds are %s",
		e.Index, e.Kind, strings.Join(Kinds, ", "))
}

// ErrInvalidRule is a rule of a known kind with its fields wrong.
type ErrInvalidRule struct {
	Index  int
	Reason string
}

func (e ErrInvalidRule) Error() string {
	return fmt.Sprintf("rule %d: %s", e.Index, e.Reason)
}

// ErrApprovalBound is a rule whose fix is bound to an approval the
// publication cannot stand in for: a package removal is approved with the
// set of packages that really go, and only a campaign shows that set.
type ErrApprovalBound struct {
	Index int
	Kind  string
}

func (e ErrApprovalBound) Error() string {
	return fmt.Sprintf("rule %d: %s is approval-bound; it runs in report or campaign mode, not automatic",
		e.Index, e.Kind)
}

// ErrNoRules is a publication of a document without a rule.
var ErrNoRules = errors.New("a policy needs at least one rule")

// ErrInvalidMode is an unknown remediation mode.
var ErrInvalidMode = errors.New("the remediation mode is report, campaign or automatic")

// ValidateRules checks every rule for its kind and its fields, and the
// set against the mode. A rule the version does not know is refused
// rather than skipped: a typo must not turn into a rule that judges
// nothing on the whole fleet.
func ValidateRules(rules []Rule, mode string) error {
	if !KnownMode(mode) {
		return ErrInvalidMode
	}
	if len(rules) == 0 {
		return ErrNoRules
	}
	if len(rules) > MaxRules {
		return fmt.Errorf("a policy carries at most %d rules; split it", MaxRules)
	}
	for index, rule := range rules {
		if err := validateRule(index, rule); err != nil {
			return err
		}
		if mode == ModeAutomatic && approvalBound(rule.Kind) {
			return ErrApprovalBound{Index: index, Kind: rule.Kind}
		}
	}
	return nil
}

// approvalBound names the kinds whose fix is a removal. The operator
// approves a removal together with what really goes, and a publication
// cannot show that.
func approvalBound(kind string) bool {
	return kind == KindPackageAbsent
}

func validateRule(index int, rule Rule) error {
	invalid := func(reason string) error { return ErrInvalidRule{Index: index, Reason: reason} }
	switch rule.Kind {
	case KindPackageInstalled, KindPackageAbsent:
		if strings.TrimSpace(rule.Name) == "" {
			return invalid("a package rule names the package")
		}
		if strings.ContainsAny(rule.Name, " \t\n/") {
			return invalid("the package name " + rule.Name + " is not a package name")
		}
	case KindUnitState:
		if strings.TrimSpace(rule.Unit) == "" {
			return invalid("a unit rule names the unit")
		}
		if !strings.Contains(rule.Unit, ".") || strings.ContainsAny(rule.Unit, " \t\n/") {
			return invalid("the unit " + rule.Unit + " is not a unit name; name it with its suffix, e.g. cron.service")
		}
		if rule.Enabled == nil && rule.Active == nil {
			return invalid("a unit rule declares enabled, active or both")
		}
	case KindFileContent:
		if !strings.HasPrefix(rule.Path, "/") {
			return invalid("a file rule names an absolute path")
		}
		if !isHexDigest(rule.SHA256) {
			return invalid("a file rule names the sha256 of the version, 64 hexadecimal characters")
		}
	case KindSysctl:
		if strings.TrimSpace(rule.Key) == "" || strings.ContainsAny(rule.Key, " \t\n") {
			return invalid("a sysctl rule names the key, e.g. net.ipv4.ip_forward")
		}
		if strings.TrimSpace(rule.Value) == "" {
			return invalid("a sysctl rule names the value")
		}
	case KindSSHKeyPresent:
		if strings.TrimSpace(rule.User) == "" || strings.ContainsAny(rule.User, " \t\n:") {
			return invalid("a key rule names the account")
		}
		if !strings.HasPrefix(rule.Fingerprint, "SHA256:") || len(rule.Fingerprint) < 20 {
			return invalid("a key rule names the SHA256 fingerprint of the key, as ssh-keygen -lf prints it")
		}
		if rule.PublicKey != "" && len(strings.Fields(rule.PublicKey)) < 2 {
			return invalid("the public key is the line of authorized_keys: the type, the material and an optional comment")
		}
	case "":
		return invalid("a rule names its kind")
	default:
		return ErrUnsupportedRule{Index: index, Kind: rule.Kind}
	}
	return nil
}

func isHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Policy is the record as the API shows it: the draft with its published
// version number, or a policy never published with version zero.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     int    `json:"version"`
	// Selector is the campaign selector as recorded. It travels raw the
	// way a campaign's does: the typed form is read with DocumentOf when
	// the panel needs it.
	Selector        json.RawMessage `json:"selector"`
	Rules           []Rule          `json:"rules"`
	RemediationMode string          `json:"remediation_mode"`
	Enabled         bool            `json:"enabled"`
	CheckInterval   int             `json:"check_interval_seconds"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	PublishedAt     *time.Time      `json:"published_at,omitempty"`
	PublishedBy     string          `json:"published_by,omitempty"`
	LastEvaluatedAt *time.Time      `json:"last_evaluated_at,omitempty"`
	// Draft says the document differs from the published version: the
	// loop judges what was published, not what is being typed.
	Draft bool `json:"draft"`
	// Counts summarise the latest results by verdict; every verdict is
	// present so a screen draws four segments without guessing.
	Counts map[string]int `json:"counts"`
}

// Document is the part of a policy a publication freezes.
type Document struct {
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	Selector        campaigns.Selector `json:"selector"`
	Rules           []Rule             `json:"rules"`
	RemediationMode string             `json:"remediation_mode"`
	CheckInterval   int                `json:"check_interval_seconds"`
}

// DocumentOf takes the frozen part out of a policy. A selector that does
// not decode reads as empty: a policy over nobody, which the publication
// refuses.
func DocumentOf(policy Policy) Document {
	document := Document{
		Name: policy.Name, Description: policy.Description,
		Rules: policy.Rules, RemediationMode: policy.RemediationMode, CheckInterval: policy.CheckInterval,
	}
	if len(policy.Selector) > 0 {
		_ = json.Unmarshal(policy.Selector, &document.Selector)
	}
	return document
}

// Equal says whether two documents declare the same thing. The draft flag
// of a policy rests on it.
func (d Document) Equal(other Document) bool {
	a, errA := json.Marshal(d)
	b, errB := json.Marshal(other)
	return errA == nil && errB == nil && string(a) == string(b)
}

// Version is one publication: the frozen document and the evidence of who
// published it.
type Version struct {
	PolicyID string `json:"policy_id"`
	Version  int    `json:"version"`
	// Document is the frozen text as published; Decode reads it typed.
	Document        json.RawMessage `json:"document"`
	PublishedBy     string          `json:"published_by"`
	PublishedAt     time.Time       `json:"published_at"`
	Reason          string          `json:"reason,omitempty"`
	Authentication  string          `json:"authentication,omitempty"`
	ACR             string          `json:"acr,omitempty"`
	AMR             []string        `json:"amr,omitempty"`
	AuthenticatedAt *time.Time      `json:"authenticated_at,omitempty"`
}

// Decode reads the frozen document.
func (v Version) Decode() (Document, error) {
	var document Document
	if err := json.Unmarshal(v.Document, &document); err != nil {
		return Document{}, fmt.Errorf("the document of version %d does not decode: %w", v.Version, err)
	}
	if document.Rules == nil {
		document.Rules = []Rule{}
	}
	return document, nil
}

// Result is the verdict of one rule on one host.
type Result struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name,omitempty"`
	HostID     string `json:"host_id"`
	Hostname   string `json:"hostname,omitempty"`
	RuleIndex  int    `json:"rule_index"`
	// Rule is the rule as the judged version carried it, so a screen
	// reads the verdict next to the declaration without a second read.
	Rule    *Rule  `json:"rule,omitempty"`
	Version int    `json:"version"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// ObservedRevision names the read of the host the verdict rests on.
	ObservedRevision string    `json:"observed_revision,omitempty"`
	EvaluatedAt      time.Time `json:"evaluated_at"`
}

// Spec is what a create or an update carries.
type Spec struct {
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	Selector        campaigns.Selector `json:"selector"`
	Rules           []Rule             `json:"rules"`
	RemediationMode string             `json:"remediation_mode"`
	Enabled         *bool              `json:"enabled"`
	CheckInterval   int                `json:"check_interval_seconds"`
}

// Validate checks the parts a draft has to have. The rules are checked
// at publication - a draft may be half-written - but the name, the mode
// and the interval are required from the start, because the list shows
// them.
func (s Spec) Validate() error {
	name := strings.TrimSpace(s.Name)
	if name == "" {
		return errors.New("a policy needs a name")
	}
	if len(name) > MaxNameLength {
		return fmt.Errorf("the name is longer than %d characters", MaxNameLength)
	}
	if !KnownMode(s.RemediationMode) {
		return ErrInvalidMode
	}
	if s.CheckInterval != 0 {
		interval := time.Duration(s.CheckInterval) * time.Second
		if interval < MinCheckInterval || interval > MaxCheckInterval {
			return fmt.Errorf("the check interval has to be between %d and %d seconds",
				int(MinCheckInterval/time.Second), int(MaxCheckInterval/time.Second))
		}
	}
	if len(s.Rules) > MaxRules {
		return fmt.Errorf("a policy carries at most %d rules; split it", MaxRules)
	}
	if s.Selector.Expression != nil {
		if err := s.Selector.Expression.Validate(); err != nil {
			return fmt.Errorf("the selector: %w", err)
		}
	}
	return nil
}

// EmptyCounts gives the four verdicts at zero, so a screen never has to
// guess whether a missing key means zero or unknown.
func EmptyCounts() map[string]int {
	return map[string]int{
		VerdictCompliant: 0, VerdictDrift: 0, VerdictError: 0, VerdictNotApplicable: 0,
	}
}
