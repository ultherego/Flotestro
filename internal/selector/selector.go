// Package selector describes which hosts an order concerns.
//
// A selector is a small typed structure rather than a query language: a
// campaign records it for the audit trail, the panel shows it to the
// approver, and both have to read it without a parser. The structure is
// compiled to SQL over the hosts table, so a selector never pulls the fleet
// into memory to filter it - the same rule the host list follows.
//
// The one-line text form ("site = warsaw and not tag = role=db") exists
// for the places where an operator types a scope by hand - an alert rule,
// a search box. Parse turns it into the same structure; nothing is
// evaluated from text.
package selector

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Expression is one node of a selector: exactly one field is set. A
// combinator (all, any, not) holds other nodes; a leaf names one fact
// about the host.
//
// Nothing here is a wildcard. A leaf compares a value for equality, and
// "everything" is written as the absence of a selector, not as a selector
// that happens to match everything.
type Expression struct {
	// All holds when every child holds; Any when at least one does; Not
	// when its child does not.
	All []Expression `json:"all,omitempty"`
	Any []Expression `json:"any,omitempty"`
	Not *Expression  `json:"not,omitempty"`

	Site        string `json:"site,omitempty"`
	Environment string `json:"environment,omitempty"`
	OSFamily    string `json:"os_family,omitempty"`
	// Tag is 'key' or 'key=value', exactly as recorded on the host.
	Tag string `json:"tag,omitempty"`
	// Group names a saved group by identifier or by name. A static group
	// contributes its member list, a dynamic one its own selector.
	Group string `json:"group,omitempty"`
	// Capability is the name of an adapter the host has to report as
	// available: 'packages.apt', not 'packages'.
	Capability      string `json:"capability,omitempty"`
	ConnectionState string `json:"connection_state,omitempty"`
	LifecycleState  string `json:"lifecycle_state,omitempty"`
	Owner           string `json:"owner,omitempty"`
	// Channel is the release channel the host follows: stable or beta. An
	// agent upgrade in waves names the beta hosts first.
	Channel string `json:"channel,omitempty"`
	// OSVersion is a prefix of the version the host reports: '12' names
	// every Debian 12.x and '12.4' one point release. A prefix rather than
	// equality, because a family writes its version in more digits than an
	// operator means when naming a release.
	OSVersion string `json:"os_version,omitempty"`
	// SecurityUpdates, RebootRequired and FailedUnits are 'true' or
	// 'false': whether the host has pending security updates, needs a
	// reboot, has a failed unit. A host that has not reported the fact is
	// in neither list - unknown is not "no".
	SecurityUpdates string `json:"security_updates,omitempty"`
	RebootRequired  string `json:"reboot_required,omitempty"`
	FailedUnits     string `json:"failed_units,omitempty"`
	// AgentVersion is a comparison with a version: '< 0.49.0', '>= 0.49.0',
	// '= 0.49.0'; a bare version means equality. Versions compare part by
	// part, so 0.10.0 is newer than 0.9.0. A host whose version does not
	// parse is on neither side of any comparison.
	AgentVersion string `json:"agent_version,omitempty"`
	// Relay names the relay, by identifier or by name, whose open session
	// the host connects through. The session says which route the host
	// took; a host that connects directly today is behind no relay.
	Relay string `json:"relay,omitempty"`
	// FailureDomain is the domain an operator placed the host in.
	FailureDomain string `json:"failure_domain,omitempty"`

	// MemberOf is the expanded form of a reference to a static group: the
	// identifier whose member list decides. Expand produces it; a selector
	// that arrives from a client with it set is refused, so a client cannot
	// bypass the lookup by name.
	MemberOf string `json:"group_id,omitempty"`
}

// The bounds of a selector. A selector deeper or larger than this is not
// something anybody reads before approving; refusing it is kinder than
// compiling it.
const (
	MaxDepth = 8
	MaxNodes = 64
	// MaxExpansion bounds how many dynamic groups may stand inside one
	// another. The chain is checked for cycles separately; the bound keeps
	// an honest chain readable.
	MaxExpansion = 4
	// maxValue bounds a leaf value; a site or a tag longer than this is a
	// mistake, not a name.
	maxValue = 128
)

// TagPattern is the shape of a tag: a lower-case key, optionally with a
// value after '='. The key side is deliberately narrow, so that tags sort
// and group predictably; the value side allows what versions, paths and
// names of teams need.
var TagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*(=[a-zA-Z0-9_.:/-]+)?$`)

// The values a state leaf may name. The list is the same one the host
// table constrains; a selector naming a state no host can be in would
// silently match nothing.
var (
	connectionStates = []string{"online", "offline", "stale", "unknown"}
	lifecycleStates  = []string{"active", "quarantined", "recovery", "retiring", "retired"}
	releaseChannels  = []string{"stable", "beta"}
	booleans         = []string{"true", "false"}
)

// versionPattern is the shape of a version an agent reports, as far as
// the comparison reads it: up to four numeric parts, an optional 'v' in
// front. A suffix such as '-rc1' is not part of the order and is refused
// in a selector rather than silently dropped.
var versionPattern = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})$`)

// versionOperators are the comparisons a version leaf may make, longest
// first so that '<=' is not read as '<' followed by '='.
var versionOperators = []string{"<=", ">=", "<", ">", "="}

// VersionComparison is an agent_version leaf taken apart: the operator
// and the version without its 'v'.
type VersionComparison struct {
	Operator string
	Version  string
}

// String renders the comparison in the form a leaf carries: the operator,
// one space, the version.
func (v VersionComparison) String() string {
	return v.Operator + " " + v.Version
}

// ParseVersionComparison reads an agent_version leaf: an operator among
// <, <=, >, >=, = followed by a version, or a bare version, which means
// equality.
func ParseVersionComparison(value string) (VersionComparison, error) {
	text := strings.TrimSpace(value)
	comparison := VersionComparison{Operator: "="}
	for _, operator := range versionOperators {
		if strings.HasPrefix(text, operator) {
			comparison.Operator = operator
			text = strings.TrimSpace(text[len(operator):])
			break
		}
	}
	match := versionPattern.FindStringSubmatch(text)
	if match == nil {
		return VersionComparison{}, fmt.Errorf("%w: %q is not a version comparison (an operator among <, <=, >, >=, = and a version such as 0.49.0)",
			ErrInvalid, value)
	}
	comparison.Version = match[1]
	return comparison, nil
}

var (
	// ErrInvalid means a selector that does not hold together; the message
	// says where.
	ErrInvalid = errors.New("invalid selector")
	// ErrUnknownGroup means a reference to a group that does not exist.
	ErrUnknownGroup = errors.New("unknown group")
	// ErrCycle means a dynamic group that, through other groups, refers to
	// itself. Such a group has no answer and is refused rather than
	// resolved partially.
	ErrCycle = errors.New("the group refers to itself")
	// ErrUnexpanded means a group reference reached the compiler. Groups
	// are resolved before compilation, so this is a programming error, not
	// an operator's.
	ErrUnexpanded = errors.New("the selector still holds a group reference; expand it first")
)

// Validate checks the shape of a selector as it arrives from a client.
func (e *Expression) Validate() error {
	if e == nil {
		return fmt.Errorf("%w: the selector is empty", ErrInvalid)
	}
	nodes := 0
	return e.validate(1, &nodes, "selector")
}

func (e *Expression) validate(depth int, nodes *int, at string) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: %s is nested deeper than %d levels", ErrInvalid, at, MaxDepth)
	}
	*nodes++
	if *nodes > MaxNodes {
		return fmt.Errorf("%w: more than %d conditions", ErrInvalid, MaxNodes)
	}
	if e.MemberOf != "" {
		return fmt.Errorf("%w: %s names a group by internal identifier; use \"group\"", ErrInvalid, at)
	}

	set := 0
	if len(e.All) > 0 {
		set++
	}
	if len(e.Any) > 0 {
		set++
	}
	if e.Not != nil {
		set++
	}
	for _, fact := range e.leaves() {
		if fact.value != "" {
			set++
		}
	}
	switch {
	case set == 0:
		return fmt.Errorf("%w: %s names no condition", ErrInvalid, at)
	case set > 1:
		return fmt.Errorf("%w: %s sets more than one field; nest conditions under \"all\" or \"any\"", ErrInvalid, at)
	}

	for i := range e.All {
		if err := e.All[i].validate(depth+1, nodes, fmt.Sprintf("%s.all[%d]", at, i)); err != nil {
			return err
		}
	}
	for i := range e.Any {
		if err := e.Any[i].validate(depth+1, nodes, fmt.Sprintf("%s.any[%d]", at, i)); err != nil {
			return err
		}
	}
	if e.Not != nil {
		if err := e.Not.validate(depth+1, nodes, at+".not"); err != nil {
			return err
		}
	}
	for _, fact := range e.leaves() {
		if fact.value == "" {
			continue
		}
		if len(fact.value) > maxValue {
			return fmt.Errorf("%w: %s.%s is longer than %d characters", ErrInvalid, at, fact.name, maxValue)
		}
		if strings.TrimSpace(fact.value) != fact.value {
			return fmt.Errorf("%w: %s.%s has surrounding whitespace", ErrInvalid, at, fact.name)
		}
		switch fact.name {
		case "tag":
			if !TagPattern.MatchString(fact.value) {
				return fmt.Errorf("%w: %s.tag %q is not a tag (key or key=value, lower-case key)", ErrInvalid, at, fact.value)
			}
		case "connection_state":
			if !contains(connectionStates, fact.value) {
				return fmt.Errorf("%w: %s.connection_state %q is not one of %s", ErrInvalid, at, fact.value,
					strings.Join(connectionStates, ", "))
			}
		case "lifecycle_state":
			if !contains(lifecycleStates, fact.value) {
				return fmt.Errorf("%w: %s.lifecycle_state %q is not one of %s", ErrInvalid, at, fact.value,
					strings.Join(lifecycleStates, ", "))
			}
		case "channel":
			if !contains(releaseChannels, fact.value) {
				return fmt.Errorf("%w: %s.channel %q is not one of %s", ErrInvalid, at, fact.value,
					strings.Join(releaseChannels, ", "))
			}
		case "security_updates", "reboot_required", "failed_units":
			if !contains(booleans, fact.value) {
				return fmt.Errorf("%w: %s.%s %q is not true or false", ErrInvalid, at, fact.name, fact.value)
			}
		case "agent_version":
			if _, err := ParseVersionComparison(fact.value); err != nil {
				return fmt.Errorf("%w: %s.agent_version %q is not a version comparison (an operator among <, <=, >, >=, = and a version such as 0.49.0)",
					ErrInvalid, at, fact.value)
			}
		}
	}
	return nil
}

// leaf is one fact of a host together with its column, for the compiler.
type leaf struct {
	name  string
	value string
}

// leaves lists the leaf fields of the node in a fixed order, so that the
// compiled SQL is deterministic and the tests can read it.
func (e *Expression) leaves() []leaf {
	return []leaf{
		{"site", e.Site},
		{"environment", e.Environment},
		{"os_family", e.OSFamily},
		{"tag", e.Tag},
		{"group", e.Group},
		{"capability", e.Capability},
		{"connection_state", e.ConnectionState},
		{"lifecycle_state", e.LifecycleState},
		{"owner", e.Owner},
		{"channel", e.Channel},
		{"os_version", e.OSVersion},
		{"security_updates", e.SecurityUpdates},
		{"reboot_required", e.RebootRequired},
		{"failed_units", e.FailedUnits},
		{"agent_version", e.AgentVersion},
		{"relay", e.Relay},
		{"failure_domain", e.FailureDomain},
		{"group_id", e.MemberOf},
	}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Group is what the expander needs to know about a saved group.
type Group struct {
	ID   string
	Name string
	Kind Kind
	// Selector is the expression of a dynamic group; nil for a static one.
	Selector *Expression
}

// Kind tells a fixed member list from a saved selector.
type Kind string

const (
	KindStatic  Kind = "static"
	KindDynamic Kind = "dynamic"
)

// Groups resolves group references. A nil result with a nil error means
// the group does not exist.
type Groups interface {
	Lookup(ctx context.Context, ref string) (*Group, error)
}

// Expand resolves every group reference in the selector: a static group
// becomes a membership test by identifier, a dynamic one is replaced by
// its own selector, expanded in turn. The input is not changed.
//
// Expansion happens at read time, so a group edited after a campaign was
// recorded does not change what that campaign did - the snapshot of
// targets binds, and the recorded selector says what was asked for.
func Expand(ctx context.Context, e *Expression, groups Groups) (*Expression, error) {
	if e == nil {
		return nil, fmt.Errorf("%w: the selector is empty", ErrInvalid)
	}
	// The bound on the size holds after the expansion as before it: a
	// handful of references to large dynamic groups would otherwise turn a
	// selector that passed validation into one the database has to chew
	// through unbounded. The count runs along with the expansion, so a
	// chain of groups that widened after they were saved is refused at the
	// bound and not after every group behind it was looked up and copied.
	nodes := 0
	expanded, err := expand(ctx, e, groups, nil, &nodes)
	if err != nil {
		return nil, err
	}
	if total := expanded.count(); total > MaxNodes {
		return nil, fmt.Errorf("%w: the expanded selector has %d conditions, more than %d",
			ErrInvalid, total, MaxNodes)
	}
	return expanded, nil
}

// count is the number of nodes of the tree, the root included.
func (e *Expression) count() int {
	if e == nil {
		return 0
	}
	nodes := 1
	for i := range e.All {
		nodes += e.All[i].count()
	}
	for i := range e.Any {
		nodes += e.Any[i].count()
	}
	nodes += e.Not.count()
	return nodes
}

// expand copies the selector with every group reference resolved. nodes
// counts what the copy holds so far: a reference is counted by what
// replaces it, every other node as it is copied, which is the same count
// the finished tree gives - reached one node at a time.
func expand(ctx context.Context, e *Expression, groups Groups, chain []string, nodes *int) (*Expression, error) {
	if e.Group == "" {
		if err := countNode(nodes); err != nil {
			return nil, err
		}
	}
	out := *e
	out.All, out.Any, out.Not = nil, nil, nil
	for i := range e.All {
		child, err := expand(ctx, &e.All[i], groups, chain, nodes)
		if err != nil {
			return nil, err
		}
		out.All = append(out.All, *child)
	}
	for i := range e.Any {
		child, err := expand(ctx, &e.Any[i], groups, chain, nodes)
		if err != nil {
			return nil, err
		}
		out.Any = append(out.Any, *child)
	}
	if e.Not != nil {
		child, err := expand(ctx, e.Not, groups, chain, nodes)
		if err != nil {
			return nil, err
		}
		out.Not = child
	}
	if e.Group == "" {
		return &out, nil
	}

	if groups == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownGroup, e.Group)
	}
	group, err := groups.Lookup(ctx, e.Group)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownGroup, e.Group)
	}
	for _, seen := range chain {
		if seen == group.ID {
			return nil, fmt.Errorf("%w: %q", ErrCycle, group.Name)
		}
	}
	switch group.Kind {
	case KindStatic:
		if err := countNode(nodes); err != nil {
			return nil, err
		}
		return &Expression{MemberOf: group.ID}, nil
	case KindDynamic:
		if group.Selector == nil {
			return nil, fmt.Errorf("%w: the dynamic group %q has no selector", ErrInvalid, group.Name)
		}
		if len(chain) >= MaxExpansion {
			return nil, fmt.Errorf("%w: groups nested deeper than %d levels at %q", ErrInvalid, MaxExpansion, group.Name)
		}
		// The chain is copied: siblings under one "all" must not see each
		// other's path through a shared backing array.
		next := append(append([]string(nil), chain...), group.ID)
		return expand(ctx, group.Selector, groups, next, nodes)
	default:
		return nil, fmt.Errorf("%w: the group %q has an unknown kind %q", ErrInvalid, group.Name, group.Kind)
	}
}

// countNode adds one node to the running count of an expansion and stops
// it at the bound.
func countNode(nodes *int) error {
	*nodes++
	if *nodes > MaxNodes {
		return fmt.Errorf("%w: the expanded selector has more than %d conditions", ErrInvalid, MaxNodes)
	}
	return nil
}

// Compile renders an expanded selector as an SQL condition over the alias
// h of the hosts table. offset is the number of parameters the enclosing
// query already uses; the condition numbers its own from the next one.
//
// The result is one parenthesised condition, so the caller can join it
// with its own by "and" without thinking about precedence.
func Compile(e *Expression, offset int) (string, []any, error) {
	if e == nil {
		return "", nil, fmt.Errorf("%w: the selector is empty", ErrInvalid)
	}
	c := compiler{offset: offset}
	condition, err := c.node(e)
	if err != nil {
		return "", nil, err
	}
	return condition, c.args, nil
}

type compiler struct {
	offset int
	args   []any
}

// param records an argument and returns its placeholder.
func (c *compiler) param(value any) string {
	c.args = append(c.args, value)
	return fmt.Sprintf("$%d", c.offset+len(c.args))
}

func (c *compiler) node(e *Expression) (string, error) {
	switch {
	case len(e.All) > 0:
		return c.join(e.All, " and ")
	case len(e.Any) > 0:
		return c.join(e.Any, " or ")
	case e.Not != nil:
		inner, err := c.node(e.Not)
		if err != nil {
			return "", err
		}
		return "not " + inner, nil
	case e.Site != "":
		return "h.site = " + c.param(e.Site), nil
	case e.Environment != "":
		return "h.environment = " + c.param(e.Environment), nil
	case e.OSFamily != "":
		return "h.os_family = " + c.param(e.OSFamily), nil
	case e.Tag != "":
		// Containment rather than "= any": the GIN index on the column
		// answers containment, and the list filter uses the same form.
		return "h.tags @> " + c.param([]string{e.Tag}) + "::text[]", nil
	case e.Capability != "":
		return "exists (select 1 from host_capability_registry r" +
			" where r.host_id = h.id and r.name = " + c.param(e.Capability) + " and r.available)", nil
	case e.ConnectionState != "":
		return "h.connection_state = " + c.param(e.ConnectionState), nil
	case e.LifecycleState != "":
		return "h.lifecycle_state = " + c.param(e.LifecycleState), nil
	case e.Owner != "":
		return "h.owner = " + c.param(e.Owner), nil
	case e.Channel != "":
		return "h.release_channel = " + c.param(e.Channel), nil
	case e.OSVersion != "":
		return "starts_with(h.os_version, " + c.param(e.OSVersion) + ")", nil
	case e.SecurityUpdates != "":
		// A count of null is a host that has not reported; the comparison
		// leaves it out of both answers, the way the host list does.
		if e.SecurityUpdates == "true" {
			return "h.pending_security_updates > 0", nil
		}
		return "h.pending_security_updates = 0", nil
	case e.RebootRequired != "":
		return "h.reboot_required = " + e.RebootRequired, nil
	case e.FailedUnits != "":
		if e.FailedUnits == "true" {
			return "h.failed_units > 0", nil
		}
		return "h.failed_units = 0", nil
	case e.AgentVersion != "":
		comparison, err := ParseVersionComparison(e.AgentVersion)
		if err != nil {
			return "", err
		}
		// The version is ordered numerically part by part, the same way
		// the host list orders it; a host whose version does not parse is
		// left out of every comparison rather than compared as text.
		return "(h.agent_version ~ '^v?\\d+(\\.\\d+)*' and " + VersionParts("h") + " " + comparison.Operator +
			" string_to_array(" + c.param(comparison.Version) + ", '.')::int[])", nil
	case e.Relay != "":
		// The session, not the host, says which route it took. A reference
		// that parses as an identifier is one; anything else is the name.
		if _, err := uuid.Parse(e.Relay); err == nil {
			return "exists (select 1 from agent_sessions s" +
				" where s.host_id = h.id and s.ended_at is null and s.relay_id = " + c.param(e.Relay) + "::uuid)", nil
		}
		return "exists (select 1 from agent_sessions s join relays r on r.id = s.relay_id" +
			" where s.host_id = h.id and s.ended_at is null and r.name = " + c.param(e.Relay) + ")", nil
	case e.FailureDomain != "":
		return "h.failure_domain = " + c.param(e.FailureDomain), nil
	case e.MemberOf != "":
		return "exists (select 1 from host_group_members m" +
			" where m.group_id = " + c.param(e.MemberOf) + "::uuid and m.host_id = h.id)", nil
	case e.Group != "":
		return "", fmt.Errorf("%w: %q", ErrUnexpanded, e.Group)
	default:
		return "", fmt.Errorf("%w: a node names no condition", ErrInvalid)
	}
}

// VersionParts renders the agent version of the aliased host row as an
// array of integers, so two versions compare part by part rather than as
// text - '0.10.0' after '0.9.0', not before it. It reads only a version
// the caller has already matched against the same pattern.
func VersionParts(alias string) string {
	return "string_to_array(substring(" + alias + ".agent_version from '^v?(\\d+(?:\\.\\d+)*)'), '.')::int[]"
}

func (c *compiler) join(children []Expression, operator string) (string, error) {
	parts := make([]string, 0, len(children))
	for i := range children {
		part, err := c.node(&children[i])
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return "(" + strings.Join(parts, operator) + ")", nil
}

// Describe renders the selector in one line for people: the audit detail,
// a log line, the scope bar. It is not a grammar and is not parsed back.
func (e *Expression) Describe() string {
	if e == nil {
		return ""
	}
	switch {
	case len(e.All) > 0:
		return "(" + describeList(e.All, " and ") + ")"
	case len(e.Any) > 0:
		return "(" + describeList(e.Any, " or ") + ")"
	case e.Not != nil:
		return "not " + e.Not.Describe()
	}
	for _, fact := range e.leaves() {
		if fact.value == "" {
			continue
		}
		if fact.name == "agent_version" {
			// The value already carries its operator: "agent_version < 0.49.0",
			// not "agent_version=< 0.49.0".
			if comparison, err := ParseVersionComparison(fact.value); err == nil {
				return fact.name + " " + comparison.String()
			}
		}
		return fact.name + "=" + fact.value
	}
	return "nothing"
}

func describeList(children []Expression, operator string) string {
	parts := make([]string, 0, len(children))
	for i := range children {
		parts = append(parts, children[i].Describe())
	}
	return strings.Join(parts, operator)
}
