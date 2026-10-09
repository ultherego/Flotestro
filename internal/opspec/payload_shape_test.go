package opspec

import (
	"reflect"
	"strings"
	"testing"
)

// The panel offers the payload a wizard starts from. For an operation with a
// hand-written template that is the template; for everything else it was an
// empty object - and not one of the 24 fan-out reads has a template. An
// operator ordering journal.read across the fleet was given {} and no way to
// learn from the panel that the operation is refused without a line count.
//
// So every read that is refused without a payload has to name the group it
// reads.
func TestEveryFanOutReadNamesTheGroupItReads(t *testing.T) {
	described := 0
	for _, action := range AllActions() {
		if action.FanOutLimit() == 0 || Validate(action, Payload{}) == nil {
			continue
		}
		if Shape(action).Group == "" {
			t.Errorf("%s is refused without a payload and names no group, so the panel can "+
				"say nothing about what goes in it (the validator says: %v)",
				action, Validate(action, Payload{}))
			continue
		}
		described++
	}
	if described == 0 {
		t.Fatal("no fan-out read needs a payload, which is not this product; the guard stopped reading")
	}
	t.Logf("%d fan-out reads name the group they read", described)
}

// A named field has to be a field of the group, written the way a caller writes
// it. A name that is not in the type is a name the panel would put in a
// skeleton its own API then refuses.
func TestEveryNamedFieldIsAFieldOfItsGroup(t *testing.T) {
	known := fieldsByGroup()
	checked := 0
	for _, action := range AllActions() {
		shape := Shape(action)
		if shape.Group == "" {
			continue
		}
		names, found := known[shape.Group]
		if !found {
			t.Errorf("%s reads the group %q, which Payload does not declare", action, shape.Group)
			continue
		}
		for _, field := range shape.Fields {
			checked++
			if !names[field.Name] {
				t.Errorf("%s names %q, which is not a field of %q", action, field.Name, shape.Group)
			}
			switch field.Kind {
			case "string", "number", "boolean", "array", "object":
			default:
				t.Errorf("%s names %q with the kind %q, which a caller cannot write",
					action, field.Name, field.Kind)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no operation named a field, so this guard compared nothing")
	}
	t.Logf("%d named fields compared with the type they belong to", checked)
}

// What the two shapes claim, asked of the validator.
//
// An empty list of fields beside a group is a claim: the group on its own is
// accepted. docker.read, packages.plan and process.list are like that, and
// {"docker_read":{}} is a payload the panel can offer as it stands.
//
// A list of fields is the other claim: the group on its own is not enough, and
// these are the fields the refusal is about. Both have to hold, or the panel
// builds a skeleton that is refused and the operator is no better off than
// with the empty object.
func TestTheShapeClaimsOnlyWhatTheValidatorAgreesWith(t *testing.T) {
	groups := map[string]payloadField{}
	for _, group := range payloadGroups() {
		groups[group.name] = group
	}
	bare, named := 0, 0
	for _, action := range AllActions() {
		shape := Shape(action)
		if shape.Group == "" {
			continue
		}
		group := groups[shape.Group]
		alone := Validate(action, withGroup(group, nil))
		if len(shape.Fields) == 0 {
			bare++
			if alone != nil {
				t.Errorf("%s names the group %q and no field, which says the group alone is "+
					"accepted - and it is refused: %v", action, shape.Group, alone)
			}
			continue
		}
		named++
		if alone == nil {
			t.Errorf("%s names the fields %v, which says the group alone is not enough - "+
				"and the group alone is accepted", action, shape.Fields)
			continue
		}
		// Filling what was named has to move that refusal. Whether the result
		// is accepted is another matter: a path of "x" is refused for not being
		// absolute, and that is about the value, not about the absence.
		filled := withGroup(group, indexesOf(group, shape.Fields))
		if after := Validate(action, filled); !differs(after, alone) {
			t.Errorf("%s names %v and filling every one of them leaves the same refusal (%v), "+
				"so those are not the fields it is about", action, shape.Fields, alone)
		}
	}
	if bare == 0 || named == 0 {
		t.Fatalf("the guard saw %d operations accepting a bare group and %d naming fields; "+
			"it is meant to see both", bare, named)
	}
	t.Logf("%d operations accept a bare group, %d name the fields their refusal is about", bare, named)
}

// Two fields wanted together are the case a single-field probe cannot see:
// the refusal names both and no one field moves it. Joining a domain is that
// case, and it is in the product rather than in a fixture.
func TestFieldsWantedTogetherAreBothNamed(t *testing.T) {
	shape := Shape(ActionType("identity.host.preflight"))
	if shape.Group != "domain_enroll" {
		t.Fatalf("the preflight reads %q; this test is written about domain_enroll", shape.Group)
	}
	for _, want := range []string{"domain", "realm"} {
		if !containsName(shape.Fields, want) {
			t.Errorf("the preflight is refused with %q and does not name %q: %v",
				Validate(ActionType("identity.host.preflight"), withGroup(
					payloadGroupNamed(t, "domain_enroll"), nil)), want, shape.Fields)
		}
	}
}

// And a field that is one of two alternatives is named too: a renewal takes a
// request identifier or a certificate path, so neither is required on its own
// and the panel still has to offer both.
func TestEitherFieldOfAnAlternativeIsNamed(t *testing.T) {
	shape := Shape(ActionType("certificate.renew"))
	for _, want := range []string{"path", "request"} {
		if !containsName(shape.Fields, want) {
			t.Errorf("a renewal takes a request identifier or a certificate path and the "+
				"shape does not name %q: %v", want, shape.Fields)
		}
	}
}

func fieldsByGroup() map[string]map[string]bool {
	shape := reflect.TypeFor[Payload]()
	byGroup := map[string]map[string]bool{}
	for i := range shape.NumField() {
		field := shape.Field(i)
		if field.Type.Kind() != reflect.Pointer {
			continue
		}
		group, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		names := map[string]bool{}
		inner := field.Type.Elem()
		for j := range inner.NumField() {
			name, _, _ := strings.Cut(inner.Field(j).Tag.Get("json"), ",")
			if name != "" && name != "-" {
				names[name] = true
			}
		}
		byGroup[group] = names
	}
	return byGroup
}

func indexesOf(group payloadField, named []PayloadFieldName) []int {
	indexes := make([]int, 0, len(named))
	for i := range group.element.NumField() {
		name, settable := fieldName(group, i)
		if settable && containsName(named, name) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func containsName(named []PayloadFieldName, name string) bool {
	for _, each := range named {
		if each.Name == name {
			return true
		}
	}
	return false
}

func payloadGroupNamed(t *testing.T, name string) payloadField {
	t.Helper()
	for _, group := range payloadGroups() {
		if group.name == name {
			return group
		}
	}
	t.Fatalf("Payload declares no group %q", name)
	return payloadField{}
}
