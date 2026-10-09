package opspec

import (
	"reflect"
	"strings"
	"sync"
)

// PayloadGroup says which group of Payload an operation reads: "unit" for
// unit.restart, "journal" for journal.read, and "" for an operation that needs
// no payload at all.
//
// It is derived from the validator rather than listed beside it. A list would be
// a second place to change for every operation added, and the kind of second
// place that is right on the day it is written: the reference page carries the
// same fact in a column, and nothing compared the two. Validate refuses an
// operation whose group is absent, so the group is the one whose presence stops
// it refusing - which is a question the validator can be asked, once, rather
// than a claim made alongside it.
func PayloadGroup(action ActionType) string { return Shape(action).Group }

// payloadField is one group of Payload: where it sits and what to allocate.
type payloadField struct {
	name    string
	index   int
	element reflect.Type
}

var payloadGroupsOnce = sync.OnceValue(func() []payloadField {
	shape := reflect.TypeFor[Payload]()
	fields := make([]payloadField, 0, shape.NumField())
	for i := range shape.NumField() {
		field := shape.Field(i)
		if field.Type.Kind() != reflect.Pointer {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		fields = append(fields, payloadField{name: name, index: i, element: field.Type.Elem()})
	}
	return fields
})

func payloadGroups() []payloadField { return payloadGroupsOnce() }

// PayloadGroups is every group a payload can carry, in the order the type
// declares them.
func PayloadGroups() []string {
	groups := payloadGroups()
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.name)
	}
	return names
}
