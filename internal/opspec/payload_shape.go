package opspec

import (
	"reflect"
	"sort"
	"strings"
	"sync"
)

// PayloadShape is what an operation wants in its payload: the group it reads
// and the fields without which the validator refuses it.
type PayloadShape struct {
	// Group is the field of Payload the operation reads, or "" for an
	// operation that needs no payload at all.
	Group string
	// Fields are the fields of Group the validator is about, as a caller writes
	// them. It may want all of them - joining a domain takes a domain and a
	// realm - or one of them: a renewal takes a request identifier or a
	// certificate path, and its refusal says so. An empty list beside a group
	// means the group on its own is accepted, which is an answer and not a
	// silence.
	Fields []PayloadFieldName
}

// PayloadFieldName is one field of a payload group: the name a caller writes
// and what shape of value goes in it. The kind is there so that a skeleton can
// be offered with a value of the right sort rather than a null the operation
// then refuses.
type PayloadFieldName struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Shape asks the validator what an operation wants, rather than being told
// beside it.
//
// The group alone was not enough for a caller. The panel offered an empty
// object for every fan-out read and the operator had a skeleton with nothing
// in it: 24 reads, and for 17 of them the registry said nothing about what
// goes inside. A list of required fields written next to the validator would
// be the second place that is right on the day it is written - the reference
// page already carries such a column, and nothing compared the two until a
// test did.
//
// The derivation asks the validator two questions about each field. Does its
// presence move the refusal of an otherwise empty group - which finds the one
// field an operation is waiting for. And does its absence break a payload that
// is otherwise complete - which finds the fields wanted together, where one
// refusal names them all and no single field moves it: joining a domain is
// refused with "joining requires a domain and a realm" until both are there.
//
// The group is found the same way, by presence first and then by its fields:
// file.read reads the path through a nil-safe accessor, so an absent group and
// an empty one are the same refusal and only a field tells them apart.
func Shape(action ActionType) PayloadShape {
	cached, _ := payloadShapeCache.LoadOrStore(action, deriveShape(action))
	shape, _ := cached.(PayloadShape)
	return shape
}

var payloadShapeCache sync.Map

func deriveShape(action ActionType) PayloadShape {
	if !action.Known() {
		return PayloadShape{}
	}
	refusal := Validate(action, Payload{})
	if refusal == nil {
		// The operation takes no payload, so there is nothing to describe.
		return PayloadShape{}
	}
	for _, group := range payloadGroups() {
		// The group on its own. An operation that reads its payload through a
		// nil-safe accessor is unmoved by this and answers below.
		present := Payload{}
		value := reflect.ValueOf(&present).Elem()
		value.Field(group.index).Set(reflect.New(group.element))
		if changed(action, present, refusal) {
			return PayloadShape{Group: group.name, Fields: fieldsOf(action, group)}
		}
	}
	for _, group := range payloadGroups() {
		if fields := fieldsOf(action, group); len(fields) > 0 {
			return PayloadShape{Group: group.name, Fields: fields}
		}
	}
	// Something is wanted and none of the groups is it: an operation refused
	// for a reason outside the payload, which is not this function's to name.
	return PayloadShape{}
}

// fieldsOf asks both questions of every field of one group.
func fieldsOf(action ActionType, group payloadField) []PayloadFieldName {
	empty := withGroup(group, nil)
	emptyRefusal := Validate(action, empty)
	// Whether this group's fields do anything at all. Without this the test
	// below is trivially true for a group the operation never reads: the
	// refusal is the same with the field and without it, so every field of
	// every foreign group looked like one the refusal was about - and file.read
	// came back naming "unit".
	complete := Validate(action, withGroup(group, everyField(group)))
	engaged := differs(complete, emptyRefusal)
	matters := map[string]bool{}
	for i := range group.element.NumField() {
		name, settable := fieldName(group, i)
		if !settable {
			continue
		}
		// Its presence, on its own, against an empty group.
		if emptyRefusal != nil && differs(Validate(action, withGroup(group, []int{i})), emptyRefusal) {
			matters[name] = true
			continue
		}
		// Its absence, from a payload that is otherwise complete: a field whose
		// removal brings back the refusal the bare group got is a field that
		// refusal is about. Two fields wanted together are found only this way -
		// "joining requires a domain and a realm" does not move for either of
		// them alone.
		//
		// It is asked only where the bare group is refused. Where it is
		// accepted there is nothing missing, and the removal of a field from a
		// complete payload says something else entirely: journal.follow refuses
		// an "until", which belongs to journal.read, so dropping it is what
		// makes that payload acceptable - and reading the comparison the other
		// way had the panel offering the one field the operation forbids.
		if emptyRefusal != nil && engaged &&
			!differs(Validate(action, withGroup(group, everyFieldBut(group, i))), emptyRefusal) {
			matters[name] = true
		}
	}
	names := make([]PayloadFieldName, 0, len(matters))
	for i := range group.element.NumField() {
		name, settable := fieldName(group, i)
		if settable && matters[name] {
			names = append(names, PayloadFieldName{
				Name: name, Kind: kindOf(group.element.Field(i).Type)})
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	return names
}

// kindOf is the shape of a value as a caller writes it in JSON.
func kindOf(shape reflect.Type) string {
	for shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	switch shape.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return "array"
	default:
		return "object"
	}
}

// withGroup builds a payload carrying one group with the named fields set.
func withGroup(group payloadField, indexes []int) Payload {
	payload := Payload{}
	value := reflect.ValueOf(&payload).Elem()
	value.Field(group.index).Set(reflect.New(group.element))
	body := value.Field(group.index).Elem()
	for _, i := range indexes {
		if target := body.Field(i); target.CanSet() {
			target.Set(plausibleValue(group.element.Field(i).Type))
		}
	}
	return payload
}

func everyField(group payloadField) []int {
	indexes := make([]int, 0, group.element.NumField())
	for i := range group.element.NumField() {
		if _, settable := fieldName(group, i); settable {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func everyFieldBut(group payloadField, omitted int) []int {
	kept := make([]int, 0, group.element.NumField())
	for _, i := range everyField(group) {
		if i != omitted {
			kept = append(kept, i)
		}
	}
	return kept
}

// fieldName is the name a caller writes for one field, and whether it can be
// set at all.
func fieldName(group payloadField, i int) (string, bool) {
	field := group.element.Field(i)
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "" || name == "-" || !field.IsExported() {
		return "", false
	}
	return name, true
}

// differs compares two outcomes of the validator by what they say.
func differs(a, b error) bool {
	switch {
	case a == nil && b == nil:
		return false
	case a == nil || b == nil:
		return true
	default:
		return a.Error() != b.Error()
	}
}

// changed says whether this payload moves the refusal.
func changed(action ActionType, payload Payload, refusal error) bool {
	next := Validate(action, payload)
	return next == nil || next.Error() != refusal.Error()
}

// plausibleValue is a value of the right type and nothing more. It is not a
// value the validator has to accept: a path of "x" is refused for not being
// absolute, and that refusal is itself the answer - the field was wanted.
func plausibleValue(shape reflect.Type) reflect.Value {
	switch shape.Kind() {
	case reflect.String:
		return reflect.ValueOf("x").Convert(shape)
	case reflect.Bool:
		return reflect.ValueOf(true).Convert(shape)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflect.ValueOf(int64(1)).Convert(shape)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflect.ValueOf(uint64(1)).Convert(shape)
	case reflect.Float32, reflect.Float64:
		return reflect.ValueOf(1.0).Convert(shape)
	case reflect.Slice:
		one := reflect.MakeSlice(shape, 1, 1)
		one.Index(0).Set(plausibleValue(shape.Elem()))
		return one
	case reflect.Map:
		one := reflect.MakeMap(shape)
		one.SetMapIndex(plausibleValue(shape.Key()), plausibleValue(shape.Elem()))
		return one
	case reflect.Pointer:
		return reflect.New(shape.Elem())
	default:
		return reflect.Zero(shape)
	}
}
