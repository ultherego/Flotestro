// Package runscope carries the resource scope of an operation down to the
// modules that start their own tools.
//
// The helper decides per request whether the tools of an operation run in a
// transient scope, and how that scope is spelled: a systemd-run invocation
// that goes in front of the tool. The package managers and the backup tools
// are started by their own modules, which know nothing of the helper - so
// the prefix travels in the context, and the module applies it at the one
// place it builds a command. A context without a scope leaves the argument
// array alone: the same modules serve the agent, which never scopes.
//
// The package imports nothing of the project on purpose: it sits under the
// modules and the helper alike, and a cycle here would tie the package
// manager to the process that happens to start it.
package runscope

import "context"

// Wrap transforms the argument array of a tool right before it starts. The
// array it gets is the full invocation - the path of the tool first - and
// the array it returns is what gets executed. Nothing in it is interpreted:
// a wrap prefixes, it does not quote.
type Wrap func(argv []string) []string

// key is the context key of the wrap; unexported, so that only this package
// reads and writes it.
type key struct{}

// With records the wrap in the context. A nil wrap clears one recorded
// higher up, so a caller can make sure a plain run is a plain run.
func With(ctx context.Context, wrap Wrap) context.Context {
	return context.WithValue(ctx, key{}, wrap)
}

// Apply returns the argument array the context asks for: the wrapped one
// when a wrap is recorded, the same one otherwise. An empty array is never
// wrapped - there is no tool to put under a scope.
func Apply(ctx context.Context, argv []string) []string {
	wrap, _ := ctx.Value(key{}).(Wrap)
	if wrap == nil || len(argv) == 0 {
		return argv
	}
	return wrap(argv)
}

// Prefixed builds the invocation of a tool behind a fixed prefix. The
// result is a fresh array: the prefix is shared by every tool of an
// operation, and appending to it in place would let two tools started at
// once write into the same backing store.
func Prefixed(prefix, argv []string) []string {
	out := make([]string, 0, len(prefix)+len(argv))
	out = append(out, prefix...)
	return append(out, argv...)
}
