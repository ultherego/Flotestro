// Package runscope carries the resource scope of an operation down to the
// modules that start their own tools.
package runscope

import "context"

// Wrap transforms the argument array of a tool right before it starts.
type Wrap func(argv []string) []string

// key is the context key of the wrap; unexported, so that only this package
// reads and writes it.
type key struct{}

// With records the wrap in the context. A nil wrap clears one recorded
// higher up, so a caller can make sure a plain run is a plain run.
func With(ctx context.Context, wrap Wrap) context.Context {
	return context.WithValue(ctx, key{}, wrap)
}

// Apply returns the argument array the context asks for: the wrapped one when
// a wrap is recorded, the same one otherwise.
func Apply(ctx context.Context, argv []string) []string {
	wrap, _ := ctx.Value(key{}).(Wrap)
	if wrap == nil || len(argv) == 0 {
		return argv
	}
	return wrap(argv)
}

// Prefixed builds the invocation of a tool behind a fixed prefix.
func Prefixed(prefix, argv []string) []string {
	out := make([]string, 0, len(prefix)+len(argv))
	out = append(out, prefix...)
	return append(out, argv...)
}
