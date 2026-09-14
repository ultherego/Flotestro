package main

import "github.com/ultherego/flotestro/internal/buildinfo"

// version is the version of the relay: the tool and the daemon come in one
// package and must not drift apart in their number.
var version = buildinfo.Version
