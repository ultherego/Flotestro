// Command control-plane runs the API, the agent gateway and the enrollment
// endpoint. What it runs is internal/app; this file is the entry point and
// nothing else, so that everything the process does is in a package something
// can import.
package main

import (
	"log/slog"
	"os"

	"github.com/ultherego/flotestro/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		slog.Error("the control plane ended with an error", "err", err)
		os.Exit(1)
	}
}
