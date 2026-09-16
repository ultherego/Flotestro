package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/helpercap"
)

// helperTrustCommands routes the subcommands that touch what the root
// helper trusts: the host identity and the panel's capability keys.
func helperTrustCommands(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "helper-trust needs a subcommand: show, reset")
		return 2
	}
	switch args[0] {
	case "show":
		return helperTrustShowCommand(args[1:], out, errOut)
	case "reset":
		return helperTrustResetCommand(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown helper-trust subcommand: %s\n", args[0])
		return 2
	}
}

// helperTrustStore reads the helper's settings the way the helper does,
// so the command looks where the helper keeps its files.
func helperTrustStore(errOut io.Writer) (helpercap.TrustStore, helpercap.Settings, bool) {
	settings, err := helpercap.LoadSettings(config.Env("FLOTESTRO_HELPER_CONFIG", helpercap.DefaultConfigPath))
	if err != nil {
		fmt.Fprintf(errOut, "the helper's settings: %v\n", err)
		return helpercap.TrustStore{}, settings, false
	}
	return helpercap.TrustStore{Dir: settings.TrustDir, HostIDPath: settings.HostIDPath}, settings, true
}

// helperTrustShowCommand prints the identity and the keys. The files
// belong to root, so the command is run as root; without it the answer is
// what an unprivileged process may see, which is nothing.
func helperTrustShowCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("helper-trust show", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	store, settings, ok := helperTrustStore(errOut)
	if !ok {
		return 1
	}
	hostID, err := store.HostID()
	if err != nil {
		fmt.Fprintf(errOut, "the host identity: %v\n", err)
		return 1
	}
	keyring, skipped, err := store.Keyring()
	if err != nil {
		fmt.Fprintf(errOut, "the trusted keys: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Mode:         %s (%s)\n", settings.Mode, settings.Source)
	if hostID == "" {
		fmt.Fprintf(out, "Host:         none yet (%s)\n", settings.HostIDPath)
	} else {
		fmt.Fprintf(out, "Host:         %s\n", hostID)
	}
	ids := keyring.IDs()
	if len(ids) == 0 {
		fmt.Fprintf(out, "Trusted keys: none (%s)\n", settings.TrustDir)
	}
	for _, id := range ids {
		fmt.Fprintf(out, "Trusted key:  %s\n", id)
	}
	for _, name := range skipped {
		fmt.Fprintf(out, "Not a key:    %s\n", name)
	}
	switch {
	case hostID != "" && len(ids) == 0:
		fmt.Fprintln(out, "The helper has an identity but trusts no key: it will refuse every bundle until the keys are restored or the identity is reset.")
		return 1
	case hostID == "" && len(ids) == 0:
		fmt.Fprintln(out, "The helper takes the first bundle of the panel on trust at the next session.")
	}
	return 0
}

// helperTrustResetCommand forgets the identity and the keys.
//
// This is the decision that the host is a new machine to the panel: it
// was enrolled anew, and the panel that signed what the helper trusted may
// be gone. The next session hands the helper the current panel's bundle,
// and that one is taken on trust. Only root can do it, and a typed host
// name stands in for the second person of the panel.
func helperTrustResetCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("helper-trust reset", flag.ContinueOnError)
	flags.SetOutput(errOut)
	confirm := flags.String("confirm", "", "the name of this host, typed as the confirmation")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	hostname, _ := os.Hostname()
	if *confirm == "" || *confirm != hostname {
		fmt.Fprintf(errOut, "the reset forgets what the helper trusts; confirm it with --confirm %s\n", hostname)
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(errOut, "the files of the helper belong to root; run the command as root")
		return 1
	}
	store, _, ok := helperTrustStore(errOut)
	if !ok {
		return 1
	}
	if err := store.Reset(); err != nil {
		fmt.Fprintf(errOut, "the reset failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(out, "The helper's identity and keys were forgotten; the next session of the agent hands it the panel's bundle, which is taken on trust.")
	return 0
}
