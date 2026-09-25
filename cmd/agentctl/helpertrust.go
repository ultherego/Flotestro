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
		fmt.Fprintln(errOut, "helper-trust needs a subcommand: show, pin, reset")
		return 2
	}
	switch args[0] {
	case "show":
		return helperTrustShowCommand(args[1:], out, errOut)
	case "pin":
		return helperTrustPinCommand(args[1:], out, errOut)
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
	return helpercap.TrustStore{Dir: settings.TrustDir, HostIDPath: settings.HostIDPath,
		PinPath: settings.PinPath, Bootstrap: settings.Bootstrap}, settings, true
}

// helperTrustShowCommand prints the identity and the keys.
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
	pins, pinErr := store.Pins()
	fmt.Fprintf(out, "Mode:         %s (%s)\n", settings.Mode, settings.Source)
	fmt.Fprintf(out, "Bootstrap:    %s (%s)\n", settings.Bootstrap, settings.PinPath)
	switch {
	case pinErr != nil:
		fmt.Fprintf(out, "Pinned panel: unreadable: %v\n", pinErr)
	case len(pins) == 0:
		fmt.Fprintln(out, "Pinned panel: none")
	}
	for _, pin := range pins {
		fmt.Fprintf(out, "Pinned panel: %s\n", pin)
	}
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
	case hostID != "" || len(ids) != 0:
	case len(pins) > 0:
		fmt.Fprintln(out, "The helper enrolls at the next session with the panel pinned above, and with no other.")
	case settings.Bootstrap == helpercap.BootstrapPinned:
		fmt.Fprintln(out, "The helper enrolls with nobody: it takes no panel on trust and no panel is pinned. Pin one with flotestro-agentctl helper-trust pin.")
		return 1
	default:
		fmt.Fprintln(out, "The helper takes the first bundle of the panel on trust at the next session. Pin the panel to decide which one that is.")
	}
	return 0
}

// helperTrustPinCommand names the panels this host may be enrolled by. The
// fingerprints are the ones the panel prints when it starts.
func helperTrustPinCommand(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("helper-trust pin", flag.ContinueOnError)
	flags.SetOutput(errOut)
	clear := flags.Bool("clear", false, "remove the pins, putting the host back on first-use trust")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*clear && flags.NArg() == 0 {
		fmt.Fprintln(errOut, "helper-trust pin takes the SHA-256 fingerprints of the panel, or --clear")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(errOut, "the files of the helper belong to root; run the command as root")
		return 1
	}
	store, settings, ok := helperTrustStore(errOut)
	if !ok {
		return 1
	}
	if err := store.WritePins(flags.Args()); err != nil {
		fmt.Fprintf(errOut, "the pin was not written: %v\n", err)
		return 1
	}
	if *clear {
		fmt.Fprintf(out, "The pins were removed from %s.\n", settings.PinPath)
		return 0
	}
	fmt.Fprintf(out, "%s now names %d panel(s); an enrollment by any other is refused.\n",
		settings.PinPath, flags.NArg())
	return 0
}

// helperTrustResetCommand forgets the identity and the keys.
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
