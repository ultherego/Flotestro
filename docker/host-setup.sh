#!/usr/bin/env sh
#
# What a host needs once, before the first "up", so that the panel is still
# there after the machine reboots.
#
# Under the Docker daemon there is nothing to do: the daemon starts with the
# machine and brings the containers back with it. Rootless Podman has no
# daemon, so two things are set for the account that runs the deployment -
# lingering, which keeps the containers alive after the last logout, and the
# unit Podman ships, which replays the restart policies at boot. Run as root,
# the same unit is enabled at system scope and there is no lingering to set.
#
# It is safe to run again: it changes only what is not already set, and says
# what it found either way.
#
#   ./host-setup.sh          - set what is missing
#   ./host-setup.sh --check  - say what is missing and change nothing
set -eu

check_only=no
case "${1:-}" in
    --check) check_only=yes ;;
    "") ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

say() { printf 'host-setup: %s\n' "$1"; }
missing=0

# The last thing both paths do: what is set on the host only matters if the
# containers ask to be brought back at all. A compose file edited to say
# "unless-stopped" would leave the host set up correctly and the panel down
# after every reboot, which is the hardest version of this to notice.
finish() {
    for file in compose.yaml compose.relay.yaml; do
        [ -f "$(dirname "$0")/$file" ] || continue
        if grep -q 'restart: unless-stopped' "$(dirname "$0")/$file"; then
            missing=$((missing + 1))
            say "$file says 'restart: unless-stopped'; the unit above starts only 'always', so those containers would not come back"
        fi
    done

    if [ "$check_only" = yes ] && [ "$missing" -gt 0 ]; then
        say "$missing thing(s) to fix; run this without --check"
        exit 1
    fi
    say "this host brings the deployment back after a reboot"
}

if ! command -v podman >/dev/null 2>&1; then
    say "podman is not installed here; under the Docker daemon a reboot needs nothing set"
    exit 0
fi
# Rootful Podman has no lingering and no user manager to ask: the containers
# belong to the system, and so does the unit that replays their restart
# policies. This used to print that unit's name and exit 0, which told the
# operator the host was ready when nothing had been done to it.
if [ "$(id -u)" = 0 ]; then
    say "this is root; the deployment is started by the system's podman-restart.service"
    if systemctl is-enabled podman-restart.service >/dev/null 2>&1; then
        say "podman-restart.service is enabled"
    else
        missing=$((missing + 1))
        if [ "$check_only" = yes ]; then
            say "podman-restart.service is NOT enabled - nothing starts the containers after a reboot"
        elif systemctl enable podman-restart.service >/dev/null 2>&1; then
            say "podman-restart.service enabled"
        else
            say "podman-restart.service could not be enabled; it comes with the podman package, and this host has to be able to run systemctl enable"
            exit 1
        fi
    fi
    finish
    exit 0
fi

account="$(id -un)"

# systemctl --user needs the account's own session bus. Run from cron, from a
# sudo without a session or from a shell that has neither, it answers "not
# enabled" for everything, which reads like a host that needs fixing rather
# than a check that could not be made.
if ! systemctl --user show-environment >/dev/null 2>&1; then
    say "this shell cannot reach the user manager of $account"
    say "run it from a session of that account - ssh in as $account, or:"
    say "  sudo -u $account XDG_RUNTIME_DIR=/run/user/$(id -u) $0 ${1:-}"
    exit 1
fi

# Lingering: without it the containers stop with the last session of the
# account, which is what closing an SSH window does.
if [ "$(loginctl show-user "$account" -p Linger --value 2>/dev/null || echo no)" = yes ]; then
    say "lingering is on for $account"
else
    missing=$((missing + 1))
    if [ "$check_only" = yes ]; then
        say "lingering is OFF for $account - the deployment stops with the session"
    elif loginctl enable-linger "$account" 2>/dev/null; then
        say "lingering turned on for $account"
    else
        say "lingering could not be turned on; run: sudo loginctl enable-linger $account"
        exit 1
    fi
fi

# The unit that replays the restart policies at boot. It starts the containers
# whose policy is "always", which is what the compose files of this product
# say, and nothing else - a deployment that said "unless-stopped" would be
# skipped by it silently.
if systemctl --user is-enabled podman-restart.service >/dev/null 2>&1; then
    say "podman-restart.service is enabled"
else
    missing=$((missing + 1))
    if [ "$check_only" = yes ]; then
        say "podman-restart.service is NOT enabled - nothing starts the containers after a reboot"
    elif systemctl --user enable podman-restart.service >/dev/null 2>&1; then
        say "podman-restart.service enabled"
    else
        say "podman-restart.service could not be enabled; it comes with the podman package"
        exit 1
    fi
fi

# And the thing the two of them act on.
finish
