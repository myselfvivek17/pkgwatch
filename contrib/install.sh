#!/bin/sh
# Install pkgwatch on Linux or macOS, and leave it running.
#
#   sh contrib/install.sh              # agent (the usual case)
#   sh contrib/install.sh --hub        # hub as well
#   sh contrib/install.sh --no-service # binary only, start it yourself
#
# There are no published releases yet, so this does NOT download anything: it
# builds from the checkout it is run in, or installs a binary you point it at
# with --binary. A supply-chain tool whose installer piped an unsigned build
# from the internet would be a poor advertisement for itself.
#
# Everything it does is reversible and printed as it happens.

set -eu

PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
BINARY=""
WANT_HUB=0
WANT_SERVICE=1

while [ $# -gt 0 ]; do
    case "$1" in
        --hub) WANT_HUB=1 ;;
        --no-service) WANT_SERVICE=0 ;;
        --binary) shift; BINARY="${1:-}" ;;
        --prefix) shift; PREFIX="${1:-}"; BIN_DIR="$PREFIX/bin" ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

say() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------- the binary

if [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] || { say "no such file: $BINARY"; exit 1; }
else
    command -v go >/dev/null 2>&1 || {
        say "Go is not installed, so there is nothing to build from."
        say "Either install Go, or build elsewhere and pass --binary <path>."
        exit 1
    }
    # Run from the repo root whether invoked as ./install.sh or contrib/install.sh.
    root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
    say "building from $root"
    ( cd "$root" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/pkgwatch.$$ ./cmd/pkgwatch )
    BINARY=/tmp/pkgwatch.$$
fi

mkdir -p "$BIN_DIR"
install -m 0755 "$BINARY" "$BIN_DIR/pkgwatch"
case "$BINARY" in /tmp/pkgwatch.*) rm -f "$BINARY" ;; esac
say "installed $BIN_DIR/pkgwatch"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    # Said rather than silently fixed: this script does not edit shell profiles.
    # An installer that rewrites the file your shell sources every login should
    # be the thing you asked for, not a side effect.
    *) say ""; say "NOTE: $BIN_DIR is not on your PATH. Add it:"; say "  export PATH=\"\$PATH:$BIN_DIR\"" ;;
esac

[ "$WANT_SERVICE" -eq 1 ] || { say ""; say "Skipped the service. Start it with: pkgwatch agent"; exit 0; }

# --------------------------------------------------------------- the service

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install_systemd_unit() {
    unit="$1"
    src="$root/systemd/$unit"
    [ -f "$src" ] || { say "missing unit file: $src"; return 1; }

    dest="$HOME/.config/systemd/user"
    mkdir -p "$dest"

    # The shipped unit already points at %h/.local/bin/pkgwatch — a systemd
    # specifier, resolved per user, which is right for the default prefix and
    # better than anything this script could substitute. Only rewrite it when
    # the binary went somewhere else.
    if [ "$BIN_DIR" = "$HOME/.local/bin" ]; then
        cp "$src" "$dest/$unit"
    else
        sed "s|^ExecStart=.*/pkgwatch |ExecStart=$BIN_DIR/pkgwatch |" "$src" > "$dest/$unit"
    fi
    say "installed $dest/$unit"

    systemctl --user daemon-reload
    systemctl --user enable --now "$unit"

    # Without lingering, a user service dies at logout — which on a headless box
    # means it dies and nobody notices until the day it was needed.
    if ! loginctl show-user "$USER" 2>/dev/null | grep -q 'Linger=yes'; then
        say ""
        say "NOTE: user services stop at logout. To keep it running:"
        say "  loginctl enable-linger $USER"
    fi
}

case "$(uname -s)" in
    Linux)
        command -v systemctl >/dev/null 2>&1 || {
            say "no systemctl here — start it yourself with: pkgwatch agent"
            exit 0
        }
        install_systemd_unit pkgwatch-agent.service
        [ "$WANT_HUB" -eq 1 ] && install_systemd_unit pkgwatch-hub.service
        ;;
    Darwin)
        plist="$root/launchd/com.pkgwatch.agent.plist"
        dest="$HOME/Library/LaunchAgents"
        mkdir -p "$dest"
        sed "s|/usr/local/bin/pkgwatch|$BIN_DIR/pkgwatch|" "$plist" > "$dest/com.pkgwatch.agent.plist"
        launchctl unload "$dest/com.pkgwatch.agent.plist" 2>/dev/null || true
        launchctl load "$dest/com.pkgwatch.agent.plist"
        say "loaded $dest/com.pkgwatch.agent.plist"
        [ "$WANT_HUB" -eq 1 ] && say "NOTE: no launchd unit for the hub is shipped; run it under launchd yourself."
        ;;
    *)
        say "unrecognised system: $(uname -s). Start it yourself with: pkgwatch agent"
        exit 0
        ;;
esac

# ------------------------------------------------------------------ verified

say ""
# The service being "started" is not the service working, and this project has
# been bitten by exactly that: a task reporting Ready with LastTaskResult 0
# while the gate had been down for seven hours.
sleep 3
if "$BIN_DIR/pkgwatch" health >/dev/null 2>&1; then
    say "serving:"
    "$BIN_DIR/pkgwatch" health
else
    say "The service was started but is not answering /health yet."
    say "Check it with:  pkgwatch health"
    say "  systemd:  journalctl --user -u pkgwatch-agent -n 50"
    say "  launchd:  log show --predicate 'process == \"pkgwatch\"' --last 5m"
    exit 1
fi

say ""
say "Next:"
say "  pkgwatch scan                     take the first inventory"
say "  pkgwatch sync --file <bundle>     install an advisory bundle"
say "  pkgwatch shell-init               gate npm and pip in this shell"
[ "$WANT_HUB" -eq 1 ] && say "  pkgwatch hub set-password         the hub will not start routable without one"
exit 0
