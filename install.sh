#!/bin/sh
# Triple Seven agent installer — https://github.com/byteramp/triple-seven
#
#   curl -fsSL https://raw.githubusercontent.com/byteramp/triple-seven/main/install.sh | sh
#
# Installs the `t7-agent` package from PyPI (signed releases, see "Verifying a
# release" in the README) with pipx when available, otherwise into a private
# virtual environment, then starts `t7 setup` when run inside a git repository.
# Read before you run: it touches only ~/.local (pipx or a venv) — no sudo.
set -eu

PKG="t7-agent"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/t7"
BIN="$HOME/.local/bin"

say() { printf '%s\n' "$*"; }
die() { printf 't7 install: %s\n' "$*" >&2; exit 1; }

say "Triple Seven · Byteramp — installing the agent"
say ""

PY=""
for c in python3 python3.15 python3.14 python3.13 python3.12 python3.11 python3.10; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || die "Python 3.10 or newer is required (https://www.python.org/downloads/ or: brew install python)."

if command -v pipx >/dev/null 2>&1; then
  say "Using pipx."
  pipx install --force "$PKG" >/dev/null || die "pipx install $PKG failed"
  T7="$(command -v t7 || echo "$BIN/t7")"
else
  say "pipx not found — installing into $DATA/venv"
  "$PY" -m venv "$DATA/venv" || die "could not create a virtual environment (on Debian/Ubuntu: apt install python3-venv)"
  "$DATA/venv/bin/python" -m pip install --quiet --upgrade pip "$PKG" || die "pip install $PKG failed"
  mkdir -p "$BIN"
  ln -sf "$DATA/venv/bin/t7" "$BIN/t7"
  T7="$BIN/t7"
fi

say "Installed: $("$T7" --version)"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) say ""
     say "Add $BIN to your PATH so 't7' works in new terminals:"
     say "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc   # or ~/.bashrc"
     ;;
esac
say ""

# Interactive setup needs a terminal; `curl | sh` has the script on stdin, so read from /dev/tty.
# In a project folder (git or not yet), continue straight into setup; t7 setup offers
# `git init` for a new project. Not in $HOME: there we only show the next step.
if [ -t 1 ] && [ -r /dev/tty ] && [ "$(pwd -P)" != "$(cd "$HOME" && pwd -P)" ]; then
  exec "$T7" setup < /dev/tty
fi
"$T7"
