#!/usr/bin/env bash
# Probe: can we run Docker on a macos-14 GitHub Actions runner via colima?
#
# This script deliberately does NOT touch macOS's native openssh server.
# Its only job is to install colima, start the Lima VM, and verify that
# `docker version` / `docker info` succeed. If the probe succeeds, the
# follow-up is to build a Linux openssh-server container image and run
# it on 127.0.0.1:22222 so tests/15 can connect without needing the
# host's native sshd.
set -euo pipefail

# macos-14 GitHub runners execute steps under the `runner` user; the
# setup script itself is invoked via sudo, but colima must run as a
# regular user — it stores VM state under ~/<user>/.colima and the
# underlying Lima VM cannot be launched by uid 0.
RUNNER_USER="${SUDO_USER:-runner}"

# macos-14 is arm64 → Homebrew installs to /opt/homebrew. If for any
# reason that prefix is missing, fall back to /usr/local (the legacy
# Intel prefix). Either way the `brew` binary lives in <prefix>/bin.
BREW_BIN="/opt/homebrew/bin"
if [ ! -x "${BREW_BIN}/brew" ]; then
    BREW_BIN="/usr/local/bin"
fi
export PATH="${BREW_BIN}:${PATH}"

if ! sudo -u "${RUNNER_USER}" -H bash -c "export PATH='${BREW_BIN}:\$PATH'; command -v brew" >/dev/null; then
    echo "FATAL: brew not found on ${RUNNER_USER}'s PATH (${BREW_BIN})" >&2
    echo "       macos-14 GitHub runners ship Homebrew preinstalled — if" >&2
    echo "       it's missing the runner image may have changed." >&2
    exit 1
fi

echo "==> Installing colima as ${RUNNER_USER}..."
# `brew install colima` also pulls in `docker` (the CLI) as a runtime
# dependency, so a single install gives us both the colima manager
# and the docker client. brew install is idempotent — it returns 0
# if colima is already at the latest version.
sudo -u "${RUNNER_USER}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    brew install colima
"
if ! sudo -u "${RUNNER_USER}" -H bash -c "export PATH='${BREW_BIN}:\$PATH'; command -v colima" >/dev/null; then
    echo "FATAL: colima install did not put colima on ${RUNNER_USER}'s PATH" >&2
    exit 1
fi
echo "    colima at: $(sudo -u "${RUNNER_USER}" -H bash -c "export PATH='${BREW_BIN}:\$PATH'; command -v colima")"

echo "==> Starting colima VM (cpu=2 mem=4G disk=20G)..."
# The CPU/memory/disk values are colima's accepted minimums and are
# small enough to come up in under a minute on the free GitHub-hosted
# macos-14 runner. colima start is idempotent: if the default profile
# is already running, the call returns within seconds and prints
# "profile 'default' is already running".
sudo -u "${RUNNER_USER}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    colima start --cpu 2 --memory 4 --disk 20
"

echo "==> colima status:"
sudo -u "${RUNNER_USER}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    colima status
"

echo "==> docker version (colima's daemon ↔ CLI handshake):"
sudo -u "${RUNNER_USER}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    docker version
"

echo "==> docker info (server section only):"
sudo -u "${RUNNER_USER}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    docker info 2>&1 | grep -E '^(Server Version|Storage Driver|Cgroup Version|Operating System|Kernel Version|Docker Root Dir|Containers |Images )' | head -15
"

# Sanity probe: can the docker CLI actually create+remove a trivial
# container? A green `docker version` only proves the API surfaces are
# wired up; an actual run proves the VM is functional. We use the
# smallest possible image (`hello-world`) and remove the container
# immediately so we don't pollute the daemon.
echo "==> docker run hello-world (end-to-end VM check)..."
sudo -u "${RUNNER_USER}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    docker run --rm hello-world
" | tail -20

echo "==> Probe SUCCESS: Docker works on macos-14 via colima."
echo "    Next step (if you choose): build a Linux openssh-server image"
echo "    and run it on 127.0.0.1:22222 so tests/15 can connect."