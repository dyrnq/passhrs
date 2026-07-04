#!/usr/bin/env bash
# Provision a real OpenSSH server on 127.0.0.1:22222 on a macOS runner.
# Uses /usr/sbin/sshd shipped with the OS — no homebrew install needed.
#
# Targets GitHub-hosted macos-14 runners; assumes passwordless sudo
# (the default on GitHub-hosted runners).
set -euo pipefail

USER="testuser"
# PassTest1234# meets Windows password complexity (upper + lower + digit
# + special, 13 chars). Same value used by every platform setup script
# and the e2e tests so the test sshd authenticates passhrs consistently.
PASS="PassTest1234#"
PORT="22222"
HOST="127.0.0.1"
SSHD_BIN="/usr/sbin/sshd"
SFTP_SERVER="/usr/libexec/sftp-server"

SSHD_CFG_DIR="$(cd "$(dirname "$0")" && pwd)"
SSHD_CFG_TEMPLATE="${SSHD_CFG_DIR}/sshd_config"
RUNTIME_DIR="${TMPDIR:-/tmp}/passhrs-test-sshd"
SSHD_CFG="${RUNTIME_DIR}/sshd_config"
HOST_KEY="${RUNTIME_DIR}/ssh_host_ed25519_key"
SSHD_LOG="${RUNTIME_DIR}/sshd.log"
SSHD_PID_FILE="${RUNTIME_DIR}/sshd.pid"

if [ ! -x "${SSHD_BIN}" ]; then
    echo "FATAL: ${SSHD_BIN} not found (expected on stock macOS)" >&2
    exit 1
fi
if [ ! -x "${SFTP_SERVER}" ]; then
    echo "FATAL: ${SFTP_SERVER} not found" >&2
    exit 1
fi

mkdir -p "${RUNTIME_DIR}"

# 1. Materialise the sshd config with the correct sftp-server path.
sed "s|__SFTP_SERVER_PATH__|${SFTP_SERVER}|g" \
    "${SSHD_CFG_TEMPLATE}" \
    > "${SSHD_CFG}"

# 2. Generate a host key on first run; reuse on subsequent runs.
if [ ! -f "${HOST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${HOST_KEY}" -N "" -q
fi

# 3. Create testuser if missing. macOS user records live in OpenDirectory,
#    not /etc/passwd, so use dscl.
if ! dscl . -read "/Users/${USER}" UniqueID >/dev/null 2>&1; then
    UNIQUE_ID="55555"
    sudo dscl . -create "/Users/${USER}"
    sudo dscl . -create "/Users/${USER}" UserShell "/bin/zsh"
    sudo dscl . -create "/Users/${USER}" RealName "Passhrs Test User"
    sudo dscl . -create "/Users/${USER}" UniqueID "${UNIQUE_ID}"
    sudo dscl . -create "/Users/${USER}" PrimaryGroupID 20
    sudo dscl . -create "/Users/${USER}" NFSHomeDirectory "/Users/${USER}"
    sudo dscl . -create "/Users/${USER}" Password "${PASS}"
    sudo createhomedir -u "${USER}" >/dev/null
fi

# Always reset password to the test value so re-runs are deterministic.
sudo dscl . -passwd "/Users/${USER}" "${PASS}" >/dev/null

# 4. Tear down any previous instance. Under launchd we bootout the
#    plist rather than killing by PID: a stale label might still
#    own an orphaned sshd whose pidfile was cleared by a previous
#    failed run, and we'd rather launchctl revoke it cleanly.
#
#    The `user/$(id -u)` domain is the correct non-GUI session
#    domain — `gui/$(id -u)` requires a WindowServer / Aqua session
#    that the GitHub Actions macOS runner does not have (bootstrap
#    fails with exit 125 / "Domain does not support specified
#    action"). `user/<uid>` is the equivalent for headless sessions
#    and has been the supported path since macOS 10.10.
PLIST="${HOME}/Library/LaunchAgents/com.passhrs.test-sshd.plist"
mkdir -p "$(dirname "${PLIST}")"
LAUNCHD_DOMAIN="user/$(id -u)"
sudo launchctl bootout "${LAUNCHD_DOMAIN}" "${PLIST}" 2>/dev/null || true
# Belt-and-suspenders: also kill any orphaned sshd bound to PORT
# from an even earlier run that pre-dated the launchd path.
if [ -f "${SSHD_PID_FILE}" ]; then
    OLD_PID="$(cat "${SSHD_PID_FILE}" || true)"
    if [ -n "${OLD_PID}" ] && sudo kill -0 "${OLD_PID}" 2>/dev/null; then
        sudo kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
    rm -f "${SSHD_PID_FILE}"
fi
# Catch any orphan sshd from a previous crashed run that left a
# listener bound to PORT without a recognised plist owner.
ORPHAN_PID=$(sudo lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)
if [ -n "${ORPHAN_PID}" ]; then
    echo "Killing orphan sshd pid=${ORPHAN_PID} from prior run"
    sudo kill "${ORPHAN_PID}" 2>/dev/null || true
    sleep 1
fi

# 5. Launch sshd under launchd.
#
#    Backgrounding sshd from bash (`sudo sshd ... &` + `nohup` /
#    `disown -h` / stdio-redirect) is NOT enough on GitHub-hosted
#    macos-14 runners: the runner's step cleanup kills all processes
#    in the step's process group, even detached ones, ~100 s after
#    the script exits — which matches exactly the "test_basic_command_exec
#    fails with Connection reset by peer ~100 s after readiness"
#    pattern we observed on 2026-07-04.
#
#    The right macOS primitive is launchd, the system's process
#    supervisor. A LaunchAgent loaded into the runner user's GUI
#    domain is owned by launchd, not by the shell that submitted
#    it; launchd keeps the process alive across shell exits and
#    only tears it down on explicit `launchctl bootout`. We point
#    `ProgramArguments` at `sudo /usr/sbin/sshd ... -D` so the
#    resulting sshd process runs as root (the usual sshd privilege
#    model) and can read host keys written to ${HOST_KEY}.
#
#    `-D` keeps sshd in foreground *inside* launchd — launchd is
#    happy to manage a foreground process; it just considers the
#    job "running" until sshd exits. We track the launchd job by
#    label, not by PID, so the teardown in step 4 (next run) is
#    `launchctl bootout gui/$UID $PLIST` rather than `kill $PID`.
#    PLIST and GUI_DOMAIN were already declared above in step 4.

# Render the plist. ProgramArguments uses `sudo` to elevate so the
# resulting sshd runs as root (otherwise sshd inherits the runner
# uid and refuses to read keys outside that uid).
cat > "${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.passhrs.test-sshd</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/sudo</string>
        <string>${SSHD_BIN}</string>
        <string>-f</string><string>${SSHD_CFG}</string>
        <string>-h</string><string>${HOST_KEY}</string>
        <string>-E</string><string>${SSHD_LOG}</string>
        <string>-p</string><string>${PORT}</string>
        <string>-D</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>StandardOutPath</key><string>${RUNTIME_DIR}/sshd.out.log</string>
    <key>StandardErrorPath</key><string>${SSHD_LOG}</string>
</dict>
</plist>
EOF

# Submit the new job. launchd will launch sudo -> sshd immediately
# because RunAtLoad=true.
sudo launchctl bootstrap "${LAUNCHD_DOMAIN}" "${PLIST}"

# 6. Wait for the daemon to accept connections (max 10s).
SSHD_PID=""
for i in $(seq 1 50); do
    if (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
        # Find the actually-listening sshd PID (launchd's child, after
        # sudo). lsof makes this robust against label-to-pid mapping
        # changes between launchd versions.
        SSHD_PID=$(sudo lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | head -1)
        echo "test sshd ready at ${HOST}:${PORT} (pid=${SSHD_PID}, launchd: com.passhrs.test-sshd)"
        echo "${SSHD_PID}" > "${SSHD_PID_FILE}"
        exit 0
    fi
    sleep 0.2
done

echo "FATAL: sshd did not start within 10s" >&2
sudo launchctl bootout "${LAUNCHD_DOMAIN}" "${PLIST}" 2>/dev/null || true
tail -n 50 "${SSHD_LOG}" >&2 || true
exit 1