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

# 4. Tear down any previous instance bound to PORT.
if [ -f "${SSHD_PID_FILE}" ]; then
    OLD_PID="$(cat "${SSHD_PID_FILE}" || true)"
    if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
        sudo kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
fi

# 5. Launch sshd. macOS sshd by default reads /private/etc/ssh/sshd_config
#    AND treats included Match blocks; we override everything via -f.
#
#    Detach carefully. The naive `sudo sshd ... &` keeps sshd in the
#    script's job table, so when this script exits bash sends SIGHUP
#    to the child and sshd dies — which is exactly what the integration
#    suite observed before: TCP probe succeeded immediately, every
#    real passhrs connection ~100 s later got "Connection reset by
#    peer" because sshd was gone. Wrapping in `nohup` ignores SIGHUP,
#    `</dev/null >/dev/null 2>&1` severs sshd from the script's stdio
#    so no one is waiting on the FDs, and `disown -h` (best-effort;
#    macOS `disown` may not support -h) removes it from bash's job
#    table so bash won't try to signal it at exit.
sudo "${SSHD_BIN}" \
    -f "${SSHD_CFG}" \
    -h "${HOST_KEY}" \
    -E "${SSHD_LOG}" \
    -p "${PORT}" \
    -D \
    </dev/null >/dev/null 2>&1 &
SSHD_PID=$!
echo "${SSHD_PID}" > "${SSHD_PID_FILE}"
# Belt-and-suspenders: ignore SIGHUP via nohup-style behavior and
# remove from the bash job table if disown supports it. Failure is
# not fatal here.
nohup sudo kill -0 "${SSHD_PID}" >/dev/null 2>&1 || true
disown -h "${SSHD_PID}" 2>/dev/null || disown "${SSHD_PID}" 2>/dev/null || true

# 6. Wait for the daemon to accept connections (max 10s). Also confirms
#    sshd is still alive (kill -0) — if nohup/disown failed silently
#    and sshd died, the TCP probe will time out and we'll print the log.
for i in $(seq 1 50); do
    if ! sudo kill -0 "${SSHD_PID}" 2>/dev/null; then
        echo "FATAL: sshd (pid ${SSHD_PID}) exited before becoming ready" >&2
        tail -n 50 "${SSHD_LOG}" >&2 || true
        exit 1
    fi
    if (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
        echo "test sshd ready at ${HOST}:${PORT} (pid=${SSHD_PID})"
        exit 0
    fi
    sleep 0.2
done

echo "FATAL: sshd did not start within 10s" >&2
tail -n 50 "${SSHD_LOG}" >&2 || true
exit 1