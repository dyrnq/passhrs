#!/usr/bin/env bash
# Provision a real openssh-server on 127.0.0.1:22222 with a known
# testuser / PassTest1234!, then start sshd in the background. Idempotent:
# safe to re-run during local iteration.
#
# Targets GitHub-hosted ubuntu-24.04 runners; should also work on any
# Debian/Ubuntu-based host with sudo.
set -euo pipefail

USER="runner"
# PassTest1234! meets Windows password complexity (upper + lower + digit
# + special, 13 chars). The same value is used by every platform setup
# script and the e2e tests so the test sshd always authenticates the
# passhrs client with the same credentials.
PASS="PassTest1234!"
# NOTE: USER used to be 'testuser' (created via useradd). The macOS
# setup hit a wall because macOS's pam_sacl.so + pam_opendirectory
# require SACL authorizationdb grants that we couldn't easily write
# from the setup script. Switched all platforms to the pre-existing
# `runner` user (GitHub-hosted runners ship with this account;
# Linux has /home/runner, macOS has /Users/runner, Windows has
# C:\Users\runner). We just chpasswd it.
PORT="22222"
HOST="127.0.0.1"
SSHD_CFG_DIR="$(cd "$(dirname "$0")" && pwd)"
SSHD_CFG_TEMPLATE="${SSHD_CFG_DIR}/sshd_config"
RUNTIME_DIR="${TMPDIR:-/tmp}/passhrs-test-sshd"
SSHD_CFG="${RUNTIME_DIR}/sshd_config"
HOST_KEY="${RUNTIME_DIR}/ssh_host_ed25519_key"
SSHD_LOG="${RUNTIME_DIR}/sshd.log"
SSHD_PID_FILE="${RUNTIME_DIR}/sshd.pid"

mkdir -p "${RUNTIME_DIR}"

# 1. Install openssh-server if missing.
if ! command -v sshd >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y openssh-server openssh-sftp-server
fi

# 2. Locate sftp-server (path varies across distros).
SFTP_SERVER=""
for candidate in \
    /usr/lib/openssh/sftp-server \
    /usr/libexec/openssh/sftp-server \
    /usr/libexec/sftp-server \
    /usr/lib/ssh/sftp-server; do
    if [ -x "${candidate}" ]; then
        SFTP_SERVER="${candidate}"
        break
    fi
done
if [ -z "${SFTP_SERVER}" ]; then
    echo "FATAL: sftp-server not found in any known location" >&2
    exit 1
fi

# 3. Materialise the sshd config with the correct sftp-server path.
#    Bump LogLevel to DEBUG3 so SFTP subsystem session attempts show
#    up in the log on failure (the SFTP init timeout in passhrs takes
#    ~10s to fire, and without DEBUG3 there's nothing in sshd.log to
#    explain the timeout). Like macOS, OpenSSH only honours the FIRST
#    LogLevel in the config file, so we have to strip the template's
#    `LogLevel ERROR` first.
sed "s|__SFTP_SERVER_PATH__|${SFTP_SERVER}|g" \
    "${SSHD_CFG_TEMPLATE}" \
    > "${SSHD_CFG}"
sed -i '/^LogLevel /d' "${SSHD_CFG}"
cat >> "${SSHD_CFG}" <<'EOF'

# --- passhrs CI overrides ---
LogLevel DEBUG3
EOF

# 4. Generate a host key on first run; reuse it on subsequent runs so
#    tests that persist /tmp keep their known_hosts entry stable.
if [ ! -f "${HOST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${HOST_KEY}" -N "" -q
fi

# 5. Set the runner user's password to the known test value. The
#    runner user is created by the GitHub-hosted Ubuntu image; we
#    don't useradd it. Setting the password via chpasswd is the
#    supported way and survives across re-runs.
if ! id "${USER}" >/dev/null 2>&1; then
    echo "FATAL: ${USER} user not present (expected on GitHub Ubuntu runner)" >&2
    exit 1
fi
echo "${USER}:${PASS}" | sudo chpasswd

# 5b. Ubuntu's OpenSSH package does not create the privilege-separation
#     directory on install; sshd refuses to start without it.
sudo mkdir -p /run/sshd
sudo chmod 0755 /run/sshd

# 6. Tear down any previous instance bound to PORT, then start fresh.
if [ -f "${SSHD_PID_FILE}" ]; then
    OLD_PID="$(cat "${SSHD_PID_FILE}" || true)"
    if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
        sudo kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
fi

# 6b. Pre-create the log file with world-readable mode BEFORE sshd
#     launches. sshd opens the -E target with O_APPEND (not O_CREAT
#     with explicit mode), so the bits we set here are the bits that
#     stick — sshd never re-chmods the log. If we let sshd create it,
#     it ends up root:root mode 600, which the unprivileged
#     `Upload sshd log (unix)` step in ci.yml can't read (EACCES). The
#     log contains only hostnames, usernames, and the libssh
#     transcript — fine for a throwaway test environment.
sudo install -m 644 /dev/null "${SSHD_LOG}"

# 7. Launch sshd in the background. -D keeps it in the foreground of the
#    child process; we background the child so the script can return.
sudo /usr/sbin/sshd \
    -f "${SSHD_CFG}" \
    -h "${HOST_KEY}" \
    -E "${SSHD_LOG}" \
    -p "${PORT}" \
    -D &
SSHD_PID=$!
echo "${SSHD_PID}" > "${SSHD_PID_FILE}"

# 8. Wait for the daemon to accept connections (max 10s).
for i in $(seq 1 50); do
    if (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
        echo "test sshd ready at ${HOST}:${PORT} (pid=${SSHD_PID})"
        exit 0
    fi
    sleep 0.2
done

echo "FATAL: sshd did not start within 10s" >&2
tail -n 50 "${SSHD_LOG}" >&2 || true
exit 1