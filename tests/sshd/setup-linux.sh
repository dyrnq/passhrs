#!/usr/bin/env bash
# Provision a real openssh-server on 127.0.0.1:22222 with a known
# testuser / testpass, then start sshd in the background. Idempotent:
# safe to re-run during local iteration.
#
# Targets GitHub-hosted ubuntu-24.04 runners; should also work on any
# Debian/Ubuntu-based host with sudo.
set -euo pipefail

USER="testuser"
PASS="testpass"
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
sed "s|__SFTP_SERVER_PATH__|${SFTP_SERVER}|g" \
    "${SSHD_CFG_TEMPLATE}" \
    > "${SSHD_CFG}"

# 4. Generate a host key on first run; reuse it on subsequent runs so
#    tests that persist /tmp keep their known_hosts entry stable.
if [ ! -f "${HOST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${HOST_KEY}" -N "" -q
fi

# 5. Create testuser with the known password (no-op if it already exists).
if ! id "${USER}" >/dev/null 2>&1; then
    sudo useradd -m -s /bin/sh "${USER}"
fi
echo "${USER}:${PASS}" | sudo chpasswd

# 6. Tear down any previous instance bound to PORT, then start fresh.
if [ -f "${SSHD_PID_FILE}" ]; then
    OLD_PID="$(cat "${SSHD_PID_FILE}" || true)"
    if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
        sudo kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
fi

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