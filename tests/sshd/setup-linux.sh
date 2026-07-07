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
# Test-user ed25519 keypair for pubkey auth. Mirrors the macOS
# setup so tests/12 (and any future key-auth test) can drive
# `passhrs -i ${TEST_KEY}` against this sshd without dealing with
# password auth at all. The private key path is exported as
# PHR_TEST_KEY for the integration-tests step to consume.
TEST_KEY="${RUNTIME_DIR}/runner_id_ed25519"
TEST_KEY_PUB="${TEST_KEY}.pub"
SSHD_LOG="${RUNTIME_DIR}/sshd.log"
SSHD_PID_FILE="${RUNTIME_DIR}/sshd.pid"

mkdir -p "${RUNTIME_DIR}"

# 1. Install openssh-server if missing.
if ! command -v sshd >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y openssh-server openssh-sftp-server
fi
# Install sshpass so the end-of-script smoke probe (step 8a) can drive
# sshpass -p ${PASS} ssh ... to verify the password actually authenticates
# before the integration-test step inherits a misconfigured sshd. Without
# this, a silent chpasswd failure only surfaces as 30 opaque
# "Authentication failed" messages in the cargo test output, which makes
# it hard to distinguish from a real bug in passhrs. sshpass is a small
# no-daemon utility; safe to install alongside openssh-server.
if ! command -v sshpass >/dev/null 2>&1; then
    sudo apt-get install -y sshpass
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
# chpasswd can silently fail if the runner user is locked or has a
# no-password entry (the runner image occasionally ships one). Verify
# the password field in /etc/shadow is non-empty and not '*' / '!' /
# '!!' / '*LK*' (locked-account markers) — otherwise every auth_args()
# call in the integration tests would fall through to a literal empty
# password and sshd would reply "Authentication failed" 30 times in a
# row before any test ever produces a real failure message.
if ! sudo getent shadow "${USER}" | cut -d: -f2 | grep -qE '^[^!*]'; then
    echo "FATAL: ${USER}'s /etc/shadow password field is empty/locked after chpasswd" >&2
    sudo getent shadow "${USER}" >&2 || true
    exit 1
fi
echo "    chpasswd verified: /etc/shadow has non-empty password for ${USER}"

# 5a. Generate the test-user ed25519 keypair used by tests/12 (and
#     any future key-auth test). Idempotent: only generate on first
#     run so the file persists across re-runs (and so the public-key
#     line in authorized_keys doesn't get duplicated by a re-run).
if [ ! -f "${TEST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${TEST_KEY}" -N "" -q
fi
# Key needs to be readable by the runner user (it owns the test
# process), not root-only. Same chown story as macOS — see
# setup-macos-brew-openssh.sh lines 318-341 for the full reasoning
# (ssh rejects a 600 key owned by a different uid even with the
# right bits; russh can't read root-owned 600 either).
chown "${USER}:${USER}" "${TEST_KEY}" "${TEST_KEY_PUB}"
chmod 600 "${TEST_KEY}"
chmod 644 "${TEST_KEY_PUB}"

# 5b. Drop the public key into runner's authorized_keys. sshd_config
#     already has PubkeyAuthentication yes + PasswordAuthentication
#     yes, so this adds key auth on top of the password path that
#     step 5 set up. Idempotent: check first so re-runs don't
#     duplicate the line.
sudo -u "${USER}" mkdir -p "/home/${USER}/.ssh"
sudo -u "${USER}" touch "/home/${USER}/.ssh/authorized_keys"
if ! sudo -u "${USER}" grep -qF "$(cat "${TEST_KEY_PUB}")" \
        "/home/${USER}/.ssh/authorized_keys"; then
    sudo -u "${USER}" tee -a "/home/${USER}/.ssh/authorized_keys" \
        >/dev/null < "${TEST_KEY_PUB}"
fi
sudo chmod 600 "/home/${USER}/.ssh/authorized_keys"
sudo chown "${USER}:${USER}" "/home/${USER}/.ssh/authorized_keys"
echo "    pubkey auth: TEST_KEY_PUB appended to ~${USER}/.ssh/authorized_keys"

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
        break
    fi
    sleep 0.2
done

if ! (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
    echo "FATAL: sshd did not start within 10s" >&2
    tail -n 50 "${SSHD_LOG}" >&2 || true
    exit 1
fi

# 8a. End-to-end smoke probe: drive sshpass -p ${PASS} ssh to log in
# with the runner user's password and run `echo linux_ssh_ok`. This
# catches: wrong chpasswd, sshd_config typos (e.g. PasswordAuthentication
# silently overridden by a Match block), and the rare case where sshd
# starts but the PAM stack rejects every password. sshpass is
# installed in step 1 alongside openssh-server.
echo "==> Smoke-testing ssh password auth..."
if ! sshpass -p "${PASS}" ssh \
        -p "${PORT}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=no \
        -o ConnectTimeout=5 \
        -o NumberOfPasswordPrompts=1 \
        "${USER}@${HOST}" \
        "echo linux_ssh_ok" 2>&1; then
    echo "FATAL: ssh password auth probe failed; check sshd log + chpasswd output" >&2
    tail -n 80 "${SSHD_LOG}" >&2 || true
    exit 1
fi

# 8b. End-to-end smoke probe for pubkey auth: drive the same
# `passhrs -i` shape that tests/12 will use, against the same key
# we just authorized. Catches chown/chmod/authorized_keys mistakes
# before the integration-tests step inherits a misconfigured sshd.
echo "==> Smoke-testing ssh pubkey auth..."
if ! ssh -i "${TEST_KEY}" \
        -p "${PORT}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        "${USER}@${HOST}" \
        "echo linux_pubkey_ok" 2>&1; then
    echo "FATAL: ssh pubkey auth probe failed; check authorized_keys + key perms" >&2
    tail -n 80 "${SSHD_LOG}" >&2 || true
    exit 1
fi

# 9. Export PHR_TEST_KEY so the integration-tests step can drive
#    `passhrs -i ${PHR_TEST_KEY}` without needing to know where the
#    key lives. Mirrors setup-macos-brew-openssh.sh lines 540-552
#    so tests/12 + tests/15 auth_args() work identically on every
#    platform. GITHUB_ENV is set by GitHub Actions; the `>>` is a
#    no-op when running the script locally for iteration.
if [ -n "${GITHUB_ENV:-}" ]; then
    {
        echo "PHR_TEST_KEY=${TEST_KEY}"
        echo "==> Wrote PHR_TEST_KEY=${TEST_KEY} to GITHUB_ENV"
    } | tee -a "${GITHUB_ENV}"
else
    echo "==> PHR_TEST_KEY=${TEST_KEY} (export manually for local iteration)"
fi

exit 0