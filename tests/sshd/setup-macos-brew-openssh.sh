#!/usr/bin/env bash
# Provision a real OpenSSH server on 127.0.0.1:22222 on a macos-14
# runner using Homebrew's openssh and SSH-key authentication.
#
# Why both changes vs. the previous (system sshd + password) approach:
#
#   1. Homebrew openssh installs a self-contained sshd into
#      /opt/homebrew/opt/openssh/sbin/sshd, isolated from system
#      updates and from Apple's managed-launchd-managed
#      /usr/sbin/sshd. This matters less for auth (the underlying
#      PAM/OpenDirectory stack is identical), but it means we can
#      pin a known version, restart it under our own lifecycle,
#      and tear it down without fighting system SIP.
#
#   2. The hard wall on macOS Sonoma+ is the secure-token lockout:
#      dscl . -passwd, sysadminctl -resetPasswordFor, and passwd
#      all require the user's OLD password or an interactive
#      token bootstrap a non-interactive CI script cannot drive.
#      SSH key auth sidesteps the password path entirely — sshd
#      verifies a challenge signed by the client's private key
#      against authorized_keys, never asking for the user's
#      password. As root we can drop the public key into
#      /Users/testuser/.ssh/authorized_keys without ever knowing
#      the user's password.
#
# `PasswordAuthentication no` in the rendered sshd_config means
# password auth is rejected outright — so even if some future
# regression re-introduces a password try, it fails fast with a
# clear "Permission denied (publickey)" rather than a confusing
# secure-token error.
set -euo pipefail

# ---- constants --------------------------------------------------------------

USER="testuser"
# PassTest1234! meets Windows password complexity. Kept in the env so
# tests/15's cfg-gated USER constant stays consistent across platforms
# even though the macOS sshd no longer accepts password auth.
PASS="PassTest1234!"
PORT="22222"
HOST="127.0.0.1"

# macos-14 is arm64 → Homebrew installs to /opt/homebrew. Intel
# fallback (/usr/local) is unlikely on macos-14 but supported.
BREW_BIN="/opt/homebrew/bin"
if [ ! -x "${BREW_BIN}/brew" ]; then
    BREW_BIN="/usr/local/bin"
fi
export PATH="${BREW_BIN}:${PATH}"

# Resolve sshd + sftp-server AFTER `brew install openssh` below.
# Searching for them here (before install) would always miss — the
# Homebrew openssh formula installs sshd to
# /opt/homebrew/Cellar/openssh/<ver>/sbin/sshd with symlinks under
# /opt/homebrew/opt/openssh/sbin/sshd and /opt/homebrew/sbin/sshd,
# none of which exist on a fresh runner before install runs.
SSHD_BIN=""
SFTP_SERVER=""

SSHD_CFG_DIR="$(cd "$(dirname "$0")" && pwd)"
SSHD_CFG_TEMPLATE="${SSHD_CFG_DIR}/sshd_config"
# Runtime dir is intentionally the same as setup-macos.sh and
# setup-linux.sh (passhrs-test-sshd), NOT a -brew-suffixed variant.
# ci.yml's "Dump sshd log on failure" step hard-codes a list of
# candidate paths; if we used a -brew suffix here, the dump step
# would emit nothing and a failed auth handshake would leave us
# staring at "Authentication failed" in the test log with no
# sshd-side reason. Keeping the suffix-less path means a single
# dump step handles all three platforms' failed-state diagnostics.
RUNTIME_DIR="${TMPDIR:-/tmp}/passhrs-test-sshd"
SSHD_CFG="${RUNTIME_DIR}/sshd_config"
HOST_KEY="${RUNTIME_DIR}/ssh_host_ed25519_key"
SSHD_LOG="${RUNTIME_DIR}/sshd.log"
SSHD_PID_FILE="${RUNTIME_DIR}/sshd.pid"
# Private key for tests/15's passhrs client. The public counterpart
# (TEST_KEY_PUB) is written into /Users/testuser/.ssh/authorized_keys.
TEST_KEY="${RUNTIME_DIR}/testuser_id_ed25519"
TEST_KEY_PUB="${TEST_KEY}.pub"
HOME_DIR="/Users/${USER}"

mkdir -p "${RUNTIME_DIR}"

# ---- 1. install Homebrew openssh ------------------------------------------

echo "==> Installing openssh via brew (as ${SUDO_USER:-runner})..."
# `brew install openssh` is idempotent — returns 0 if already at latest.
sudo -u "${SUDO_USER:-runner}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    brew install openssh
" || {
    echo "FATAL: brew install openssh failed" >&2
    exit 1
}

# ---- 1b. dynamically resolve Homebrew openssh's binary paths ----------
# Don't hardcode `/opt/homebrew/...` — that's only correct on
# Apple Silicon. Use `brew --prefix openssh` to ask Homebrew
# directly where it installed the formula, then fall back to a
# handful of common paths for edge cases (custom taps, manual
# install). `command -v sshd` last-catches the rare case where
# someone already has an sshd on PATH.
OPENSSH_PREFIX="$(brew --prefix openssh 2>/dev/null || true)"
BREW_PREFIX="$(brew --prefix 2>/dev/null || true)"
echo "    brew --prefix:         ${BREW_PREFIX}"
echo "    brew --prefix openssh: ${OPENSSH_PREFIX}"

CANDIDATES=(
    "${OPENSSH_PREFIX}/sbin/sshd"
    "${BREW_PREFIX}/opt/openssh/sbin/sshd"
    "/opt/homebrew/opt/openssh/sbin/sshd"
    "/opt/homebrew/sbin/sshd"
    "/usr/local/opt/openssh/sbin/sshd"
    "/usr/local/sbin/sshd"
    "$(command -v sshd 2>/dev/null || true)"
)
for cand in "${CANDIDATES[@]}"; do
    if [ -n "${cand}" ] && [ -x "${cand}" ]; then
        SSHD_BIN="${cand}"
        break
    fi
done

if [ -z "${SSHD_BIN}" ]; then
    echo "FATAL: Homebrew openssh installed but sshd not found" >&2
    echo "Searched:" >&2
    for c in "${CANDIDATES[@]}"; do echo "  - ${c}" >&2; done
    echo "Cellar contents (best-effort):" >&2
    find "${OPENSSH_PREFIX}" "${BREW_PREFIX}" -name sshd -type f 2>/dev/null \
        | head -10 >&2 || true
    exit 1
fi
echo "    sshd: ${SSHD_BIN}  ($(${SSHD_BIN} -V 2>&1 || echo unknown))"

# sftp-server is a separate binary that the openssh formula also
# installs. It can land in <prefix>/libexec/sftp-server (modern
# Homebrew) or <prefix>/sbin/sftp-server (older), and the system
# sftp-server at /usr/libexec/sftp-server is a last-resort fallback.
SFTP_CANDIDATES=(
    "${OPENSSH_PREFIX}/libexec/sftp-server"
    "${BREW_PREFIX}/libexec/sftp-server"
    "/opt/homebrew/libexec/sftp-server"
    "/usr/local/libexec/sftp-server"
    "/usr/libexec/sftp-server"
)
for cand in "${SFTP_CANDIDATES[@]}"; do
    if [ -n "${cand}" ] && [ -x "${cand}" ]; then
        SFTP_SERVER="${cand}"
        break
    fi
done
if [ -z "${SFTP_SERVER}" ]; then
    echo "FATAL: sftp-server binary not found" >&2
    echo "Searched:" >&2
    for c in "${SFTP_CANDIDATES[@]}"; do echo "  - ${c}" >&2; done
    exit 1
fi
echo "    sftp-server: ${SFTP_SERVER}"

# ---- 2. materialize sshd_config (template + per-run overrides) ------------

sed "s|__SFTP_SERVER_PATH__|${SFTP_SERVER}|g" \
    "${SSHD_CFG_TEMPLATE}" \
    > "${SSHD_CFG}"
# OpenSSH honours the FIRST LogLevel it sees, so we have to delete
# the template's `LogLevel ERROR` before appending DEBUG3 — otherwise
# auth-failure context we'd want on failure is silently suppressed.
sed -i '' '/^LogLevel /d' "${SSHD_CFG}"
cat >> "${SSHD_CFG}" <<EOF

# --- passhrs CI overrides (Homebrew openssh + key auth) ---
LogLevel DEBUG3
# macOS secure-token lockout makes password auth unrecoverable from
# a non-interactive CI script. Force pubkey-only so any future
# regression that re-enables password tries fails fast with a
# clear "Permission denied (publickey)" instead of a confusing
# OpenDirectory error.
PasswordAuthentication no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
EOF

# ---- 3. generate host key + test-user keypair -----------------------------

if [ ! -f "${HOST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${HOST_KEY}" -N "" -q
fi
if [ ! -f "${TEST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${TEST_KEY}" -N "" -q
    chmod 600 "${TEST_KEY}"
fi

# ---- 4. create testuser via sysadminctl -addUser --------------------------

# Idempotency: if a previous run left a testuser record, delete it
# first so sysadminctl -addUser doesn't refuse with "user exists".
# (sysadminctl -deleteUser is the supported path; dscl . -delete
# is a fallback for the rare case where -deleteUser refuses on a
# system-protected record.)
if sudo dscl . -read "/Users/${USER}" >/dev/null 2>&1; then
    echo "==> Removing pre-existing ${USER} from a previous run..."
    sudo sysadminctl -deleteUser "${USER}" 2>&1 \
        || sudo dscl . -delete "/Users/${USER}" 2>&1 || true
    # The home dir survives -deleteUser; nuke it so the next -addUser
    # doesn't inherit stale state (notably .ssh/authorized_keys).
    sudo rm -rf "${HOME_DIR}" 2>/dev/null || true
fi

echo "==> Creating ${USER} via sysadminctl -addUser..."
# -admin puts the user in the admin group → SACL ssh grant →
# pam_sacl.so lets the SSH session past the account stage even
# though we never set a password.
sudo sysadminctl -addUser "${USER}" \
    -fullName "passhrs test user" \
    -admin \
    -home "${HOME_DIR}" 2>&1 || {
        echo "FATAL: sysadminctl -addUser ${USER} failed" >&2
        exit 1
    }

# ---- 5. drop public key into authorized_keys ------------------------------
# This is the bit that bypasses the secure-token wall: sshd reads
# authorized_keys and challenges the client's private key. No
# user password is ever consulted.
sudo mkdir -p "${HOME_DIR}/.ssh"
sudo chmod 700 "${HOME_DIR}/.ssh"
sudo cp "${TEST_KEY_PUB}" "${HOME_DIR}/.ssh/authorized_keys"
sudo chmod 600 "${HOME_DIR}/.ssh/authorized_keys"
sudo chown -R "${USER}:staff" "${HOME_DIR}/.ssh"

# ---- 6. clear pwpolicy + bump passwordLastSet -----------------------------
# Belt-and-braces: pwpolicy -clear + recent passwordLastSet ensures
# the account isn't blocked by an expired-password policy even
# though we never set a password. (Some macOS configurations
# auto-expire accounts whose passwordLastSet is 0.)
sudo pwpolicy -u "${USER}" -clear 2>/dev/null || true
NOW_EPOCH="$(date +%s)"
sudo dscl . -create "/Users/${USER}" passwordLastSet "${NOW_EPOCH}" 2>/dev/null || true
sudo dscl . -delete "/Users/${USER}" accountExpires 2>/dev/null || true

# ---- 7. diagnostic dump (shown on CI failure) ----------------------------

echo "--- ${USER} OpenDirectory state ---"
sudo dscl . -read "/Users/${USER}" 2>&1 | head -60 || true
echo "--- pwpolicy ---"
sudo pwpolicy -u "${USER}" -getpolicy 2>&1 | head -20 || true
echo "--- /etc/pam.d/sshd ---"
sudo cat /etc/pam.d/sshd 2>&1 || true
echo "--- ${HOME_DIR}/.ssh ---"
sudo ls -la "${HOME_DIR}/.ssh" 2>&1 || true
echo "--- ${HOME_DIR} perms ---"
sudo ls -ldn "${HOME_DIR}" 2>&1 || true
echo "--- com.apple.access_ssh rule ---"
sudo security authorizationdb read com.apple.access_ssh 2>&1 || true
echo "--- rendered sshd_config ---"
cat "${SSHD_CFG}" 2>&1 || true
echo "-----------------------------------"

# ---- 8. tear down prior instance ----------------------------------------

if [ -f "${SSHD_PID_FILE}" ]; then
    OLD_PID="$(cat "${SSHD_PID_FILE}" || true)"
    if [ -n "${OLD_PID}" ] && sudo kill -0 "${OLD_PID}" 2>/dev/null; then
        sudo kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
    rm -f "${SSHD_PID_FILE}"
fi
# Catch orphan sshd from a prior crashed run that left a listener
# bound to PORT but no pidfile.
ORPHAN_PID=$(sudo lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)
if [ -n "${ORPHAN_PID}" ]; then
    echo "Killing orphan sshd pid=${ORPHAN_PID} from prior run"
    sudo kill "${ORPHAN_PID}" 2>/dev/null || true
    sleep 1
fi

# ---- 9. launch detached sshd via python3 setsid --------------------------
# Same pattern as setup-macos.sh: sshd must survive the step's
# process-group SIGKILL during CI cleanup. os.setsid() detaches it
# into a brand-new session + pgid that the runner's step-cleanup
# doesn't target. -D keeps sshd in the foreground of its new
# session so we get a stable PID for liveness + teardown.
SSHD_PID=$(
    python3 -c '
import os, sys
pid = os.fork()
if pid > 0:
    print(pid); sys.exit(0)
os.setsid()
null_in = os.open("/dev/null", os.O_RDONLY)
null_out = os.open("/dev/null", os.O_WRONLY)
os.dup2(null_in, 0)
os.dup2(null_out, 1)
os.dup2(null_out, 2)
argv = ["/usr/bin/sudo", "--", sys.argv[1]] + sys.argv[2:]
os.execv(argv[0], argv)
' \
        "${SSHD_BIN}" \
        -f "${SSHD_CFG}" \
        -h "${HOST_KEY}" \
        -E "${SSHD_LOG}" \
        -p "${PORT}" \
        -D
)
echo "${SSHD_PID}" > "${SSHD_PID_FILE}"
# sshd created the log file via sudo — root-owned, mode 600. The
# `Upload sshd log (unix)` step in ci.yml runs as the unprivileged
# runner user and would hit EACCES trying to read it. chmod 644 so
# the artifact upload succeeds (the log contains only hostnames,
# usernames, and the libssh protocol transcript — fine for a
# throwaway test environment).
sudo chmod 644 "${SSHD_LOG}" || true
echo "Launched detached sshd (pid=${SSHD_PID}, ${SSHD_BIN}) via python3 os.setsid"

# ---- 10. wait for sshd to accept connections ----------------------------

for i in $(seq 1 50); do
    if ! sudo kill -0 "${SSHD_PID}" 2>/dev/null; then
        echo "FATAL: detached sshd (pid ${SSHD_PID}) exited before becoming ready" >&2
        tail -n 50 "${SSHD_LOG}" >&2 || true
        exit 1
    fi
    if (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
        echo "test sshd ready at ${HOST}:${PORT} (pid=${SSHD_PID})"
        break
    fi
    sleep 0.2
done

if ! (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
    echo "FATAL: sshd did not start accepting connections within 10s" >&2
    sudo kill "${SSHD_PID}" 2>/dev/null || true
    tail -n 50 "${SSHD_LOG}" >&2 || true
    exit 1
fi

# ---- 11. end-to-end smoke test with key auth ----------------------------
# Drive a real SSH handshake from this script (as root, which is fine —
# the sshd_config allows PermitRootLogin yes for the test) to confirm
# the keypair is wired correctly. This catches: wrong home-dir perms,
# authorized_keys not picked up, sshd_config typo, SACL grant missing.
echo "==> Smoke-testing ssh key auth..."
if ! ssh -i "${TEST_KEY}" \
        -p "${PORT}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        "${USER}@${HOST}" \
        "echo ssh_key_auth_ok" 2>&1; then
    echo "FATAL: ssh key auth probe failed; check sshd log" >&2
    tail -n 80 "${SSHD_LOG}" >&2 || true
    exit 1
fi

# ---- 12. export PHR_TEST_KEY for the integration-tests step -------------
# GitHub Actions exposes $GITHUB_ENV as a writable file in each step;
# `echo "KEY=VAL" >> "$GITHUB_ENV"` makes KEY available as an env var
# in subsequent steps. tests/15 reads PHR_TEST_KEY to construct the
# `-i <key>` argument on macOS (the password path is Linux/Windows).
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "PHR_TEST_KEY=${TEST_KEY}" >> "${GITHUB_ENV}"
    echo "==> Wrote PHR_TEST_KEY=${TEST_KEY} to GITHUB_ENV"
else
    # Local/manual invocation (no GITHUB_ENV). Print the key path so
    # the user can `export PHR_TEST_KEY=...` themselves.
    echo "==> GITHUB_ENV unset (running outside CI); set manually:"
    echo "    export PHR_TEST_KEY=${TEST_KEY}"
fi

echo "==> Setup SUCCESS: ${USER}@${HOST}:${PORT} accepts ed25519 key auth."
echo "    sshd log: ${SSHD_LOG} (LogLevel DEBUG3)"
echo "    test key: ${TEST_KEY}"

# ---- 13. tail the DEBUG3 sshd log to the GitHub log ----------------------
# The smoke-test probe above proves pubkey auth works from a normal
# openssh client, but the integration tests use russh. If russh fails
# to authenticate we want the sshd-side reason visible inline in the
# provision-step log so we don't have to download the artifact. The
# full log is also persisted as a build artifact below.
echo "==> sshd DEBUG3 log so far (full file at ${SSHD_LOG}):"
sudo cat "${SSHD_LOG}" 2>&1 | tail -n 200 || true
echo "==> end of DEBUG3 log"