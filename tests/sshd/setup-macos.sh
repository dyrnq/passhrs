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
#    Override LogLevel to DEBUG3 — macOS auth failures don't print
#    anything at ERROR, and the smoke-test in the readiness loop below
#    hangs because macOS ssh has no controlling terminal and won't read
#    a password from our FIFO. The DEBUG3 output is what we'll read on
#    the test-side `Dump sshd log on failure` step.
sed "s|__SFTP_SERVER_PATH__|${SFTP_SERVER}|g" \
    "${SSHD_CFG_TEMPLATE}" \
    > "${SSHD_CFG}"
# macOS-only: bump log level. OpenSSH honours the FIRST LogLevel it
# sees and ignores later ones, so we have to delete the template's
# `LogLevel ERROR` before appending DEBUG3 — otherwise the auth-failure
# reason we want to see is silently suppressed by the template's
# "Quiet logging" default.
sed -i '' '/^LogLevel /d' "${SSHD_CFG}"
cat >> "${SSHD_CFG}" <<EOF

# --- passhrs CI overrides ---
LogLevel DEBUG3
EOF

# 2. Generate a host key on first run; reuse on subsequent runs.
if [ ! -f "${HOST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${HOST_KEY}" -N "" -q
fi

# 3. Create testuser if missing. macOS user records live in OpenDirectory,
#    not /etc/passwd, so use dscl.
#
#    Two macOS-specific quirks make a vanilla dscl user unable to log
#    in over SSH even with PasswordAuthentication yes + UsePAM yes:
#
#    a. AuthenticationAuthority: a dscl-created user has no auth
#       authority entries, so pam_opendirectory's account check
#       returns "Access denied for user ... by PAM account
#       configuration [preauth]". Adding `;basic;` opts the user in
#       to the basic-password authentication flow that PAM/SSH use.
#
#    b. password aging: macOS's pwpolicy gives newly-created users
#       a password-expiry policy. If the password is "expired" (or
#       the policy says "must change on next log in"), PAM rejects
#       the account even when the supplied password matches. We set
#       `passwordLastSet` to the current time so the password is
#       fresh from PAM's perspective, and clear any forced-expiry
#       policy via pwpolicy.
if ! dscl . -read "/Users/${USER}" UniqueID >/dev/null 2>&1; then
    UNIQUE_ID="55555"
    sudo dscl . -create "/Users/${USER}"
    sudo dscl . -create "/Users/${USER}" UserShell "/bin/zsh"
    sudo dscl . -create "/Users/${USER}" RealName "Passhrs Test User"
    sudo dscl . -create "/Users/${USER}" UniqueID "${UNIQUE_ID}"
    sudo dscl . -create "/Users/${USER}" PrimaryGroupID 20
    sudo dscl . -create "/Users/${USER}" NFSHomeDirectory "/Users/${USER}"
    sudo dscl . -create "/Users/${USER}" AuthenticationAuthority ";basic;"
    sudo dscl . -create "/Users/${USER}" Password "${PASS}"
    sudo createhomedir -u "${USER}" >/dev/null
fi

# Always reset password to the test value so re-runs are deterministic.
sudo dscl . -passwd "/Users/${USER}" "${PASS}" >/dev/null

# Refresh passwordLastSet so PAM treats the password as freshly set
# (avoids 'password expired' / 'must change on next login' rejections).
# Setting it to 0 also works; we use the current epoch to match what
# dscl . -passwd would record on a brand-new user.
NOW_EPOCH="$(date +%s)"
sudo dscl . -create "/Users/${USER}" passwordLastSet "${NOW_EPOCH}" 2>/dev/null || true

# Strip any forced-expiry / pw-policy that would deny SSH login on
# the next run. `pwpolicy -u USER -clear` removes all custom policies
# for the user, falling back to the system default (no expiry for
# non-admin users).
sudo pwpolicy -u "${USER}" -clear 2>/dev/null || true
# Belt-and-suspenders: also clear accountExpires (an absolute
# timestamp past which the account is locked).
sudo dscl . -delete "/Users/${USER}" accountExpires 2>/dev/null || true

# Diagnostic dump of the testuser's OpenDirectory state. PAM's
# account-management step on macOS uses pam_opendirectory.so and can
# deny a dscl-created account for any of: missing AuthenticationAuthority,
# non-empty accountPolicyData forcing pw change, passwordLastSet=0
# (never set), etc. Print the relevant attributes so future failures
# can be diagnosed from the CI log without an interactive shell.
echo "--- testuser OpenDirectory state ---"
sudo dscl . -read "/Users/${USER}" 2>&1 | head -60 || true
echo "--- pwpolicy ---"
sudo pwpolicy -u "${USER}" -getpolicy 2>&1 | head -20 || true
echo "--- /etc/pam.d/sshd ---"
sudo cat /etc/pam.d/sshd 2>&1 || true
echo "--- /Users/${USER} perms ---"
sudo ls -ldn "/Users/${USER}" 2>&1 || true
echo "--- /etc/nologin (if any) ---"
sudo ls -l /etc/nologin 2>&1 | head -3 || true
echo "--------------------------------------"

# 4. Tear down any previous instance bound to PORT. We track
#    sshd by PID across runs.
if [ -f "${SSHD_PID_FILE}" ]; then
    OLD_PID="$(cat "${SSHD_PID_FILE}" || true)"
    if [ -n "${OLD_PID}" ] && sudo kill -0 "${OLD_PID}" 2>/dev/null; then
        sudo kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
    rm -f "${SSHD_PID_FILE}"
fi
# Catch any orphan sshd from a previous crashed run that didn't
# write a pidfile but left a listener bound to PORT.
ORPHAN_PID=$(sudo lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)
if [ -n "${ORPHAN_PID}" ]; then
    echo "Killing orphan sshd pid=${ORPHAN_PID} from prior run"
    sudo kill "${ORPHAN_PID}" 2>/dev/null || true
    sleep 1
fi

# 5. Launch sshd detached into its own session.
#
#    The naive `sudo sshd ... &` keeps sshd in this bash script's
#    process group. When the script exits, the GitHub Actions
#    runner's step-cleanup delivers SIGKILL to every process in
#    the step's process group (we observed sshd dying ~100 s
#    after the readiness probe succeeded, but only after cargo
#    build + ~50 s of tests had started), so every later SSH
#    connection gets "Connection reset by peer".
#
#    macOS does not ship `setsid(1)` so we use Python (which the
#    runner always has) to do it: a small bootstrap that forks,
#    then in the child calls `os.setsid()` to create a brand-new
#    session and process group detached from the runner's step
#    process group, redirects stdio to /dev/null, and execs the
#    target. The runner's step-cleanup SIGKILL, which targets the
#    step's pgid specifically, does not reach processes in a
#    different pgid.
#
#    We intentionally KEEP `-D` so sshd stays in the foreground
#    of its new session — that gives us a stable PID ($! in
#    bash, captured by Python via fork's parent return) that we
#    can read with `kill -0` and `lsof` for both liveness and
#    teardown.
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
echo "Launched detached sshd (pid=${SSHD_PID}) via python3 os.setsid"

# 6. Wait for the daemon to accept connections (max 10s).
for i in $(seq 1 50); do
    if ! sudo kill -0 "${SSHD_PID}" 2>/dev/null; then
        echo "FATAL: detached sshd (pid ${SSHD_PID}) exited before becoming ready" >&2
        tail -n 50 "${SSHD_LOG}" >&2 || true
        exit 1
    fi
    if (echo >"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
        echo "test sshd ready at ${HOST}:${PORT} (pid=${SSHD_PID}, detached via setsid)"
        echo "sshd log: ${SSHD_LOG} (LogLevel DEBUG3)"
        exit 0
    fi
    sleep 0.2
done

echo "FATAL: sshd did not start within 10s" >&2
sudo kill "${SSHD_PID}" 2>/dev/null || true
tail -n 50 "${SSHD_LOG}" >&2 || true
exit 1