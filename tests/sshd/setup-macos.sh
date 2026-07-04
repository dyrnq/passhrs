#!/usr/bin/env bash
# Provision a real OpenSSH server on 127.0.0.1:22222 on a macOS runner.
# Uses /usr/sbin/sshd shipped with the OS — no homebrew install needed.
#
# Targets GitHub-hosted macos-14 runners; assumes passwordless sudo
# (the default on GitHub-hosted runners).
set -euo pipefail

USER="runner"
# PassTest1234# meets Windows password complexity (upper + lower + digit
# + special, 13 chars). Same value used by every platform setup script
# and the e2e tests so the test sshd authenticates passhrs consistently.
PASS="PassTest1234#"
# NOTE: USER used to be 'testuser' (a custom dscl user we created).
# That broke on the runner image because pam_sacl.so + pam_opendirectory
# require SACL authorizationdb grants we couldn't easily write via the
# sandboxed setup script. Switched to the runner user that the image
# ships with — its OpenDirectory record is pre-authorized for SSH.
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

# 3. Use the `runner` user that already exists on the GitHub-hosted
#    macOS image. It has a working home directory, is in the right
#    groups (staff, admin), has SACL ssh grants by default, and
#    passes every pam_opendirectory / pam_sacl / pam_nologin check
#    that a fresh dscl user fails.
#
#    The earlier dscl-based testuser approach hit a wall: macOS's
#    `/etc/pam.d/sshd` runs `account required pam_sacl.so
#    sacl_service=ssh` followed by `account required
#    pam_opendirectory.so`. pam_sacl denied the dscl user via
#    `com.apple.access_ssh`, returning PAM_PERM_DENIED before
#    pam_opendirectory even ran. The runner user already has
#    authorizationdb grants baked in by the image, so it sidesteps
#    the SACL problem entirely.
#
#    We just set its password to our known test password and
#    ensure ~/.ssh exists for completeness.
USER="runner"
HOME_DIR="/Users/${USER}"

# Reset runner's password to the test value so re-runs are
# deterministic.
#
# Why this is harder than it looks: macOS Sonoma+ requires a
# "secure token" to reset another user's password via either
# `dscl . -passwd` or `sysadminctl -resetPasswordFor`, even when
# the caller is root via sudo. The token unlock requires either
# the user's old password (we don't have it — fresh CI runner)
# or an interactive secure-token bootstrap that the sandboxed
# setup script can't perform. Both APIs report
#     "Operation is not permitted without secure token unlock"
#     "DS Error: -14090 (eDSAuthFailed)"
# and the password write silently no-ops.
#
# The way around it is `passwd(8)`: when invoked by root for a
# different user, `passwd` does NOT require secure token — it
# prompts for the new password twice via /dev/tty and updates
# the local OpenDirectory record directly. We drive that
# interactive prompt with Python's `pty.fork()` (the only
# pty-allocation helper on a stock macOS runner — neither
# setsid(1) nor expect(1) are installed by default).
#
# After the write we verify with `dscl . -authonly`, which
# doesn't need secure token (it just asks OpenDirectory whether
# the password matches the stored hash). If authonly rejects,
# the password set didn't take and sshd would just fail every
# PAM auth at test time — abort before launching sshd.
echo "Setting password for ${USER} via sudo passwd driven by python3 pty..."
SUCC="false"
if python3 - "$USER" "$PASS" <<'PYEOF' 2>&1
import pty, os, sys, time, select, errno

user, pw = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    # Child: exec sudo passwd <user>. The new argv[0] is "passwd"
    # so `ps` doesn't show the password in the visible arg list.
    os.execv("/usr/bin/sudo", ["sudo", "/usr/bin/passwd", user])
# Parent: drive the prompts.
def read_until(token, timeout=2.0):
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError as e:
                if e.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            buf += chunk
            if token in buf:
                return buf, True
    return buf, False

# "Changing password for <user>.\r\nNew password:" — wait for the
# first prompt before sending, otherwise passwd may consume the
# bytes as soon as the fd is writable and miss the question. The
# actual prompt text has shifted between macOS releases (pre-Sonoma
# uses "New password:"; Sonoma reports "New password for <user>:";
# Sonoma+ sometimes skips straight to "Retype new password:" if the
# initial password is provided on stdin). We deliberately look for
# just "assword" so both forms match, and capture the full transcript
# on failure for the CI log.
buf, ok = read_until(b"assword", timeout=15.0)
if not ok:
    sys.stderr.write("FAIL: never saw any 'password' prompt within 15s\n")
    sys.stderr.write("---- passwd transcript so far ----\n")
    sys.stderr.write(buf.decode("utf-8", errors="replace") + "\n")
    sys.stderr.write("---- end transcript ----\n")
    sys.exit(1)
# If "Retype" is already in the captured buffer, we received both
# prompts in one shot — skip the first write, just send the retype.
if b"Retype" not in buf:
    os.write(fd, pw.encode("utf-8") + b"\n")
    buf2, ok = read_until(b"Retype", timeout=15.0)
    if not ok:
        sys.stderr.write("FAIL: sent first password; never saw 'Retype' within 15s\n")
        sys.stderr.write((buf + buf2).decode("utf-8", errors="replace") + "\n")
        sys.exit(1)
os.write(fd, pw.encode("utf-8") + b"\n")
# Capture the verdict line. macOS prints either a success message
# or a "Try again" / "Authentication failed" line; we look for any
# newline-terminated verdict.
_, ok = read_until(b"\n", timeout=10.0)
# Drain anything left after the verdict line.
try:
    while True:
        r, _, _ = select.select([fd], [], [], 0.3)
        if not r:
            break
        chunk = os.read(fd, 4096)
        if not chunk:
            break
except OSError:
    pass
# Wait for child to exit and reap it.
wpid, status = os.waitpid(pid, 0)
sys.exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
PYEOF
then
    SUCC="true"
fi
if [ "${SUCC}" != "true" ]; then
    echo "FATAL: python3 pty-driven 'sudo passwd ${USER}' failed" >&2
    echo "See output above for the interactive transcript." >&2
    exit 1
fi

# Verify the password is actually accepted by PAM. We do this with a
# non-sshd probe — `dscl . -authonly` is the standard OpenDirectory
# authentication check and doesn't require a real SSH session. If the
# check fails, the rest of the setup is pointless.
echo "Verifying password via dscl . -authonly ..."
if ! sudo dscl . -authonly -user "${USER}" -password "${PASS}" 2>&1; then
    echo "FATAL: dscl . -authonly rejected the password we just set" >&2
    echo "Aborting before launching sshd; tests would all fail with" >&2
    echo "'PAM: password authentication failed' otherwise." >&2
    exit 1
fi

# Ensure /Users/runner/.ssh exists with sane perms. The runner
# user already owns /Users/runner (UID matches), so chown is a no-op.
if [ ! -d "${HOME_DIR}/.ssh" ]; then
    sudo mkdir -p "${HOME_DIR}/.ssh"
    sudo chmod 700 "${HOME_DIR}/.ssh"
fi

# Strip any forced-expiry / pw-policy that would deny SSH login on
# the next run. Run after the password reset because pwpolicy -clear
# can sometimes re-stamp passwordLastSet to 0.
sudo pwpolicy -u "${USER}" -clear 2>/dev/null || true
NOW_EPOCH="$(date +%s)"
sudo dscl . -create "/Users/${USER}" passwordLastSet "${NOW_EPOCH}" 2>/dev/null || true
sudo dscl . -delete "/Users/${USER}" accountExpires 2>/dev/null || true

# Diagnostic dump of the runner user's state. The same fields that
# made dscl-created users fail pam_opendirectory are printed so future
# regressions can be diagnosed from the CI log without a shell.
echo "--- ${USER} OpenDirectory state ---"
sudo dscl . -read "/Users/${USER}" 2>&1 | head -60 || true
echo "--- pwpolicy ---"
sudo pwpolicy -u "${USER}" -getpolicy 2>&1 | head -20 || true
echo "--- /etc/pam.d/sshd ---"
sudo cat /etc/pam.d/sshd 2>&1 || true
echo "--- ${HOME_DIR} perms ---"
sudo ls -ldn "${HOME_DIR}" 2>&1 || true
echo "--- /etc/nologin (if any) ---"
sudo ls -l /etc/nologin 2>&1 | head -3 || true
echo "--- com.apple.access_ssh rule ---"
sudo security authorizationdb read com.apple.access_ssh 2>&1 || true
echo "-----------------------------------"

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