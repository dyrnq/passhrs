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
#
# HOMEBREW_NO_AUTO_UPDATE=1 stops brew from running `brew update` before
# the install. On a fresh macos-14 runner the brew prefix has never
# seen an update, so a vanilla `brew install openssh` triggers an
# implicit `brew update` first; if that update hits a transient
# GitHub-API or DNS flake (very common on shared CI egress IPs) the
# whole `brew install` aborts in a few seconds with no useful context
# — exactly the failure pattern we saw on the last 10+ CI runs. Pin
# NO_AUTO_UPDATE and let a single explicit retry absorb the flake.
#
# HOMEBREW_NO_INSTALL_FROM_API=1 keeps the formula fetch from the
# local tap repo instead of the new API endpoint, which is more
# reliable in CI environments that occasionally have restricted
# egress to *.bintray-style hosts.
sudo -u "${SUDO_USER:-runner}" -H bash -c "
    export PATH='${BREW_BIN}:\$PATH'
    export HOMEBREW_NO_AUTO_UPDATE=1
    export HOMEBREW_NO_INSTALL_FROM_API=1
    export HOMEBREW_NO_ANALYTICS=1
    brew install openssh
" || {
    echo "WARN: brew install openssh failed on first try; retrying once after 5s..." >&2
    sleep 5
    sudo -u "${SUDO_USER:-runner}" -H bash -c "
        export PATH='${BREW_BIN}:\$PATH'
        export HOMEBREW_NO_AUTO_UPDATE=1
        export HOMEBREW_NO_INSTALL_FROM_API=1
        export HOMEBREW_NO_ANALYTICS=1
        brew install openssh
    " || {
        echo "FATAL: brew install openssh failed twice" >&2
        exit 1
    }
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
# OpenSSH honours the FIRST occurrence of each directive, so we have to
# strip template defaults before appending per-run overrides.
#   - `LogLevel ERROR`: replaced with DEBUG3 so SFTP subsystem session
#     attempts and auth-failure context (PAM module verdicts, signature
#     verify results) are visible when a future regression hits us.
#   - `UsePAM yes`: replaced with `UsePAM no` because macOS's dscl-built
#     testuser has no secure-token attached — pam_opendirectory.so's
#     account phase then unconditionally returns PAM_PERM_DENIED after
#     the publickey signature is already verified, surfacing as
#     `Failed publickey ... Access denied for user <u> by PAM account
#     configuration` in the sshd log. With UsePAM no, sshd handles
#     pubkey auth entirely itself (no PAM for auth, account, session
#     or password). Linux/Windows keep UsePAM yes — the test runners
#     there authenticate via the runner account which has fully-formed
#     PAM records and UsePAM no would break the password path.
sed -i '' '/^LogLevel /d; /^UsePAM /d' "${SSHD_CFG}"
# Runtime-conditional `PerSourcePenalties no`: OpenSSH 9.8+ adds a
# per-source-IP connection-rate penalty that is ON by default. After
# ~30 back-to-back test runs from 127.0.0.1 the cumulative penalty
# drops late-run connections mid-handshake with ECONNRESET, breaking
# the last 2 integration tests (Issue #9 — sshd log literally shows
# `srclimit_penalise: ipv4: new 127.0.0.1/32 deferred penalty of N
# seconds` and `drop connection #0 from [127.0.0.1]:N on [127.0.0.1]:
# 22222 penalty: ...`).
#
# IMPORTANT: the directive name is `PerSourcePenalties` (not
# `srclimit` as the earlier comment claimed). OpenSSH has used
# `persourcepenalties` since the feature was introduced in 9.8 — the
# `srclimit` keyword never existed. Confirmed by reading
# openssh-portable/servconf.c keyword table for V_9_8 / V_10_0 /
# V_10_3p1: only `persourcepenalties` and `persourcepenaltyexemptlist`
# are registered. Writing `srclimit no` is treated as an unknown
# directive; sshd fatals at parse time on strict builds or silently
# ignores it on lenient ones — either way, the per-source penalty
# stays ON because nothing disables it.
#
# Two probe strategies in order (revised after PR #14 windows-2022
# failure exposed a false-positive in the original single-probe
# approach):
#   1. Run `sshd -T -f` against the BASELINE config (no override
#      directive) and inspect the dump output:
#        - OpenSSH 10.0+ (default ON): prints a long stats line
#          beginning with `persourcepenalties crash:` — penalty is
#          ACTIVE, we need to override.
#        - OpenSSH 9.8 (default OFF): prints `persourcepenalties no`
#          — penalty is ALREADY off, the directive is a no-op, do
#          NOT append.
#   2. If (and only if) the baseline says default-ON, write
#      `PerSourcePenalties no` to a scratch config, re-run `sshd -T
#      -f`, and confirm the dump output FLIPS to
#      `persourcepenalties no` AND the `crash:` line is gone.
#      Belt-and-braces against a build where the directive parses
#      but is silently ignored (uncommon, cheap to detect).
#
# Why the original single-probe pattern was wrong: OpenSSH 9.8's
# dump function emits `persourcepenalties no` whenever
# `per_source_penalty.enabled == 0`, regardless of whether the
# directive was explicitly set or just defaulted. So matching that
# line in the scratch config (where we wrote the directive) was
# meaningless — the same line would have appeared without it. The
# probe always matched on default-OFF binaries, and appending the
# directive to sshd_config on Win32-OpenSSH 10.0p2 broke every
# Windows integration test connection with os error 10054.
SCRATCH_CFG="$(mktemp -t sshd-persrc-probe.XXXXXX)"
DEFAULT_OUT="$("${SSHD_BIN}" -T -f "${SSHD_CFG}" 2>&1)"
DEFAULT_RC=$?
if [ "${DEFAULT_RC}" -ne 0 ]; then
    echo "    sshd -T baseline probe failed (rc=${DEFAULT_RC}); skipping PerSourcePenalties override"
elif printf '%s\n' "${DEFAULT_OUT}" | grep -qE '^persourcepenalties[[:space:]]+crash:'; then
    # Default-ON binary (OpenSSH 10.0+ dump format). Validate the
    # override flips the dump to `persourcepenalties no` before
    # committing to it.
    cp "${SSHD_CFG}" "${SCRATCH_CFG}"
    printf '\nPerSourcePenalties no\n' >> "${SCRATCH_CFG}"
    OVERRIDE_OUT="$("${SSHD_BIN}" -T -f "${SCRATCH_CFG}" 2>&1)"
    OVERRIDE_RC=$?
    if [ "${OVERRIDE_RC}" -eq 0 ] \
        && printf '%s\n' "${OVERRIDE_OUT}" | grep -qiE '^persourcepenalties[[:space:]]+no\b' \
        && ! printf '%s\n' "${OVERRIDE_OUT}" | grep -qE '^persourcepenalties[[:space:]]+crash:'; then
        echo "    sshd default is ON, 'PerSourcePenalties no' applied as effective — appending"
        cat >> "${SSHD_CFG}" <<'EOF'

# Disable per-source-IP connection penalty (Issue #9). OpenSSH 10.0+
# enables this by default; the test suite hammers 127.0.0.1 with
# ~30+ connections during one job, so without this override the
# last ~2 integration tests get mid-handshake ECONNRESET drops.
PerSourcePenalties no
EOF
    else
        echo "    sshd default is ON but 'PerSourcePenalties no' did not flip dump output (rc=${OVERRIDE_RC}); keeping default (penalty stays ON; MaxStartups should cover)"
    fi
elif printf '%s\n' "${DEFAULT_OUT}" | grep -qiE '^persourcepenalties[[:space:]]+no\b'; then
    # Default-OFF binary (OpenSSH 9.8 dump format). The directive is
    # a no-op; do NOT append.
    echo "    sshd default is OFF ('persourcepenalties no') — no override needed"
else
    # Either binary predates PerSourcePenalties (pre-9.8) or its
    # dump output is unexpected. Skip — same as the pre-fix state.
    echo "    sshd dump output has no persourcepenalties line — pre-9.8 binary or unexpected, keeping default"
fi
rm -f "${SCRATCH_CFG}"
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
# Sonoma+ PAM account phase denies dscl-created users without a
# secure token — see comment block above. Disable PAM entirely on
# macOS; pubkey auth is handled by sshd itself.
UsePAM no
EOF

# ---- 3. generate host key + test-user keypair -----------------------------

if [ ! -f "${HOST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${HOST_KEY}" -N "" -q
fi
if [ ! -f "${TEST_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${TEST_KEY}" -N "" -q
    # ssh-keygen ran as root (the whole script runs under sudo), so
    # the key file is root:root mode 600 by default. That breaks
    # BOTH the in-script smoke test (step 11) AND the integration
    # tests, in different ways:
    #   - Smoke test: `ssh -i <key>` is launched by this root shell.
    #     OpenSSH rejects the key regardless of effective UID if the
    #     mode bits are too open — but it ALSO rejects mode 600 when
    #     the owner is a different uid (the smoke test is in the
    #     runner user's name at the protocol level), exiting 255
    #     with "Permissions 0600 for ... are too open".
    #   - Integration tests: russh runs as the runner user, which
    #     can't read root-owned 600 — "Failed to load key: Permission
    #     denied (os error 13)".
    # chmod 644 alone (what the previous attempt did) fixes the
    # russh read but breaks the ssh smoke test the other way.
    # Right answer: chown to the unprivileged runner user, then
    # keep mode 600. The runner user owns the file and has the only
    # read bit set — ssh is happy, russh is happy, and no other
    # process on the runner has any reason to touch this ephemeral
    # key under /tmp.
    KEY_OWNER="${SUDO_USER:-root}"
    chown "${KEY_OWNER}:staff" "${TEST_KEY}" "${TEST_KEY_PUB}"
    chmod 600 "${TEST_KEY}"
    chmod 644 "${TEST_KEY_PUB}"
fi

# ---- 4. create testuser via dscl (Sonoma+ secure-token-safe path) --------

# sysadminctl -addUser was the previous path. It is broken on Sonoma+
# in non-interactive CI contexts: the tool bootstraps a secure-token
# for the new account and that requires an interactive auth dialog
# the runner can't satisfy, so the call fails with the opaque
# `Could not create account. (-?)`. dscl . -create the same
# OpenDirectory record by hand; this skips the secure-token bootstrap
# entirely because pubkey auth doesn't need one (sshd validates the
# challenge signature against authorized_keys without ever consulting
# the user's password). Set Password to a literal asterisk to lock
# the account out of password login — belt-and-braces on top of the
# `PasswordAuthentication no` we already write into sshd_config.

# Idempotency: clean up any prior record + home dir from a previous run
# before recreating, otherwise dscl . -create returns "object already
# exists" errors.
if sudo dscl . -read "/Users/${USER}" >/dev/null 2>&1; then
    echo "==> Removing pre-existing ${USER} from a previous run..."
    sudo sysadminctl -deleteUser "${USER}" 2>&1 \
        || sudo dscl . -delete "/Users/${USER}" 2>&1 || true
    # The home dir survives -deleteUser; nuke it so the next -create
    # doesn't inherit stale state (notably .ssh/authorized_keys).
    sudo rm -rf "${HOME_DIR}" 2>/dev/null || true
fi

echo "==> Creating ${USER} via dscl . -create (no sysadminctl, no token bootstrap)..."
# UniqueID 550 + PrimaryGroupID 20 (staff) match the canonical macOS
# user template and don't collide with any system account on a fresh
# runner. RealName and NFSHomeDirectory are needed for pam_opendirectory
# to resolve the user record at auth time. Password '*' disables
# password login at the OpenDirectory layer — pubkey-only.
sudo dscl . -create "/Users/${USER}" UniqueID 550 || {
    echo "FATAL: dscl UniqueID failed" >&2; exit 1; }
sudo dscl . -create "/Users/${USER}" PrimaryGroupID 20 || {
    echo "FATAL: dscl PrimaryGroupID failed" >&2; exit 1; }
sudo dscl . -create "/Users/${USER}" UserShell /bin/zsh || {
    echo "FATAL: dscl UserShell failed" >&2; exit 1; }
sudo dscl . -create "/Users/${USER}" RealName "passhrs test user" || {
    echo "FATAL: dscl RealName failed" >&2; exit 1; }
sudo dscl . -create "/Users/${USER}" NFSHomeDirectory "${HOME_DIR}" || {
    echo "FATAL: dscl NFSHomeDirectory failed" >&2; exit 1; }
sudo dscl . -create "/Users/${USER}" Password "*" || {
    echo "FATAL: dscl Password failed" >&2; exit 1; }
sudo createhomedir -c -u "${USER}" >/dev/null 2>&1 || {
    echo "FATAL: createhomedir -c -u ${USER} failed" >&2; exit 1; }

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
#
# Pre-create the log file with world-readable mode BEFORE launching
# sshd (same rationale as setup-linux.sh step 6b). sshd opens -E
# targets with O_APPEND — it doesn't set the mode bits — so the
# 644 we set here is what the unprivileged `Upload sshd log (unix)`
# step in ci.yml will see. Letting sshd create it as root 600 hits
# EACCES on the upload step.
sudo install -m 644 /dev/null "${SSHD_LOG}"

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
# Drive a real SSH handshake to confirm the keypair is wired correctly.
# This catches: wrong home-dir perms, authorized_keys not picked up,
# sshd_config typo, SACL grant missing.
#
# IMPORTANT: run ssh as the key's owner (KEY_OWNER, set in step 3 to
# the unprivileged runner user). ssh's secure_filename() check refuses
# keys whose st_uid doesn't match the calling process's getuid(), AND
# rejects "too open" perms regardless of effective UID. Running the
# smoke test as root against a runner-owned 600 key would fail one or
# the other check, aborting the step before the integration tests even
# run. The integration tests run as the runner user anyway, so a
# runner-as-runner smoke test exercises the exact same identity the
# tests will use.
echo "==> Smoke-testing ssh key auth (as ${KEY_OWNER})..."
if ! sudo -u "${KEY_OWNER}" -H bash -c "
    ssh -i '${TEST_KEY}' \
        -p '${PORT}' \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        '${USER}@${HOST}' \
        'echo ssh_key_auth_ok'
"; then
    echo "FATAL: ssh key auth probe failed; check sshd log" >&2
    sudo tail -n 80 "${SSHD_LOG}" >&2 || true
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