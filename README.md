# passhrs — SSH Automation Tool

**passhrs** (Password SSH Rust) is a [russh](https://github.com/warp-tech/russh)-based SSH automation client with an **OpenSSH-compatible CLI interface**, plus password direct-pass, key passphrase, file transfer, HTTP CONNECT proxy and more. **Pure Rust, no OpenSSH or external dependencies**.

## Features

### SSH Standard Compatible Options
`-p` `-l` `-i` `-L` `-R` `-D` `-J` `-N` `-f` `-C` `-t` `-n` `-v` `-q` `-E` `-o` `-4` `-6` `-A` `-a` `-S`

| Option    | Description                        |
|:----------|:-----------------------------------|
| `-p`      | Port                               |
| `-l`      | Login user                         |
| `-i`      | Identity file (supports passphrase) |
| `-L`      | Local port forwarding              |
| `-R`      | Remote port forwarding             |
| `-D`      | SOCKS5 dynamic forwarding          |
| `-J`      | ProxyJump                          |
| `-C`      | Compression (zlib RFC 4253)        |
| `-N`      | Do not execute a command           |
| `-f`      | Fork to background                 |
| `-t`      | Force PTY allocation               |
| `-n`      | Redirect stdin to `/dev/null`      |
| `-v`      | Verbose mode (multiple levels)     |
| `-q`      | Quiet mode                         |
| `-E`      | Log output to file                 |
| `-H`      | HTTP CONNECT proxy                 |
| `-4/-6`   | Address family restriction         |
| `-A`      | Forward agent                      |
| `-a`      | Disable agent forwarding           |
| `-S`      | Control socket path                |
| `-o`      | SSH options (see below)            |

### Exclusive Features

| Option                          | Description                                    |
|:--------------------------------|:-----------------------------------------------|
| `--password <pw>`               | Direct SSH password (or `@file`)               |
| `--password-file <path>`        | Read SSH password from file                    |
| `--identity-passphrase <pw>`    | Identity file passphrase (or `@file`)          |
| `--identity-passphrase-file <path>` | Read identity passphrase from file         |
| `--exec-env <VAR=val>`          | Inject env vars before command (multi)         |
| `--connect-timeout <s>`         | TCP connection timeout                         |
| `--timeout <s>`                 | Inactivity timeout                             |
| `--push <local>:<remote>`       | Upload files/dirs via SFTP (multi)             |
| `--pull <remote>:<local>`       | Download files/dirs via SFTP (multi)           |
| `--rsync <local>:<remote>`      | Smart sync (mtime/size + copia delta)          |
| `--rsync-opt <opt>`             | Rsync options (delete, dry-run, exclude, etc.) |
| `--debug-all`                   | Force debug-level logging (overrides `-q`)     |

### Supported `-o` Key-Value Pairs

| Key                           | Effect                         |
|:------------------------------|:-------------------------------|
| `StrictHostKeyChecking=no/yes`| Host key verification          |
| `UserKnownHostsFile=<path>`   | Known hosts file path          |
| `ServerAliveInterval=<n>`     | Keepalive interval (seconds)   |
| `ServerAliveCountMax=<n>`     | Max keepalive failures         |
| `TCPKeepAlive=yes/no`         | TCP keepalive                  |
| `ExitOnForwardFailure=yes/no` | Exit on forward failure        |
| `SendEnv <VAR>`               | Forward environment variable   |

### Port Forwarding
- **`-L`** Local forward: `[bind:]port:host:port`
- **`-R`** Remote forward: `[bind:]port:host:port`
- **`-D`** SOCKS5 proxy: `[bind:]port`
- **`-H`** HTTP CONNECT proxy: `[bind:]port`
- Supports `ExitOnForwardFailure=yes` (OpenSSH compatible)

### File Transfer
```bash
# Upload file
passhrs --push local.txt:/remote/path.txt --password pass user@host

# Download file
passhrs --pull /remote/file.txt:local.txt --password pass user@host

# Upload directory
passhrs --push ./scripts/:/tmp/scripts/ user@host

# Upload then execute
passhrs --push script.sh:/tmp/s.sh user@host bash /tmp/s.sh

# Rsync-style sync
passhrs --rsync /local/dir/:/remote/dir/ --rsync-opt delete user@host
```

### Environment Variables
```bash
passhrs --exec-env MYVAR=hello --exec-env PATH=/custom/bin user@host 'echo $MYVAR'
```

## Installation

### From Source
```bash
git clone https://github.com/dyrnq/passhrs.git
cd passhrs
cargo build --release
./target/release/passhrs --help

# Install to PATH
cp target/release/passhrs ~/.local/bin/
```

### From GitHub Releases
Pre-built binaries: Linux (x86_64, aarch64, armv7) / macOS (Intel, Apple Silicon) / Windows (x86_64).

## Usage Examples

```bash
# Password login with command
passhrs --password mypass user@host "ls -la"

# Key + passphrase
passhrs -i ~/.ssh/id_ed25519 --identity-passphrase myphrase user@host

# Password/passphrase from file
passhrs --password @/path/to/password.txt user@host
passhrs --identity-passphrase <(echo -n myphrase) -i ~/.ssh/id_ed25519 user@host

# Port forwarding (background)
passhrs -N -f -L 8118:localhost:8118 user@host

# To run passhrs detached from your shell session, use your shell's
# job control rather than a dedicated passhrs flag. POSIX:
nohup passhrs -N -L 8118:localhost:8118 user@host &
# Windows PowerShell:
Start-Process passhrs -ArgumentList '-N','-L','8118:localhost:8118','user@host' -WindowStyle Hidden

# SOCKS5 proxy
passhrs -D 1080 user@host

# Remote forwarding
passhrs -R 8080:localhost:80 user@host

# HTTP CONNECT proxy
passhrs -H 8888 -N user@host
curl -x http://127.0.0.1:8888 -s http://example.com

# ProxyJump
passhrs -J jump-user@jump-host:22 root@target-host

# Upload script and execute
passhrs --push script.sh:/tmp/script.sh user@host bash /tmp/script.sh

# Environment variables
passhrs --exec-env MYVAR=hello user@host "echo \$MYVAR"

# OpenSSH compatible usage
passhrs -p 12322 -C -o StrictHostKeyChecking=no user@host

# Interactive shell
passhrs user@host
```

## SSH Compatibility Reference

### Option Comparison

```
ssh:   passhrs:   description
──────────────────────────────────────────────────────────────────
 -4    ✅  -4       IPv6 only
 -6    ✅  -6       IPv6 only
 -A    ✅  -A       Agent forwarding
 -a    ✅  -a       Disable agent forwarding
 -C    ✅  -C       Enable compression
 -D    ✅  -D       SOCKS5 dynamic forwarding
 -E    ✅  -E       Log to file
 -f    ✅  -f       Fork to background
 -H    ⭐  —        HTTP CONNECT proxy (passhrs unique, OpenSSH has no -H)
 -i    ✅  -i       Identity file (supports passphrase)
 -J    ✅  -J       ProxyJump
 -L    ✅  -L       Local port forwarding
 -l    ✅  -l       Login name
 -N    ✅  -N       Do not execute command
 -n    ⚠️  -n       Conflict: passhrs redirects stdin, OpenSSH disables stdin
 -o    ✅  -o       SSH config options
 -p    ✅  -p       Port
 -q    ✅  -q       Quiet mode
 -R    ✅  -R       Remote port forwarding
 -S    ✅  -S       Control socket path (Unix only, passhrs-native protocol — see below)
 -t    ✅  -t       Force PTY
 -v    ✅  -v       Verbose output (-vv, -vvv)

 -B    ❌  —        Bind interface
 -b    ❌  —        Bind address
 -c    ✅  -c       Cipher spec (comma-separated, priority order)
 -e    ❌  —        Escape character
 -F    ❌  —        SSH config file
 -G    ❌  —        Print config and exit
 -g    ❌  —        Allow remote hosts to connect local forwards
 -I    ❌  —        PKCS#11
 -K    ❌  —        Enable GSSAPI delegation
 -k    ❌  —        Disable GSSAPI delegation
 -M    ❌  —        ControlMaster mode
 -m    ✅  -m       MAC algorithm (comma-separated, priority order)
 -O    ❌  —        Control command
 -Q    ❌  —        Query algorithms
 -s    ❌  —        SSH subsystem
 -T    ✅  -T       Disable PTY allocation
 -V    ✅  -V       Version
 -W    ❌  —        Tunnel forwarding
 -w    ❌  —        Tunnel device
 -x    ❌  —        Disable X11 forwarding
 -Y    ❌  —        Trusted X11 forwarding
 -y    ❌  —        Accept all host keys
```

### Statistics

| Category              | Count | Ratio |
|:----------------------|:------|:------|
| Total SSH short opts  | ~43   | 100%  |
| **Implemented**       | **24**| **56%** |
| Conflicting semantics | 1 (`-n`) | 2% |
| Not implemented       | ~21   | 49%   |

### Not Implemented — Notes

**Can be added via russh (low effort):**
- `-C` compression level: flate2 feature

**Semantically not fitting:** `-D` (not a proxy tool), `-W` tunnel, `-G`/`-Q` debug, `-B`/`-b`/`-e`/`-s`/`-w` (rarely used)

**`-S` control socket caveat:** passhrs implements `-S <path>` as a **passhrs-native** master/resume protocol over a Unix-domain socket at `<path>` (mode `0o600`, removed automatically on master exit). It is **not wire-compatible with OpenSSH's** control protocol — an OpenSSH client cannot talk to a passhrs master and vice versa. Wire format: resume-to-master `<u32 BE length><UTF-8 command line>`; master-to-resume `<u32 BE length><tag 1=stdout / 2=stderr / 0=done><payload>`, where the done frame is `<u32 1><tag 0><u8 exit_code>` (length=1 so the reader picks up the exit code via the same `len`-byte payload read used for stdout/stderr). Unix-only in v1; Windows named-pipe equivalent is a separate follow-up.

**Larger effort:** `-F` config file (needs full ssh_config parser)

## Platform Support

| Platform                             | Status      |
|:-------------------------------------|:------------|
| Linux x86_64 / aarch64 / armv7       | ✅ Tested   |
| macOS Intel / Apple Silicon          | ✅ Buildable |
| Windows x86_64                       | ✅ Buildable (`-f` uses `CREATE_NO_WINDOW`) |

## Tech Stack

- **Rust** — core language
- **russh** — SSH protocol (pure Rust)
- **russh-sftp** — SFTP file transfer
- **clap** — CLI argument parsing
- **tokio** — async runtime
- **flate2** — zlib compression (RFC 4253)
- **copia** — rsync-style delta sync

## Build & Test

```bash
# Build
cargo build --release

# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --all-targets -- -D warnings

# Unit tests
cargo test --release

# Integration tests (requires Docker)
make docker-start && cargo test --release -- --include-ignored

# Full CI pipeline
make ci
```

## License

MIT

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for module structure, core flow, forwarding modes, and authentication details.
