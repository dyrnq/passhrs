# passhrs Architecture

## Project Structure

```
src/
├── main.rs      # Entry point: parse args → SSH connect → session/forward orchestration (~460L)
├── cli.rs       # Cli struct (clap definition) + SSH parameter parsing functions
├── types.rs     # Core types: ForwardSpec, DynamicForwardSpec, ProxyJumpSpec, RemoteFileInfo
├── ssh.rs       # SshHandler (Handler trait impl), authentication, run_session, RawModeGuard
├── forward.rs   # Local port forwarding + generic forward spawn utility
├── proxy.rs     # SOCKS5 + HTTP CONNECT proxy
└── sftp.rs      # SFTP push/pull, rsync sync, file listing
```

## Module Dependencies

```
main.rs
  ├── cli.rs     → types.rs
  ├── types.rs
  ├── ssh.rs     → types.rs, cli.rs
  ├── forward.rs → types.rs, ssh.rs
  ├── proxy.rs   → types.rs, ssh.rs
  └── sftp.rs    → types.rs
```

## Core Flow

```
Cli::parse()               ← clap argument parsing
  ↓
parse_destination()        ← parse user@host[:port]
parse_ssh_options()        ← parse -o k=v
  ↓
SshHandler::new()          ← strict_check + known_hosts_path
  ↓
client::connect()          ← russh TCP + SSH handshake
  ↓
authenticate()             ← public key / password authentication
  ↓
[SFTP push/pull/rsync]     ← optional file transfer
  ↓
[spawn_forward_tasks()]    ← -L / -D / -H forwarding
  ↓
[channel.exec() / shell()] ← command execution or interactive shell
  ↓
run_session()              ← stdout/stderr output + stdin input
```

## Port Forwarding

| Flag | Type | Function | Description |
|------|------|----------|-------------|
| `-L` | Local | `local_port_forward()` | Listen locally, forward through SSH to remote |
| `-R` | Remote | `server_channel_open_forwarded_tcpip()` | Listen remotely, forward back to local |
| `-D` | SOCKS5 | `socks_proxy_forward()` | SOCKS5 dynamic proxy |
| `-H` | HTTP CONNECT | `http_connect_forward()` | HTTP CONNECT proxy |

Each forwarding mode (-L/-D/-H) uses a separate SSH connection via `tokio::spawn`,
managed by the generic `spawn_forward_tasks()` function.

## File Transfer

| Flag | Protocol | Features |
|------|----------|----------|
| `--push` | SFTP | Recursive file/directory upload |
| `--pull` | SFTP | Recursive file/directory download |
| `--rsync` | SFTP + copia | Skip unchanged files (mtime/size), copia delta sync |

## Authentication Methods

1. Public key (`-i` + `--identity-passphrase`)
2. Password (`--password`, `--password-file`, or `@file` syntax)
3. None (fallback, usually fails)

## CI/CD

- GitHub Actions: lint → unit-tests (4 platforms) → integration-tests (Docker SSH) → Docker multi-arch build
- Release: tag triggers Release workflow, builds and uploads platform binaries
- Integration tests: Docker container `phr-test-ssh` (Alpine + OpenSSH, port 22222)
