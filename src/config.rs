//! ssh_config(5) resolver (Issue #67).
//!
//! Wires the upstream `russh-config` crate into passhrs so users
//! can put their existing `~/.ssh/config` to work without
//! translating every line to `-o key=value` (and `Host` patterns,
//! glob negation, `Include`, etc. become first-class).
//!
//! Only the keywords `russh-config` itself understands are
//! surfaced (see the `ResolvedConfig` field docs for the
//! exhaustive list). Anything else — `ForwardX11`,
//! `ForwardAgent`, `Compression`, `LocalForward`,
//! `RemoteForward`, `Include`, `Match exec=`, … — is silently
//! dropped by the upstream parser. Users who need those should
//! pass `-o key=value` until follow-up issues close.
//!
//! Precedence (highest wins):
//!   1. `-o key=value` flags (already handled separately by
//!      `cli::parse_ssh_options`)
//!   2. CLI flags (`-p`, `-l`, `-i`, `-J`, …)
//!   3. ssh_config `Host` block matching (this module)
//!   4. defaults (port 22, user `root`, no identity, no
//!      proxy jump)
//!
//! `-F /dev/null` short-circuits lookup (matches OpenSSH).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::cli::Cli;

/// Fields we surface from ssh_config lookups. Mirrors the
/// subset of keywords `russh-config` 0.58 actually parses; if
/// upstream grows new keywords we surface them here too.
///
/// All fields are `Option<T>` because an absent directive
/// means "no override from config" — the caller layers the
/// resolved values onto the Cli only where Cli didn't already
/// set them.
#[derive(Debug, Default, Clone)]
pub(crate) struct ResolvedConfig {
    /// `Hostname <real-host>` — replaces the host part of the
    /// user's destination when matching `Host <alias>` block.
    pub hostname: Option<String>,
    /// `User <name>` — wins over the user part of the
    /// destination when CLI `-l` was not passed.
    pub user: Option<String>,
    /// `Port <n>` — wins over destination port when CLI `-p`
    /// was not passed.
    pub port: Option<u16>,
    /// First `IdentityFile <path>` from the matching block.
    /// `russh-config` exposes a `Vec<PathBuf>` (multiple
    /// IdentityFile directives accumulate); passhrs consumes
    /// only the first today — subsequent ones would need a
    /// fallback chain.
    pub identity_file: Option<PathBuf>,
    /// `ProxyJump <user@host[:port]>` — wins over `-J` when
    /// the user did not pass `-J` on the command line.
    pub proxy_jump: Option<String>,
    /// `StrictHostKeyChecking yes|no` — layered onto the
    /// runtime by `main.rs` after the `-o key=value` opts map
    /// is consulted.
    pub strict_host_key_checking: Option<bool>,
    /// `UserKnownHostsFile <path>` — overrides the runtime's
    /// default known-hosts file when set.
    pub user_known_hosts_file: Option<PathBuf>,
}

impl From<russh_config::Config> for ResolvedConfig {
    fn from(c: russh_config::Config) -> Self {
        let hc = c.host_config;
        Self {
            hostname: hc.hostname,
            user: hc.user,
            port: hc.port,
            // russh-config exposes Vec; passhrs v1 only honors
            // the first IdentityFile. Subsequent ones would
            // require a fallback chain that's not implemented.
            identity_file: hc.identity_file.and_then(|mut v| v.pop()),
            proxy_jump: hc.proxy_jump,
            strict_host_key_checking: hc.strict_host_key_checking,
            user_known_hosts_file: hc.user_known_hosts_file,
        }
    }
}

/// Resolve ssh_config for `destination` (the host part of the
/// user's command line, i.e. the alias). Returns
/// `ResolvedConfig::default()` if no config applies (either
/// `-F /dev/null` was passed, or `~/.ssh/config` is missing on
/// the default lookup path).
///
/// Errors only when:
/// - `-F <file>` was given but the file can't be opened /
///   parsed (OpenSSH errors here too)
/// - `parse_ssh_config` finds lines outside any `Host` block
///   (`Error::HostNotFound` from russh-config)
pub(crate) fn resolve_config(cli: &Cli, destination: &str) -> Result<ResolvedConfig> {
    if let Some(ref path) = cli.config_file {
        // User explicitly named a file. Honor the special
        // `/dev/null` short-circuit that skips lookup entirely
        // — matches OpenSSH exactly.
        if path == Path::new("/dev/null") {
            return Ok(ResolvedConfig::default());
        }
        // Explicit -F: missing file is a HARD error (OpenSSH
        // exits with "Could not open configuration file").
        let cfg = russh_config::parse_path(path, destination)
            .with_context(|| format!("-F: failed to load ssh config: {}", path.display()))?;
        return Ok(cfg.into());
    }

    // No -F: try ~/.ssh/config. Missing file / missing home is
    // SILENT (OpenSSH silently falls through when the user has
    // no config file). Other parse errors propagate.
    match russh_config::parse_home(destination) {
        Ok(cfg) => Ok(cfg.into()),
        Err(russh_config::Error::NoHome) | Err(russh_config::Error::Io(_)) => {
            Ok(ResolvedConfig::default())
        }
        Err(russh_config::Error::HostNotFound) => Err(anyhow!(
            "ssh config: directives outside any `Host` block (malformed file)"
        )),
    }
}

/// Layer `resolved` onto `cli`, filling only fields that the
/// user did NOT set on the command line. This encodes the
/// OpenSSH precedence rule: CLI flag wins, config fills in
/// only what's missing.
///
/// Port is intentionally NOT handled here — the existing
/// `main.rs` port logic already distinguishes "user passed
/// `-p 22`" from "user didn't pass `-p`" via the
/// `cli.ssh_port != 22` heuristic, and folds `-o port=`,
/// destination port, and config port in the right order.
/// Threading port through here would either duplicate or
/// shadow that logic; the inline branch in `main.rs` is
/// clearer.
pub(crate) fn apply_resolved(cli: &mut Cli, resolved: &ResolvedConfig) {
    if cli.user.is_none() {
        if let Some(ref u) = resolved.user {
            cli.user = Some(u.clone());
        }
    }
    if cli.identity_file.is_none() {
        if let Some(ref p) = resolved.identity_file {
            cli.identity_file = Some(p.clone());
        }
    }
    if cli.proxy_jump.is_none() {
        if let Some(ref p) = resolved.proxy_jump {
            cli.proxy_jump = Some(p.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the resolver. The clap-acceptance tests
    //! in `tests/08_compat_args.rs` cover the parser surface;
    //! here we exercise `resolve_config` + `apply_resolved`
    //! directly so the precedence logic, glob matching, and
    //! `/dev/null` short-circuit are pinned byte-for-byte.
    use super::*;
    use clap::Parser;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Per-test unique counter — Rust runs unit tests in
    /// parallel by default, and we write each fixture to its
    /// own temp file to avoid races.
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Write `contents` to a fresh temp file and return the
    /// path. Each call yields a unique file (PID + counter),
    /// so tests can run in parallel without trampling each
    /// other's fixture. Files leak across runs — they're
    /// tiny and well under `/tmp` pressure.
    fn write_fixture(contents: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "passhrs-config-test-{}-{}.txt",
            std::process::id(),
            n,
        ));
        std::fs::write(&path, contents).expect("write fixture");
        path
    }

    /// Run a fixture config string through the resolver.
    /// Returns the populated `ResolvedConfig`.
    fn resolve_with(cli_args: &[&str], fixture: &str, host: &str) -> ResolvedConfig {
        let path = write_fixture(fixture);
        let mut cli = Cli::parse_from(cli_args);
        cli.config_file = Some(path);
        resolve_config(&cli, host).expect("resolve")
    }

    #[test]
    fn parses_hostname_user_port_identity_proxy_jump() {
        let cfg = resolve_with(
            &["passhrs", "test-host"],
            r#"
Host test-host
  Hostname real-server.example.com
  User alice
  Port 2222
  IdentityFile ~/.ssh/test_key
  ProxyJump bastion@hop.internal
"#,
            "test-host",
        );
        assert_eq!(cfg.hostname.as_deref(), Some("real-server.example.com"));
        assert_eq!(cfg.user.as_deref(), Some("alice"));
        assert_eq!(cfg.port, Some(2222));
        // `~` expands via russh-config. Compare via suffix so the
        // assertion holds on both Unix (home=/home/runner) and
        // Windows (home=C:\Users\runneradmin, with mixed \ + /
        // separators from russh-config's expansion).
        let id = cfg
            .identity_file
            .as_ref()
            .expect("identity_file must be resolved");
        let id_str = id.to_string_lossy();
        assert!(
            id_str.ends_with(".ssh/test_key") || id_str.ends_with(".ssh\\test_key"),
            "expected path to end with .ssh/test_key, got: {}",
            id_str
        );
        assert_eq!(cfg.proxy_jump.as_deref(), Some("bastion@hop.internal"));
    }

    #[test]
    fn glob_pattern_matches_subdomain() {
        let cfg = resolve_with(
            &["passhrs", "db.internal"],
            r#"
Host *.internal
  User admin
"#,
            "db.internal",
        );
        assert_eq!(cfg.user.as_deref(), Some("admin"));
    }

    #[test]
    fn negated_pattern_excludes_match() {
        // `Host *.internal !staging.internal` — staging must
        // NOT pick up the `User ops` directive.
        let cfg_match = resolve_with(
            &["passhrs", "db.internal"],
            r#"
Host *.internal !staging.internal
  User ops
"#,
            "db.internal",
        );
        assert_eq!(cfg_match.user.as_deref(), Some("ops"));

        let cfg_excluded = resolve_with(
            &["passhrs", "staging.internal"],
            r#"
Host *.internal !staging.internal
  User ops
"#,
            "staging.internal",
        );
        assert_eq!(
            cfg_excluded.user, None,
            "negation must exclude staging.internal"
        );
    }

    #[test]
    fn cli_user_wins_over_config_user() {
        // Config says alice; CLI passes `-l carol`. The
        // resolved.host_config has `user = Some("alice")`,
        // but `apply_resolved` must NOT overwrite
        // `cli.user` because the CLI flag wins (OpenSSH
        // precedence).
        let path = write_fixture(
            r#"
Host test-host
  User alice
"#,
        );
        let mut cli = Cli::parse_from(["passhrs", "-l", "carol", "test-host"]);
        cli.config_file = Some(path);
        let resolved = resolve_config(&cli, "test-host").unwrap();
        // Sanity: the resolve itself did pick up alice.
        assert_eq!(resolved.user.as_deref(), Some("alice"));
        apply_resolved(&mut cli, &resolved);
        // But cli.user stays as carol — CLI wins.
        assert_eq!(cli.user.as_deref(), Some("carol"));
    }

    #[test]
    fn cli_identity_file_wins_over_config_identity_file() {
        // Config says /tmp/key_a, CLI says /tmp/key_b. CLI wins.
        let path = write_fixture(
            r#"
Host test-host
  IdentityFile /tmp/key_a
"#,
        );
        let mut cli = Cli::parse_from(["passhrs", "-i", "/tmp/key_b", "test-host"]);
        cli.config_file = Some(path);
        let resolved = resolve_config(&cli, "test-host").unwrap();
        apply_resolved(&mut cli, &resolved);
        assert_eq!(
            cli.identity_file.as_ref().map(|p| p.display().to_string()),
            Some("/tmp/key_b".to_string())
        );
    }

    #[test]
    fn config_fills_unset_cli_field() {
        // CLI didn't pass -l, but config has User alice.
        // apply_resolved must fill cli.user from config.
        let path = write_fixture(
            r#"
Host test-host
  User alice
"#,
        );
        let mut cli = Cli::parse_from(["passhrs", "test-host"]);
        assert!(cli.user.is_none());
        cli.config_file = Some(path);
        let resolved = resolve_config(&cli, "test-host").unwrap();
        apply_resolved(&mut cli, &resolved);
        assert_eq!(cli.user.as_deref(), Some("alice"));
    }

    #[test]
    fn dev_null_short_circuits() {
        // `-F /dev/null` must return an empty ResolvedConfig
        // regardless of any other state.
        let cli = Cli::parse_from(["passhrs", "-F", "/dev/null", "test-host"]);
        let resolved = resolve_config(&cli, "test-host").expect("/dev/null must not error");
        assert!(resolved.hostname.is_none());
        assert!(resolved.user.is_none());
        assert!(resolved.port.is_none());
        assert!(resolved.identity_file.is_none());
        assert!(resolved.proxy_jump.is_none());
    }

    #[test]
    fn missing_explicit_file_is_error() {
        // `-F /path/that/does/not/exist` must error (matches
        // OpenSSH which says "Could not open configuration
        // file").
        let bogus = PathBuf::from("/tmp/passhrs-no-such-config-XYZ123");
        let _ = std::fs::remove_file(&bogus); // ensure absent
        let cli = Cli::parse_from(["passhrs", "-F", bogus.to_str().unwrap(), "test-host"]);
        let res = resolve_config(&cli, "test-host");
        assert!(res.is_err(), "missing -F file must error, got: {:?}", res);
    }

    #[test]
    fn directives_outside_host_block_is_error() {
        // `Hostname foo.com` without a `Host` line must error
        // (russh-config's HostNotFound). This catches malformed
        // configs that silently drop everything.
        let path = write_fixture("Hostname foo.com\n");
        let mut cli = Cli::parse_from(["passhrs", "test-host"]);
        cli.config_file = Some(path);
        let res = resolve_config(&cli, "test-host");
        assert!(res.is_err(), "directives outside Host block must error");
    }

    #[test]
    fn unknown_keywords_are_silently_ignored() {
        // ForwardX11, Compression, etc. are NOT in russh-config's
        // match arms — they should be dropped without error.
        let cfg = resolve_with(
            &["passhrs", "test-host"],
            r#"
Host test-host
  ForwardX11 yes
  Compression yes
  Hostname real-host
  User bob
"#,
            "test-host",
        );
        assert_eq!(cfg.user.as_deref(), Some("bob"));
        assert_eq!(cfg.hostname.as_deref(), Some("real-host"));
    }

    #[test]
    fn empty_config_file_is_default_resolved_config() {
        // Whitespace-only file: no Host blocks. The resolver
        // must return empty ResolvedConfig without error
        // (matches OpenSSH, which prints a warning and
        // continues).
        let path = write_fixture("\n\n   \n# only comments\n\n");
        let mut cli = Cli::parse_from(["passhrs", "any-host"]);
        cli.config_file = Some(path);
        let resolved = resolve_config(&cli, "any-host").expect("empty must not error");
        assert!(resolved.hostname.is_none());
        assert!(resolved.user.is_none());
        assert!(resolved.port.is_none());
    }
}
