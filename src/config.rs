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

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::cli::Cli;

/// Hard cap on `Include` nesting depth. Catches pathological
/// recursive configs (A includes B includes A) before the
/// process stack blows up. OpenSSH has no explicit cap but
/// recursion is implicit; 16 is generous enough for any sane
/// modular config (one Include per layer × 16 layers).
const MAX_INCLUDE_DEPTH: usize = 16;

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
    /// All `IdentityFile <path>` entries from the matching
    /// block, in the order they appear. `russh-config`
    /// exposes a `Vec<PathBuf>` (multiple directives
    /// accumulate); passhrs surfaces the full chain so the
    /// auth loop can try each key until one authenticates
    /// (Issue #71 — matches OpenSSH semantics).
    pub identity_file: Vec<PathBuf>,
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
            // Preserve every IdentityFile in order — the
            // auth loop tries each in turn until one
            // succeeds (Issue #71). An empty Vec means
            // "no IdentityFile in this Host block".
            identity_file: hc.identity_file.unwrap_or_default(),
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
/// - An `Include` directive is malformed (cycle, missing
///   file, nested inside a Host block)
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
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("-F: failed to load ssh config: {}", path.display()))?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        return load_and_parse(&content, base_dir, destination);
    }

    // No -F: try ~/.ssh/config. Missing file / missing home is
    // SILENT (OpenSSH silently falls through when the user has
    // no config file). Other parse errors propagate.
    let home = match std::env::home_dir() {
        Some(h) => h,
        None => return Ok(ResolvedConfig::default()),
    };
    let ssh_config = home.join(".ssh").join("config");
    if !ssh_config.exists() {
        return Ok(ResolvedConfig::default());
    }
    let content = match std::fs::read_to_string(&ssh_config) {
        Ok(c) => c,
        Err(_) => return Ok(ResolvedConfig::default()),
    };
    // Base dir for top-level ~/.ssh/config is ~/.ssh, so
    // `Include ~/.ssh/config.d/*` expands correctly relative
    // to the file's own directory.
    let base_dir = ssh_config.parent().unwrap_or_else(|| Path::new("."));
    load_and_parse(&content, base_dir, destination)
}

/// Read `content`, run the `Include` pre-processor, then hand
/// the result to russh_config::parse. Encapsulates the
/// `Include` + base_dir + cycle-tracking state so callers
/// don't have to thread it.
fn load_and_parse(content: &str, base_dir: &Path, host: &str) -> Result<ResolvedConfig> {
    let mut seen = HashSet::new();
    let merged = preprocess_includes(content, base_dir, host, &mut seen, 0)?;
    let cfg = russh_config::parse(&merged, host)
        .map_err(|e| anyhow!("ssh config: parse error: {}", e))?;
    Ok(cfg.into())
}

/// Pre-process ssh_config content: scan for `Include` lines at
/// top level (not inside a Host/Match block), expand each
/// pattern (`~` → `$HOME`, `%d`/`%u`/`%h` tokens, glob
/// patterns), read and recursively process each matched
/// file, concatenate the result. Returns the merged content
/// ready to hand to `russh_config::parse`.
///
/// `base_dir` is the directory relative to which Include
/// paths resolve (the directory of the file being processed,
/// NOT cwd — matches OpenSSH semantics where includes are
/// resolved against the config file's directory).
///
/// `seen` carries absolute canonical paths across recursion
/// to detect cyclic includes (A includes B includes A). It
/// is an in/out parameter so the cycle guard is global to the
/// whole resolution, not per-file.
///
/// `depth` is the recursion depth guard — we refuse to nest
/// more than `MAX_INCLUDE_DEPTH` levels.
fn preprocess_includes(
    content: &str,
    base_dir: &Path,
    host: &str,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<String> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(anyhow!(
            "Include nesting exceeds {} levels",
            MAX_INCLUDE_DEPTH
        ));
    }

    let mut output = String::with_capacity(content.len());
    // Track whether we've seen a Host/Match keyword. After
    // that, an `Include` directive is an error (OpenSSH
    // doesn't allow Include inside a block).
    let mut seen_block_keyword = false;

    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output.push_str(line);
            output.push('\n');
            continue;
        }

        // Split into key/value at the first whitespace. The
        // key is the directive name; we lowercase to make
        // matching case-insensitive (OpenSSH tolerates
        // `host`, `Host`, `HOST`, etc.).
        let (key, value) = match trimmed.split_once(|c: char| c.is_whitespace()) {
            Some((k, v)) => (k, v.trim()),
            None => {
                // Bare keyword with no whitespace. Treat as
                // malformed for `Include` (which requires a
                // pattern); pass through for everything else
                // and let russh_config decide what to do with
                // a directive that has no value.
                if trimmed.eq_ignore_ascii_case("include") {
                    return Err(anyhow!("Include directive missing pattern: {}", line));
                }
                output.push_str(line);
                output.push('\n');
                continue;
            }
        };
        let lower_key = key.to_ascii_lowercase();

        match lower_key.as_str() {
            "host" | "match" => {
                seen_block_keyword = true;
                output.push_str(line);
                output.push('\n');
            }
            "include" => {
                if seen_block_keyword {
                    return Err(anyhow!(
                        "Include directive not allowed after Host/Match block: {}",
                        line
                    ));
                }
                if value.is_empty() {
                    return Err(anyhow!("Include directive missing pattern: {}", line));
                }
                // Expand percent-token (suffix) and tilde
                // (prefix). Pattern is then resolved against
                // base_dir if relative.
                let pattern = expand_include_tokens(value, host);
                let pattern_path = if let Some(stripped) = pattern.strip_prefix('~') {
                    // ~/$rest → $HOME/$rest
                    let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
                    let rest = stripped.trim_start_matches('/');
                    if rest.is_empty() {
                        home
                    } else {
                        home.join(rest)
                    }
                } else if Path::new(&pattern).is_absolute() {
                    PathBuf::from(&pattern)
                } else {
                    base_dir.join(&pattern)
                };

                // Glob-expand. If the pattern contains glob
                // meta-chars, enumerate matches; otherwise
                // treat as a literal file path.
                let matched = expand_glob(&pattern_path)?;
                if matched.is_empty() {
                    return Err(anyhow!(
                        "Include: no files matched pattern {}",
                        pattern_path.display()
                    ));
                }

                for m in matched {
                    // Cycle guard: canonicalize so symlinks /
                    // `..` don't defeat the set.
                    let canonical = m.canonicalize().unwrap_or_else(|_| m.clone());
                    if !seen.insert(canonical.clone()) {
                        return Err(anyhow!("Include cycle detected: {}", canonical.display()));
                    }

                    let nested_content = std::fs::read_to_string(&m)
                        .with_context(|| format!("Include: failed to read {}", m.display()))?;
                    // For nested files, base_dir becomes the
                    // included file's directory — relative
                    // Includes inside resolve there.
                    let nested_base = m.parent().unwrap_or(base_dir);
                    let merged =
                        preprocess_includes(&nested_content, nested_base, host, seen, depth + 1)?;
                    output.push_str(&merged);
                }
            }
            _ => {
                output.push_str(line);
                output.push('\n');
            }
        }
    }

    Ok(output)
}

/// Expand OpenSSH ssh_config(5) percent-tokens in an Include
/// pattern:
///
/// - `%d` → user's home directory
/// - `%u` → local username (via `whoami` crate, which
///   russh-config already pulls in)
/// - `%h` → the target host the config is being resolved for
/// - unknown tokens (`%r`, `%l`, `%p`, `%%`) are passed
///   through verbatim — OpenSSH leaves them unexpanded when
///   they're not available, and passhrs doesn't have
///   reliable values for `%r`/`%l`/`%p` at config-parse
///   time.
///
/// The OpenSSH man page lists more (`%k`, `%L`, `%n`, `%C`,
/// `%f`, `%j`) — all unknown to us are passed through.
fn expand_include_tokens(pattern: &str, host: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            // `peek()` returns `Option<&Char>`; `.copied()`
            // gives `Option<char>` so the literal patterns
            // below bind by value instead of by reference.
            match chars.peek().copied() {
                Some('d') => {
                    chars.next();
                    if let Some(home) = std::env::home_dir() {
                        out.push_str(&home.to_string_lossy());
                    }
                }
                Some('u') => {
                    chars.next();
                    // whoami 2.x returns Result<String, Error>; on failure
                    // expand to empty (matching the `%d` branch above and
                    // OpenSSH's "leave token unexpanded" behavior).
                    out.push_str(&whoami::username().unwrap_or_default());
                }
                Some('h') => {
                    chars.next();
                    out.push_str(host);
                }
                Some('%') => {
                    chars.next();
                    out.push('%');
                }
                // Unknown tokens (including %r, %l, %p, etc.)
                // — pass through verbatim. OpenSSH does the
                // same when the value isn't available.
                Some(_) => {
                    out.push('%');
                }
                None => {
                    out.push('%');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Glob-expand a path. If the path contains glob meta-chars
/// (`*`, `?`, `[`), walk the pattern's parent directory and
/// match each entry's filename against the glob. If no
/// meta-chars, treat as a literal single-path.
///
/// OpenSSH ssh_config globs are SHELL-STYLE (not
/// `**`-recursive) — `*` matches one path component, not
/// across `/` boundaries — so a single-level
/// `read_dir` + `is_match` is exactly the right semantics.
/// This also keeps the dep tree small (no need for the
/// `glob` crate alongside `globset`).
///
/// Returns an empty Vec if no matches; callers error on
/// "no files matched pattern" (OpenSSH errors here too —
/// silently skipping an empty glob is surprising).
fn expand_glob(pattern_path: &Path) -> Result<Vec<PathBuf>> {
    let pattern_str = pattern_path.to_string_lossy();
    let has_meta = pattern_str.chars().any(|c| matches!(c, '*' | '?' | '['));

    if !has_meta {
        // Literal file path. Return it as-is — existence is
        // checked when we try to read it (and reported with
        // a clear "failed to read" context).
        return Ok(vec![pattern_path.to_path_buf()]);
    }

    // Single-level glob: the pattern's last component is
    // the glob expression, everything before is the
    // directory we walk. OpenSSH ssh_config does NOT
    // support recursive `**` — the globs are intentionally
    // restricted to a single directory level.
    let parent = pattern_path.parent().unwrap_or(Path::new("."));
    let glob_expr = pattern_path
        .file_name()
        .ok_or_else(|| anyhow!("Include: invalid pattern: {}", pattern_path.display()))?
        .to_string_lossy()
        .into_owned();

    let matcher = globset::Glob::new(&glob_expr)
        .with_context(|| format!("Include: invalid glob: {}", glob_expr))?
        .compile_matcher();

    let mut matches = Vec::new();
    if parent.is_dir() {
        for entry in std::fs::read_dir(parent)
            .with_context(|| format!("Include: failed to read directory {}", parent.display()))?
            .flatten()
        {
            let path = entry.path();
            let name = match path.file_name() {
                Some(n) => n.to_string_lossy(),
                None => continue,
            };
            if matcher.is_match(&*name) {
                matches.push(path);
            }
        }
    }
    matches.sort();
    Ok(matches)
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
    if !resolved.identity_file.is_empty() {
        if cli.identity_file.is_empty() {
            cli.identity_file = resolved.identity_file.clone();
        } else {
            // OpenSSH chain semantics: CLI `-i` flags precede
            // config-file `IdentityFile` entries; both are tried
            // in order until one authenticates (Issue #71).
            cli.identity_file
                .extend(resolved.identity_file.iter().cloned());
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

    /// Create a fresh temp directory and return its path.
    /// Like `write_fixture`, files leak across runs but
    /// they're tiny and well under /tmp pressure. We use the
    /// counter to keep each test's directory distinct even
    /// when tests run in parallel.
    fn fresh_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("passhrs-include-test-{}-{}", std::process::id(), n,));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    /// Write `contents` to `name` inside `dir`, returning the
    /// full path. Companion to `fresh_dir` for building
    /// multi-file fixtures (Include globs).
    fn write_in(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
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
            .first()
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
            cli.identity_file.first().map(|p| p.display().to_string()),
            Some("/tmp/key_b".to_string())
        );
    }

    #[test]
    fn identity_file_chain_cli_then_config_in_order() {
        // OpenSSH chain semantics: `passhrs -i A -i B -F <conf>`
        // with `IdentityFile C` in <conf> must produce
        // [A, B, C] in that order, with CLI flags preceding
        // config entries. Issue #71.
        let path = write_fixture(
            r#"
Host chain-host
  IdentityFile /tmp/key_c
  IdentityFile /tmp/key_d
"#,
        );
        let mut cli = Cli::parse_from([
            "passhrs",
            "-i",
            "/tmp/key_a",
            "-i",
            "/tmp/key_b",
            "chain-host",
        ]);
        cli.config_file = Some(path);
        let resolved = resolve_config(&cli, "chain-host").unwrap();
        apply_resolved(&mut cli, &resolved);
        assert_eq!(
            cli.identity_file
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            vec![
                "/tmp/key_a".to_string(),
                "/tmp/key_b".to_string(),
                "/tmp/key_c".to_string(),
                "/tmp/key_d".to_string(),
            ]
        );
    }

    #[test]
    fn identity_file_chain_config_alone_preserves_order() {
        // With no CLI `-i`, the config-file chain alone must be
        // preserved in declaration order. Issue #71.
        let path = write_fixture(
            r#"
Host chain-host
  IdentityFile /tmp/key_first
  IdentityFile /tmp/key_second
  IdentityFile /tmp/key_third
"#,
        );
        let mut cli = Cli::parse_from(["passhrs", "chain-host"]);
        cli.config_file = Some(path);
        let resolved = resolve_config(&cli, "chain-host").unwrap();
        apply_resolved(&mut cli, &resolved);
        assert_eq!(
            cli.identity_file
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            vec![
                "/tmp/key_first".to_string(),
                "/tmp/key_second".to_string(),
                "/tmp/key_third".to_string(),
            ]
        );
    }

    #[test]
    fn identity_file_chain_empty_when_neither_cli_nor_config() {
        // No -i and no IdentityFile => empty Vec. Issue #71.
        let cli = Cli::parse_from(["passhrs", "bare-host"]);
        let resolved = resolve_config(&cli, "bare-host").unwrap();
        let mut cli = cli;
        apply_resolved(&mut cli, &resolved);
        assert!(cli.identity_file.is_empty());
        assert!(resolved.identity_file.is_empty());
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
        assert!(resolved.identity_file.is_empty());
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

    // ─────────────────────────────────────────────────────────
    // `Include` directive — Issue #69
    //
    // These exercise `preprocess_includes` indirectly via
    // `resolve_config` (which calls it before handing the
    // merged content to russh-config). Each test pins one
    // OpenSSH-compatible Include behavior so we can detect
    // regressions on upgrades.
    // ─────────────────────────────────────────────────────────

    /// A top-level `Include <file>` line is replaced with
    /// the contents of that file. We verify by putting the
    /// actual `Host` block in the *included* file and
    /// proving the runtime still resolves it.
    #[test]
    fn include_at_top_level_pulls_in_host_block() {
        let dir = fresh_dir();
        let included = write_in(
            &dir,
            "extra.conf",
            "Host pulled-in\n  HostName pulled.example.com\n  User frominclude\n",
        );
        let main_path = write_fixture(&format!("Include {}\n", included.to_string_lossy()));
        let mut cli = Cli::parse_from(["passhrs", "pulled-in"]);
        cli.config_file = Some(main_path);
        let resolved = resolve_config(&cli, "pulled-in").expect("include must succeed");
        assert_eq!(resolved.hostname.as_deref(), Some("pulled.example.com"));
        assert_eq!(resolved.user.as_deref(), Some("frominclude"));
    }

    /// Glob patterns in Include expand against the *parent
    /// directory of the file containing the Include*. We
    /// write three files into a fresh dir, glob `inc-*.conf`,
    /// and verify each matched file's Host block applies.
    /// The main config is named `main` (not `*.conf`) so it
    /// doesn't match its own glob — which would create a
    /// cycle. Real-world equivalent: ~/.ssh/config uses
    /// `Include config.d/*` so the main file is never
    /// included back into itself.
    #[test]
    fn include_expands_glob_against_containing_dir() {
        let dir = fresh_dir();
        write_in(&dir, "inc-a.conf", "Host alpha\n  User alpha-user\n");
        write_in(&dir, "inc-b.conf", "Host beta\n  User beta-user\n");
        write_in(&dir, "ignored.txt", "Host ignored\n  User ignored\n");
        let main = write_in(&dir, "main", "Include inc-*.conf\n");
        let mut cli = Cli::parse_from(["passhrs", "alpha"]);
        cli.config_file = Some(main);
        let r1 = resolve_config(&cli, "alpha").unwrap();
        assert_eq!(r1.user.as_deref(), Some("alpha-user"));

        cli.user = None; // reset
        let r2 = resolve_config(&cli, "beta").unwrap();
        assert_eq!(r2.user.as_deref(), Some("beta-user"));

        // The .txt file must NOT have been matched — Host
        // `ignored` would otherwise appear.
        let r3 = resolve_config(&cli, "ignored").unwrap();
        assert_eq!(r3.user, None);
    }

    /// A → B → A cycle must be detected and reported, not
    /// silently re-read. The error message must include
    /// either side of the cycle so the user can find it.
    #[test]
    fn include_cycle_is_detected() {
        let dir = fresh_dir();
        let a = write_in(
            &dir,
            "a.conf",
            &format!("Include {}\n", dir.join("b.conf").to_string_lossy()),
        );
        let _b = write_in(
            &dir,
            "b.conf",
            &format!("Include {}\n", a.to_string_lossy()),
        );
        let mut cli = Cli::parse_from(["passhrs", "any"]);
        cli.config_file = Some(a);
        let err = resolve_config(&cli, "any").expect_err("cycle must error");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("cycle") || msg.contains("Cycle"),
            "expected cycle error, got: {:#}",
            err
        );
    }

    /// `Include` inside a `Host` block is an error
    /// (OpenSSH rejects this too). The error must mention
    /// "Host" or "block" so the user knows where to look.
    #[test]
    fn include_inside_host_block_is_error() {
        let dir = fresh_dir();
        let _extra = write_in(&dir, "extra.conf", "Host x\n  User x\n");
        let main = write_in(&dir, "main.conf", "Host foo\n  Include extra.conf\n");
        let mut cli = Cli::parse_from(["passhrs", "foo"]);
        cli.config_file = Some(main);
        let err = resolve_config(&cli, "foo").expect_err("Include in Host must error");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("Host") || msg.contains("block"),
            "expected block-boundary error, got: {:#}",
            err
        );
    }

    /// An Include pattern that matches no files is an error
    /// (OpenSSH errors here too — silently skipping an
    /// empty glob hides typos like `~.ssh/config.d/*`).
    #[test]
    fn include_with_no_matches_is_error() {
        let dir = fresh_dir();
        let main = write_in(&dir, "main.conf", "Include *.does-not-exist\n");
        let mut cli = Cli::parse_from(["passhrs", "any"]);
        cli.config_file = Some(main);
        let err = resolve_config(&cli, "any").expect_err("empty match must error");
        assert!(
            format!("{:#}", err).contains("no files matched"),
            "expected 'no files matched' error, got: {:#}",
            err
        );
    }

    /// Include of a non-existent file (literal path, no
    /// glob) is a hard error.
    #[test]
    fn include_missing_file_is_error() {
        let main = write_fixture("Include /tmp/passhrs-definitely-not-a-real-config-XYZ.conf\n");
        let mut cli = Cli::parse_from(["passhrs", "any"]);
        cli.config_file = Some(main);
        let err = resolve_config(&cli, "any").expect_err("missing Include must error");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("Include") || msg.contains("failed to read"),
            "expected Include-read error, got: {}",
            msg
        );
    }

    /// `Include` with no pattern at all is malformed —
    /// error out instead of globbing the current directory.
    #[test]
    fn include_with_no_pattern_is_error() {
        let main = write_fixture("Include\n");
        let mut cli = Cli::parse_from(["passhrs", "any"]);
        cli.config_file = Some(main);
        let err = resolve_config(&cli, "any").expect_err("empty Include must error");
        assert!(
            format!("{:#}", err).contains("missing pattern"),
            "expected 'missing pattern' error, got: {:#}",
            err
        );
    }

    /// `%h` in an Include pattern expands to the target
    /// host the config is being resolved for.
    #[test]
    fn include_percent_h_expands_to_target_host() {
        let dir = fresh_dir();
        write_in(
            &dir,
            "myspecialhost.conf",
            "Host myspecialhost\n  User h-expansion\n",
        );
        let main = write_in(&dir, "main.conf", "Include %h.conf\n");
        let mut cli = Cli::parse_from(["passhrs", "myspecialhost"]);
        cli.config_file = Some(main);
        let resolved = resolve_config(&cli, "myspecialhost").unwrap();
        assert_eq!(resolved.user.as_deref(), Some("h-expansion"));
    }

    /// Tilde in Include patterns expands to $HOME (matches
    /// OpenSSH). We write the included file into the real
    /// user's $HOME under a unique name; on failure the
    /// file leaks harmlessly.
    #[test]
    fn include_tilde_expands_to_home() {
        let home = match std::env::home_dir() {
            Some(h) => h,
            None => return, // skip on runners without HOME
        };
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let name = format!("passhrs-tilde-include-{}-{}.conf", std::process::id(), n);
        let included = home.join(&name);
        std::fs::write(&included, "Host tilde-host\n  User tilde-user\n")
            .expect("write home fixture");
        let main = write_fixture(&format!("Include ~/{}\n", name));
        let mut cli = Cli::parse_from(["passhrs", "tilde-host"]);
        cli.config_file = Some(main);
        let resolved = resolve_config(&cli, "tilde-host").expect("tilde include must succeed");
        assert_eq!(resolved.user.as_deref(), Some("tilde-user"));
        // Cleanup is best-effort; fixture leaks if cleanup fails.
        let _ = std::fs::remove_file(&included);
    }

    /// Nested Includes work: main → a.conf → b.conf.
    /// Each layer's Host blocks must apply. Per OpenSSH
    /// rules, Include must be at top level in EACH file
    /// (not inside a Host block) — so a.conf's Include goes
    /// before any Host line.
    #[test]
    fn include_nested_layers_all_apply() {
        let dir = fresh_dir();
        write_in(&dir, "b.conf", "Host fromb\n  User from-b\n");
        let a = write_in(
            &dir,
            "a.conf",
            // Include MUST be before the first Host line —
            // OpenSSH rejects Include inside a block.
            "Include b.conf\nHost froma\n  User from-a\n",
        );
        let main = write_in(
            &dir,
            "main.conf",
            &format!("Include {}\n", a.to_string_lossy()),
        );
        let mut cli = Cli::parse_from(["passhrs", "froma"]);
        cli.config_file = Some(main.clone());
        let ra = resolve_config(&cli, "froma").unwrap();
        assert_eq!(ra.user.as_deref(), Some("from-a"));

        cli.user = None;
        let rb = resolve_config(&cli, "fromb").unwrap();
        assert_eq!(rb.user.as_deref(), Some("from-b"));
    }

    /// Unknown percent-tokens (e.g. `%r`, `%p`) are passed
    /// through verbatim — OpenSSH does the same when the
    /// value isn't available at config-parse time.
    #[test]
    fn include_unknown_percent_tokens_pass_through() {
        // We can't actually have a file named with `%r` in
        // its name on most filesystems — `%` is a valid char
        // on Unix but the test only verifies the parser
        // doesn't drop or error on the unknown token. We
        // expect the include to fail with a missing-file
        // error (since no real file matches `%r.conf`).
        let dir = fresh_dir();
        let main = write_in(&dir, "main.conf", "Include %r.conf\n");
        let mut cli = Cli::parse_from(["passhrs", "any"]);
        cli.config_file = Some(main);
        let err = resolve_config(&cli, "any").expect_err("unknown token still errors");
        // The error should be about a missing/mismatched
        // file, NOT about a malformed pattern.
        let msg = format!("{:#}", err);
        assert!(
            !msg.contains("invalid glob"),
            "unknown percent token should pass through, got: {}",
            msg
        );
    }
}
