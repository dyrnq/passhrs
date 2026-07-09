//! Implementation of the OpenSSH-compatible `-Q <what>` query
//! flag. The flag has no SSH-traffic equivalent — it just
//! enumerates the algorithms passhrs is willing to negotiate for
//! the requested protocol feature and prints one name per line
//! to stdout, then exits 0.
//!
//! Sources of truth (russh 0.62.1):
//!
//! - `russh::cipher::ALL_CIPHERS: &[&Name]`
//! - `russh::mac::ALL_MAC_ALGORITHMS: &[&Name]`
//! - `russh::kex::ALL_KEX_ALGORITHMS: &[&Name]`
//! - `russh::compression::ALL_COMPRESSION_ALGORITHMS: &[&Name]`
//! - `russh::keys::key::ALL_KEY_TYPES: &[ssh_key::Algorithm]`
//!
//! All four `Name` types wrap `pub struct Name(&'static str)` and
//! implement `AsRef<str>` (returning the inner slice), which lets
//! the printer loop be generic over a single bound. `ssh_key::Algorithm`
//! exposes `as_str(&self) -> &str`.
//!
//! Multiple `-Q` flags are allowed; each prints its own list. The
//! function returns the process exit code: `0` on success, `1` if
//! any query is unknown.

/// Dispatch one or more `-Q <what>` values. Returns the process
/// exit code (0 on success; 1 if any `what` is unknown).
pub(crate) fn dispatch(queries: &[String]) -> i32 {
    let mut rc = 0;
    for raw in queries {
        let what = raw.to_ascii_lowercase();
        match what.as_str() {
            "cipher" => print_names(russh::cipher::ALL_CIPHERS),
            "mac" => print_names(russh::mac::ALL_MAC_ALGORITHMS),
            "kex" => print_names(russh::kex::ALL_KEX_ALGORITHMS),
            "compression" => print_names(russh::compression::ALL_COMPRESSION_ALGORITHMS),
            "key" => print_key_algorithms(),
            "help" => print_query_help(),
            // Sub-flags OpenSSH 9.x accepts that don't apply to a
            // client-only tool — kept as separate cases so the error
            // message can be specific. collapse into a single branch
            // since the answer is the same for all of them.
            "protocol-version" | "key-cert" | "key-plain" | "key-sig" | "sig" => {
                eprintln!(
                    "Unsupported query: {} (not applicable to a client). Try `-Q help`",
                    raw
                );
                rc = 1;
            }
            other => {
                eprintln!(
                    "Unsupported query: {}. Valid queries: cipher, mac, kex, compression, key, help",
                    other
                );
                rc = 1;
            }
        }
    }
    rc
}

/// Print one algorithm name per line for any russh slice where
/// the element type implements `AsRef<str>` (all four Name
/// families do, with the same `&self.0` semantics).
fn print_names<T: AsRef<str>>(slice: &[&T]) {
    for n in slice {
        println!("{}", n.as_ref());
    }
}

/// `ssh_key::Algorithm` does not implement `AsRef<str>` (its
/// `as_str` is a method on the type rather than a trait bound),
/// so it gets its own printer that calls the concrete method.
fn print_key_algorithms() {
    for alg in russh::keys::key::ALL_KEY_TYPES {
        println!("{}", alg.as_str());
    }
}

fn print_query_help() {
    println!("Supported queries:");
    println!("  cipher                Supported symmetric ciphers");
    println!("  mac                   Supported MAC algorithms");
    println!("  kex                   Supported key-exchange algorithms");
    println!("  compression           Supported compression algorithms");
    println!("  key                   Supported public-key types");
    println!("  help                  Print this help text");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_help_exits_zero() {
        let rc = dispatch(&["help".to_string()]);
        assert_eq!(rc, 0, "help query must exit 0");
    }

    #[test]
    fn dispatch_unknown_returns_one() {
        let rc = dispatch(&["not-a-real-query".to_string()]);
        assert_eq!(rc, 1, "unknown query must exit 1");
    }

    #[test]
    fn dispatch_mixed_keeps_zero_when_all_known() {
        let rc = dispatch(&["cipher".to_string(), "mac".to_string()]);
        assert_eq!(rc, 0);
    }

    #[test]
    fn dispatch_mixed_returns_one_when_any_unknown() {
        let rc = dispatch(&["cipher".to_string(), "bogus".to_string()]);
        assert_eq!(rc, 1);
    }

    #[test]
    fn all_cipher_names_are_non_empty() {
        // Sanity: every russh::cipher::ALL_CIPHERS entry must
        // yield a non-empty printable name. Catches a regression
        // where AsRef<str> got swapped for a different impl
        // that accidentally returned "" for some entry.
        for n in russh::cipher::ALL_CIPHERS {
            let s: &str = n.as_ref();
            assert!(!s.is_empty(), "cipher name {:?} empty", n);
        }
    }
}
