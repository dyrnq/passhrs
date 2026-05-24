# Crypto Backend Decision

## Overview

passhrs uses [russh](https://github.com/warp-tech/russh) for SSH protocol,
which supports two crypto backends:

| Backend | Feature flag | Implementation | Assembler required? |
|---------|-------------|----------------|---------------------|
| ring    | `ring`      | C + assembly   | Yes (NASM / ml64 on Windows) |
| aws-lc-rs | `aws-lc-rs` | Rust (pure) + C (via cargo) | No |

## Why aws-lc-rs

| Aspect | ring | aws-lc-rs |
|--------|------|-----------|
| Crypto primitives | BoringSSL fork | AWS LibCrypto (AWS-LC) |
| Windows x86_64 build | Requires `ml64.exe` or NASM | No extra tooling needed |
| macOS build | No assembler issue | No assembler issue |
| Linux build | No assembler issue | No assembler issue |
| crate downloads | ~15M | ~124M |
| Maintainer | Independent | AWS |

### Windows-specific: NASM / ml64.exe

When building with `ring` on `x86_64-pc-windows-msvc`:

- `ring` has hand-tuned assembly for AES, SHA, etc.
- MSVC toolchain provides `ml64.exe` (Microsoft Macro Assembler)
- If `ml64.exe` is not found, `ring` build fails
- CI must install NASM (`ilammy/setup-nasm`) to provide the assembler

With `aws-lc-rs`:

- Uses `aws-lc-sys` which bundles pre-built or builds from source via cmake
- No dependency on `ml64.exe` or NASM
- Builds cleanly on all three platforms without extra steps

## Current status (as of v1.0.0)

- **Backend**: `aws-lc-rs` (default, switched from `ring`)
- **CI**: NASM setup step removed, all platforms build natively
- **Release**: All 8 targets build without special assembler tooling

## Switching back

To switch back to `ring`, edit `Cargo.toml`:

```diff
- russh = { ..., features = ["rsa", "aws-lc-rs", "flate2"] }
+ russh = { ..., features = ["rsa", "ring", "flate2"] }
```

And re-add NASM setup in CI for `windows-msvc` target.
