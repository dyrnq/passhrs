# Crypto Backend Decision

## Overview

passhrs uses [russh](https://github.com/warp-tech/russh) for SSH protocol,
which supports two crypto backends:

| Backend | Feature flag | Implementation | Assembler required? |
|---------|-------------|----------------|---------------------|
| ring    | `ring`      | C + assembly   | Yes (NASM / ml64 on Windows MSVC) |
| aws-lc-rs | `aws-lc-rs` | C + assembly (AWS-LC) | Yes (NASM on Windows) |

## Current status (as of v1.0.0)

**Backend: `ring`** (switched from `aws-lc-rs` then back)

`aws-lc-rs` was evaluated but **requires NASM on Windows** as well
(its `aws-lc-sys` crate needs NASM for assembly files), so it offers
no advantage over `ring` for this project's build matrix.

| Backend | Linux | macOS | Windows MSVC | Windows GNU |
|---------|-------|-------|-------------|-------------|
| ring    | ✅    | ✅    | ✅ (needs NASM) | ✅ |
| aws-lc-rs | ✅ | ✅ | ✅ (needs NASM) | ✅ (needs NASM) |

## Windows: NASM requirement

- `ring` on `x86_64-pc-windows-msvc` requires `ml64.exe` or NASM
- CI uses `ilammy/setup-nasm@v1` for the MSVC target
- GNU target (`x86_64-pc-windows-gnu`) uses GCC assembler, no NASM needed
- Linux and macOS: no extra tooling required
