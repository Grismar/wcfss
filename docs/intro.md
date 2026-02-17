# wcfss Rust Source Introduction

This document is a developer-oriented introduction to the Rust implementation of wcfss. It focuses on how the resolver is structured, where the platform-specific behavior lives, and how to navigate the core algorithm and FFI surface. The behavioral contract is defined in `docs/spec.md`.

## Overview

wcfss provides Windows-compatible filesystem semantics on both Windows and Linux:
- On Windows it uses native Win32 APIs while enforcing spec-specific rules like collision detection and strict `..` handling.
- On Linux it emulates Windows case-insensitive behavior with a DirIndex cache, Unicode simple-uppercase keys, and explicit validation logic.

The Rust core is designed around a single trait (`Resolver`) implemented by two platform backends. The public API is a C ABI used by Rust itself and intended for future bindings.

## Code Map

Start here:
- `src/lib.rs` selects the platform resolver and re-exports the C ABI and common types.
- `src/common/types.rs` defines all public enums and structs used in the FFI (status codes, config, plan tokens, diagnostics, metrics).
- `src/resolver.rs` defines the `Resolver` trait that both platforms implement.
- `src/ffi.rs` is the C ABI surface that forwards to the platform resolver and performs pointer/size validation.

Platform-specific implementations:
- `src/linux_emulation/resolver.rs` is the main Linux implementation. It contains the DirIndex cache, collision handling, strict `..` logic, plan token handling, and execution for all intents.
- `src/linux_emulation/parser.rs` parses and normalizes input paths for Linux, including Windows-style drive/UNC parsing and Unicode case key computation.
- `src/linux_emulation/dirindex.rs` defines the DirIndex cache structures and collision tracking.
- `src/windows_native/resolver.rs` is the Windows implementation. It performs per-directory enumeration to detect collisions, enforces strict `..` semantics, and uses Win32 operations for create/open/rename/unlink.
- `src/windows_native/win32.rs` contains the thin Win32 wrappers and error mapping.

Build-time generation:
- `build.rs` generates the Unicode simple-uppercase table from `data/unicode/15.1/UnicodeData.txt` and writes it to `OUT_DIR`. This table is included by `src/linux_emulation/parser.rs`.

Tests:
- `tests/linux/` and `tests/windows/` cover platform-specific behavior. `tests/linux.rs` and `tests/windows.rs` are the platform harnesses.

## Core Concepts

Plan/execute model:
- `resolver_plan` performs a read-only resolution and returns a `ResolverPlan` containing the resolved parent/leaf and a `ResolverPlanToken`.
- `resolver_execute_from_plan` uses that token to perform the mutation or open, rejecting stale plans (generational and stamp checks on Linux).

Resolver status codes:
- Status values in `ResolverStatus` are defined in `src/common/types.rs` and are the single source of truth for error mapping.

Encoding policy:
- Inputs are validated as UTF-8. On Linux, invalid UTF-8 directory entries are skipped by default or may fail when strict encoding is enabled.

Root mapping on Linux:
- Windows-style drive and UNC roots are supported on Linux when `RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS` is set.
- Mappings are provided via `resolver_set_root_mapping`, and plan tokens include a root mapping generation to invalidate stale plans.

Diagnostics and metrics:
- Diagnostics are optional output buffers passed by callers and populated by the resolver for warnings/errors.
- Metrics are retrieved via `resolver_get_metrics` and track cache hits/misses, collisions, encoding errors, and plan staleness.

## Resolution Flow (Linux Emulation)

The core flow in `src/linux_emulation/resolver.rs` is:
1. Normalize the input path (`\` -> `/`) and parse root/components via `parser`.
2. Apply root mapping (if enabled) or base_dir for relative paths.
3. Validate `..` handling strictly, with symlink boundary checks.
4. Resolve each component using the exact-first + case-insensitive DirIndex lookup.
5. For plan creation, record plan token data (dir generations and optional stamps).
6. For execute calls, perform the OS operation and invalidate cache entries for affected directories.

DirIndex behavior:
- The DirIndex caches a case-folded mapping of directory entries for fast case-insensitive lookups.
- Validity is enforced with TTL + metadata stamps, and invalidation happens on mutations.

## Resolution Flow (Windows Native)

The Windows resolver in `src/windows_native/resolver.rs` performs:
1. Base dir validation and parsing of the input path with Windows semantics.
2. Per-component directory enumeration to detect case collisions.
3. Strict `..` handling with symlink boundary checks.
4. The actual operation using Win32 APIs (open/create/rename/unlink/mkdirs).

Windows uses enumeration for collision detection to match the spec, rather than relying on filesystem case-insensitive lookup alone.

## FFI Surface

The public ABI in `src/ffi.rs` mirrors the `Resolver` trait:
- `resolver_create` and `resolver_destroy`
- `resolver_set_root_mapping`
- `resolver_plan`
- `resolver_execute_mkdirs`, `resolver_execute_rename`, `resolver_execute_unlink`
- `resolver_execute_open_return_path` and `resolver_execute_open_return_fd`
- `resolver_execute_from_plan`
- `resolver_get_metrics`

When the resolver allocates buffers for plan tokens or resolved paths, the caller must free them via the provided `resolver_free_*` helpers (see `docs/spec.md` for exact rules).

## Reading Suggestions

If you are new to the codebase, a good reading order is:
1. `docs/spec.md` for behavior and invariants.
2. `src/common/types.rs` for the public API surface.
3. `src/ffi.rs` for ABI behavior and validation rules.
4. `src/linux_emulation/resolver.rs` to see the full algorithm.
5. `src/windows_native/resolver.rs` and `src/windows_native/win32.rs` for the native Windows path.

## Future Bindings

Bindings will be thin adapters around the C ABI. When bindings are added, this doc should gain a short section describing how those bindings map to `ResolverStringView`, `ResolverPlan`, and the free functions (`resolver_free_string`, `resolver_free_buffer`).
