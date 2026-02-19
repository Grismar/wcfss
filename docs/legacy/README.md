# Legacy Windows Compatibility File System Semantics Helper

## Overlap
 
- Case‑insensitive match (though wcfss is Unicode‑aware; helper is ASCII only).
- Directory enumeration and selection of a unique match.
- Returns a resolved path when there is exactly one match.

## What wcfss adds beyond the helper
- Full path parsing and normalization (components, separators, . and .. handling, root/base constraints).
- Windows‑compatible semantics on Linux, including Unicode simple‑uppercase keying (not ASCII only).
- Collision detection rules across whole paths, not just one directory level.
- Symlink handling and strict .. behavior (symlink boundary checks).
- Root mapping for Windows drive/UNC paths on Linux.
- Explicit error codes, diagnostics, metrics, and plan/execute model.
- Cache and invalidation (DirIndex with generations/stamps) for performance - and correctness.
- Cross‑language bindings (Rust/Python/Fortran) with stable C ABI.
- Intent‑aware operations (read/write/create/mkdir/rename/unlink), not just lookup.

## Serious problems the helper misses

- Only searches one directory; ignores multi‑component paths entirely.
- ASCII case‑folding only; breaks non‑ASCII Windows‑compat semantics.
- No collision semantics for Unicode casefold; can return wrong file on mixed‑case or locale edge cases.
- No handling of symlinks or .. traversal rules; can violate Windows expectations.
- No base_dir confinement or escapes‑root protection.
- No support for absolute path forms (drive/UNC) or root mapping.
- Treats only regular files; doesn’t support directories or intent‑specific behavior.
- Ignores invalid UTF‑8 and encoding policy requirements.
- Silent error model (returns -1) without structured diagnostics.

## What the helper possibly solves that wcfss does not

- Simplicity and trivial integration in a small C/C++ codebase without pulling a Rust library.
- Very small footprint and minimal dependencies.
- For a narrow case (single directory, ASCII names, stem/ext logic), it is easy to understand and debug.
- Counts number of collisions instead of just generating an error upon collision.
