# Engineering Spec

## 0. Purpose
Provide a deterministic, Windows-compatible interpretation of file paths and filename matching so that legacy configuration/data files produce identical results on Windows and Linux **where possible**, without requiring special filesystems or system-wide behavior changes.

Implement once (C++ or Rust) and reuse from Fortran, Python, and Rust via a stable C ABI.

## 1. Terminology
- **Path**: string containing zero or more components separated by `\` or `/`.
- **Component**: one filename element between separators (e.g. `Project_X`).
- **Key function `K(s)`**: locale-invariant, Unicode-aware *simple-uppercase* mapping applied per code point (1:1), **no Unicode normalization**.
- **Collision**: directory contains two distinct entries `a != b` such that `K(a) == K(b)`.
- **Resolver**: component that parses, normalizes, resolves, plans, and executes filesystem operations using rules below.
- **Intent**: operation type (plan/resolve/stat/open/write/create/mkdir/rename/unlink, etc.).
- **Plan**: side-effect-free description of what would happen for an intent.
- **DirIndex**: cached case-insensitive index of a directory’s children keyed by `K(name)`.
- **Generation**: monotonic integer used to invalidate caches/plans when configuration changes.
- **Stamp**: directory state marker used to revalidate DirIndex entries.
- **DirID**: OS directory identity used for caching (e.g., `(st_dev, st_ino)` plus a diagnostic path string).
- **DirGeneration**: monotonic integer associated with a directory identity, incremented for resolver-executed mutations that can change that directory’s contents.

## 2. Scope and non-goals
### In scope
- Separator normalization (`\` and `/` accepted in compat mode).
- Case-insensitive resolution compatible with Windows expectations.
- Deterministic handling of ambiguities/collisions.
- Efficient operation using directory caching and correct invalidation.
- Reusable API for Fortran/Rust/Python.
- Optional support for Windows absolute forms (drive/UNC) via application configuration.

### Non-goals
- Unicode normalization (NFC/NFD/NFK*): **never performed**.
- Exact bit-for-bit replication of NTFS `$UpCase` behavior across all Unicode corner cases.
- Global system behavior changes or filesystem requirements.

## 3. Inputs, limits, and internal representation
### 3.1 Accepted inputs
- Paths from configuration files, data files (CSV/GIS/netCDF), command line, and API calls.
- Both `\` and `/` treated as separators on all platforms in compat mode.
- Repeated separators permitted and treated as a single separator.

### 3.2 Size limits (defensive)
The resolver MUST enforce configurable limits:
- `MAX_INPUT_PATH_BYTES` (default: 32 KiB)
- `MAX_COMPONENTS` (default: 4096)
- `MAX_COMPONENT_BYTES` (default: 255 UTF-8 bytes after validation)

Inputs exceeding limits MUST fail with `PATH_TOO_LONG` and include diagnostics.

### 3.3 Internal representation
Parsed path includes:
- `root_id` (none / drive / UNC; see §4),
- normalized component list,
- original input retained for diagnostics (truncated to `MAX_INPUT_PATH_BYTES`).

## 4. Roots, absolute paths, and mapping
### 4.1 Relative paths
- `.` components are reduced lexically (no filesystem access required).
- `..` handling is defined in §7.4.
- Resolution is relative to a caller-supplied **base_dir** (required).

### 4.2 Windows absolute forms on Linux (optional feature)
Legacy configs may include:
- Drive-letter: `X:\a\b` or `X:/a/b`
- UNC: `\\server\share\path` or `//server/share/path`

Policy:
- On Linux, drive/UNC support is **disabled by default**.
- Enable drive/UNC support via resolver configuration flag `RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS`.
- If enabled, the resolver parses to an internal `root_id`:
  - `drive:X`
  - `unc:server/share`
- The resolver translates `root_id` to an OS path using an application-supplied **root mapping table**.

Root mapping keys:
- Drive roots accept `X:`, `X:\`, or `X:/` (drive letter case-insensitive).
- UNC roots accept `\\server\share` or `//server/share`.
- Matching MUST be case-insensitive using `K(s)` on the drive letter and on UNC server/share names.

Root mapping values:
- MUST be absolute OS paths (Linux: start with `/`) and valid UTF-8.

If disabled or no mapping exists:
- Intents fail with `UNSUPPORTED_ABSOLUTE_PATH` (disabled) or `UNMAPPED_ROOT` (enabled but not mapped).

### 4.3 Root mapping updates
- Root mapping table MAY be updated at runtime via API.
- Any update MUST increment `root_mapping_generation`.
- All prefix memoizations and any Plan objects that depended on root mapping MUST be invalidated when the generation changes.

## 5. Key function `K(s)` (case-insensitive comparison key)
### 5.1 Requirements
- Locale-invariant (no locale-dependent casing).
- Unicode-aware.
- No normalization.
- Prefer 1→1 mapping (no length expansion).

### 5.2 Definition
`K(s)` is constructed by applying **Unicode simple uppercase mapping** (single-code-point mapping) to each Unicode scalar value in `s`, concatenating results. No other transforms.

### 5.3 Version pinning and migration
- The mapping table MUST be pinned to a specific Unicode version (e.g. "Unicode 15.1 simple uppercase").
- Resolver configuration MUST expose:
  - `unicode_version_id` (string)
  - `unicode_version_generation` (monotonic integer)
- Upgrading the Unicode table is a behavior change that can affect collision detection and resolution outcomes. Therefore:
  - The resolver MUST allow selecting a supported `unicode_version_id` at creation time.
  - If the table is changed on a resolver instance, it MUST increment `unicode_version_generation` and invalidate all DirIndex caches and prefix memoizations.
  - Plans MUST carry the `unicode_version_generation` they were produced under; execution MUST reject stale plans (see §12.5).

## 6. Encoding policy on Linux (Policy A — required)
### 6.1 Motivation
Windows path semantics are Unicode-centric. Allowing opaque byte filenames on Linux would:
- make case-insensitive behavior non-deterministic across languages/toolchains,
- complicate caching and collision handling,
- reduce Windows-faithfulness.

### 6.2 Requirements and strictness
Compat mode requires:
- input paths are valid UTF-8.

Directory entry handling:
- Invalid UTF-8 entry names are **not addressable** in compat mode.
- Default behavior is **skip-invalid**:
  - When building DirIndex, invalid UTF-8 entries are ignored (not indexed),
  - A diagnostic warning MUST record that invalid entries were encountered (including safe byte representation),
  - Operations targeting valid UTF-8 names in the same directory MUST still work.
- Optional strictness flag `FAIL_ON_ANY_INVALID_UTF8_ENTRY` (default: false):
  - If enabled and any invalid UTF-8 entry is encountered while indexing `D`, operations in `D` MUST fail with `ENCODING_ERROR`.

## 7. Path parsing and normalization
Given an input path string:

1. Identify prefix/root (drive/UNC/none).
2. Replace all `\` with `/`. Record a warning flag if any `\` was present.
3. Split on `/` to components, preserving order.
4. Lexically drop `.` components.
5. Handle `..` according to §7.4 (may require filesystem access).
6. Handle `..` beyond root:
   - default: error `ESCAPES_ROOT`
   - optional (explicit config): clamp-to-root with warning.
7. Validate limits (§3.2) and UTF-8 (§6).
8. Produce normalized `root_id` + component list (and any metadata required by §7.4).

### 7.1 Empty normalized path
After normalization, if the component list is empty (e.g. input `""`, `"."`, `"./././."`):
- The path resolves to the **base directory (or mapped root)** itself.
- This applies to plan/resolve and execute operations.
- Operations that require a leaf component (e.g. CREATE_NEW for a file) MAY fail with `INVALID_PATH` if the intent is nonsensical on a directory target; otherwise they operate on the directory.

### 7.4 `..` handling (correctness-critical)
`..` MUST NOT be treated as purely lexical cancellation of the immediately preceding component, because the preceding component may resolve to a symlink (which would change traversal semantics) or a non-directory.

The resolver MUST support one of the following policies, selectable by configuration; default MUST be the Strict approach.

#### 7.4.1 Strict approach (default; recommended)
If the input path contains any `..`, the resolver MUST disable purely lexical reduction for those segments and instead validate each cancellation using filesystem checks during resolution:

- Maintain a stack of resolved OS directories as traversal proceeds.
- When processing a normal component `x`, resolve it (using §9 rules) within the current directory, then `lstat()` the resulting entry:
  - If it is a symlink: treat this as a semantic boundary. Any subsequent attempt to apply `..` that would cancel across this boundary MUST fail with `INVALID_PATH` (or a more specific code if introduced).
  - If it is not a directory: it may still be a valid leaf for some intents, but it cannot be a parent of further components; if further traversal is required, fail with `NOT_A_DIRECTORY`.
  - If it is a directory and not a symlink: push it as the new current directory.
- When encountering `..`:
  - If at root: apply §7 step 6 (`ESCAPES_ROOT` or clamp policy).
  - Otherwise, pop exactly one directory level from the resolved directory stack.

This policy ensures `a/..` is only reduced when `a` is confirmed to be a non-symlink directory in the resolved traversal.

#### 7.4.2 Safe lazy approach (optional)
If the input path contains any `..`, disable fast-path string normalization and fall back to OS-level canonicalization or an equivalent component-by-component iterator that checks directory identities:

- Option A (OS canonicalization): build a candidate OS path and apply `realpath`-like canonicalization where available, then re-interpret the resulting path under the resolver’s root and base constraints.
- Option B (resolver iterator): walk components using OS `openat`/`fstatat`-style operations (or equivalents), resolving directories stepwise and applying `..` by moving to the tracked parent directory identity.

If the safe lazy approach is used, the resolver MUST still enforce:
- root/base constraints (`ESCAPES_ROOT` policy),
- encoding policy (§6),
- collision semantics (§11),
- symlink loop protections (§9.3).

## 8. Base directory requirements and semantics
Every operation takes a `base_dir` parameter.

### 8.1 Requirements
- `base_dir` MUST be an absolute OS path.
- `base_dir` MUST exist and refer to a directory; else `BASE_DIR_INVALID`.
- On Linux, `base_dir` MUST be valid UTF-8 in compat mode; else `BASE_DIR_INVALID`.

### 8.2 Platform-specific definition of “absolute OS path”
- **Linux**: absolute if it begins with `/`.
- **Windows**: `base_dir` MUST be one of:
  - Drive-rooted: `X:\...`
  - UNC-rooted: `\\server\share\...`
  - Extended-length variants that include drive or UNC (`\\?\X:\...`, `\\?\UNC\server\share\...`)
  - Paths like `\foo` (current-drive rooted) and `/foo` are NOT permitted as `base_dir` (reject with `BASE_DIR_INVALID`).

### 8.3 base_dir changes across calls
- DirIndex and prefix memoization caches are keyed by **absolute OS directory identity** (§10.4), not by `base_dir`.
- Using different `base_dir` values across calls does NOT require cache invalidation by itself.
- If `base_dir` is deleted/recreated or its permissions change, it is treated like any other external mutation and discovered via stamps/OS errors.

### 8.4 base_dir casing
- `base_dir` is treated as an OS path supplied by the caller. The resolver validates existence via OS `stat`.
- The resolver does not apply compat case-insensitive resolution to `base_dir` itself.
  - If desired, an optional helper API MAY be provided to “canonicalize” a base_dir by resolving its components using compat semantics, but this is not required for v1.

## 9. Resolution algorithm (component-by-component)
Resolution occurs against:
- `base_dir` for relative paths, or
- mapped root directory for drive/UNC when enabled.

For each component `c` in order within parent directory `D`:

### 9.1 Exact-first rule
1. Attempt exact lookup for `c` in `D` (direct OS lookup).
2. If exists: select and continue.

### 9.2 Case-insensitive match via DirIndex
3. Compute `k = K(c)`.
4. Consult DirIndex for `D` (see §10): `EntrySet = fold_map[k]`.

Outcomes:
- **no entry**: not found
- **Unique(name)**: select that on-disk name, continue
- **Ambiguous([...])**: error `COLLISION` (mandatory; §11.1)

### 9.3 Symlink handling and loop detection
Symlink targets are resolved by the OS (no special case-insensitive handling of the symlink target path itself).

Loop protection for a single resolve/execute operation:
- Depth limit MUST be enforced; default 40; error `TOO_MANY_SYMLINKS`.
- Cycle detection MUST be implemented as follows:
  - Before following a symlink, obtain `(st_dev, st_ino)` via **lstat() of the symlink entry itself** (not the target).
  - Add this pair to a per-operation visited set.
  - If the pair is already present, fail immediately with `TOO_MANY_SYMLINKS` (or `SYMLINK_LOOP` if introduced; v1 may alias to `TOO_MANY_SYMLINKS`).

## 10. Directory indexing and caching
### 10.1 Purpose
Avoid repeated directory scans when resolving many paths sharing common prefixes.

### 10.2 DirIndex structure
For each directory `D`, cache:
- `dir_id`: identity (§10.4)
- `stamp`: validity marker (§10.5)
- `fold_map`: `K(name) -> EntrySet`, where EntrySet is:
  - `Unique(actual_name, inode/type optional)` OR
  - `Ambiguous([actual_name1, actual_name2, ...])`
- `built_at`: timestamp
- `dir_index_generation`: derived from relevant generations (see §10.6)
- `dir_generation`: DirGeneration counter for this directory identity

### 10.3 Building a DirIndex
- List entries of `D`.
- For each entry name `n`:
  - Validate UTF-8:
    - If invalid:
      - If `FAIL_ON_ANY_INVALID_UTF8_ENTRY`: fail `ENCODING_ERROR`
      - Else: skip entry and record diagnostic warning; continue
  - Compute `kn = K(n)` and insert into `fold_map[kn]`
  - If multiple distinct names map to same key, mark as `Ambiguous`.
- Capture `stamp` + `built_at` + `dir_index_generation`.
- Preserve the current `dir_generation` for this directory identity (DirGeneration MUST NOT reset on rebuild).

### 10.4 Cache keying
- DirIndex caches are keyed by absolute OS directory identity:
  - preferred: `(st_dev, st_ino)` of the directory
  - plus a canonical absolute path string for diagnostics only
- This makes caches independent of which `base_dir` was used to reach a directory.

### 10.5 Stamp strategy and stale-read model
- Stale reads within a TTL window are acceptable by design for directory content freshness.
- Hybrid validity strategy:
  - If `(now - built_at) < ttl_fast`: treat index as valid without stat.
  - Else:
    - `stat(D)` and compare stored `(st_dev, st_ino, st_mtime_ns, st_ctime_ns)`
    - if unchanged: refresh `built_at`
    - if changed: rebuild index.

`ttl_fast` MUST be configurable per resolver instance. Recommended defaults:
- read-heavy, stable trees: 30–60 seconds
- mixed read/write within run: 1–5 seconds

### 10.6 Generations that affect DirIndex validity
DirIndex entries MUST be considered invalid (and rebuilt) when any of the following change:
- `unicode_version_generation`
- `root_mapping_generation`
- `absolute_path_support_generation` (drive/UNC enable/disable toggle on Linux, if mutable)
- `encoding_policy_generation` (e.g., strictness flag changes, if mutable)
- `symlink_policy_generation` (e.g., depth limit changes, if mutable)

Changes to TTL values do NOT require invalidation; TTL affects revalidation timing only.

### 10.7 Prefix memoization (optional)
Memoize resolved prefixes:
- input prefix → resolved OS prefix + validation chain
- store stamps (or DirIndex identities) for each directory along prefix
- validate chain (TTL/stat + generation match) on reuse; recompute if any fails.

## 11. Collision semantics and required errors
### 11.1 Collision ambiguity (mandatory error)
If in directory `D` there exist >=2 distinct entries `a != b` such that `K(a) == K(b)`, then resolving any component `c` with `K(c) == K(a)` MUST fail with `COLLISION`.

This rule applies equally to intermediate and leaf components.

Error payload MUST include:
- directory path `D`
- requested component `c`
- colliding names list `[a, b, ...]`

### 11.2 Collision during operations that create parents (explicit)
For operations that create intermediate components (mkdir -p semantics or open with create + parent creation):
- If any intermediate component resolution encounters `COLLISION`, the operation MUST fail with `COLLISION` before performing any mutation.

## 12. Operation model: Plan vs Execute, concurrency, and TOCTOU
### 12.1 Plan/Resolve (side-effect free)
Plan/Resolve MAY read directories to evaluate case-insensitive matches, but MUST NOT:
- create, rename, delete, or write any filesystem entry.

Plan output MUST include:
- status (see §18)
- resolved parent path + resolved leaf spelling (when determinable)
- for the given intent:
  - `target_exists`
  - `target_is_dir` (if exists)
  - `would_create`
  - `would_truncate`
  - `would_error` (with reason)
- diagnostics (e.g., backslashes present, root mapping applied)

### 12.2 Execute (side effects)
Execute MUST:
1. perform Plan/Resolve internally (or accept a Plan; §12.5),
2. enforce collision rules (including intermediate collisions),
3. perform the OS call,
4. invalidate caches for affected directories (see §13),
5. return only after invalidation completes.

### 12.3 Concurrency model and consistency
- The resolver MUST be safe for concurrent use by multiple threads.
- Cache reads/writes MUST be synchronized (implementation-defined; RW locks or sharded mutexes are acceptable).
- Consistency model:
  - Stale reads within TTL are acceptable for directory content freshness.
  - During an execute mutation, concurrent plan operations MAY observe stale DirIndex results.
  - After an execute operation returns success, subsequent operations through the resolver MUST observe the mutation.

### 12.4 TOCTOU note for open-return-path
`execute_open_return_path` returns a path that the caller opens using native facilities. There is an inherent TOCTOU gap if external actors modify the filesystem between return and caller open.

Mitigation:
- Document that callers should open promptly.
- For stronger guarantees on Linux, `execute_open_return_fd` may be used.

### 12.5 Plan token validity (mandatory per-directory DirGeneration)
Plan output MUST include a `plan_token` with:
- `unicode_version_generation`
- `root_mapping_generation`
- `absolute_path_support_generation`
- `encoding_policy_generation`
- `symlink_policy_generation`
- `expected_dir_generations`: `HashMap<DirID, u64>` mapping every directory identity consulted during planning to its observed `dir_generation`
- optional `touched_dir_stamps[]`: stamps for ALL directories that were indexed/consulted during planning

Rules:
- Each directory identity tracked by the resolver MUST have an associated `dir_generation` counter (stored with the corresponding DirIndex/DirID record).
- Any execute operation that may change directory contents (create/mkdir/unlink/rmdir/rename/link/symlink, and any open with create) MUST increment the `dir_generation` for each affected parent directory **at the start of the execute** (before performing the OS operation).
  - For rename/move: increment both source parent and destination parent.
  - For create-on-open (`O_CREAT` equivalent): increment the parent on the create path.
- `execute_from_plan` MUST reject the plan as `STALE_PLAN` if for any `(DirID -> expected)` in `expected_dir_generations`, the current `dir_generation(DirID) != expected`.
  - This prevents using a plan produced concurrently with a mutation window affecting any consulted directory.
- If `touched_dir_stamps` are present, `execute_from_plan` MUST also require all stamps still match exactly (as per §10.5); otherwise `STALE_PLAN`.
- If `touched_dir_stamps` are omitted, `execute_from_plan` validates generations and `expected_dir_generations` only; directory changes are allowed only if they do not alter any consulted directory’s DirGeneration (recommended only for short-lived plans within a tightly controlled caller workflow).

## 13. Cache invalidation rules (correctness-critical)
### 13.1 Internal mutations (mandatory invalidation)
If the resolver successfully performs any operation that can change directory contents, it MUST invalidate the DirIndex for affected parent directories **before returning success**:
- `create`, `mkdir`, `unlink`, `rmdir`, `rename`, `link`, `symlink`
- For rename/move: invalidate both source parent and destination parent
- For create-on-open (`O_CREAT` equivalent): invalidate parent on success

### 13.2 External mutations
Changes made outside the resolver are detected by TTL/stat stamp logic (§10.5) or surface as OS errors.

## 14. Open/create/mkdir semantics (Windows-faithful defaults)
### 14.1 Intents (minimum)
- `STAT/EXISTS`
- `READ`
- `WRITE_TRUNCATE` (create if missing)
- `WRITE_APPEND` (create if missing)
- `CREATE_NEW` (fail if exists under Windows semantics)
- `MKDIRS` (mkdir -p semantics for directories)
- `RENAME` (move/rename; see §15)

### 14.2 Final-component behavior in parent directory `D`
Let final component be `c`:

1. If exact `c` exists: use it.
2. Else consult `K(c)` in `fold_map`:
   - `0 matches`:
     - READ/STAT: NOT_FOUND
     - WRITE_* (create enabled): create as spelled `c`
     - CREATE_NEW: create as spelled `c`
   - `1 match`:
     - READ/WRITE_*: operate on the existing entry (Windows-like)
     - CREATE_NEW: fail `EXISTS`
   - `Ambiguous`: `COLLISION` error

### 14.3 Intermediate-component semantics for operations that create parents
For each intermediate component:
- If exact exists and is directory: continue.
- Else if exactly one case-insensitive match exists:
  - if directory: continue
  - else: error `NOT_A_DIRECTORY`
- Else create directory spelled as requested.
- If `COLLISION` occurs at any step: fail before any mutation.

### 14.4 mkdirs when target exists as file
If `MKDIRS` is requested and the final resolved target exists but is not a directory, return `NOT_A_DIRECTORY`.

### 14.5 Case preservation on create
- When creating a new entry, the resolver requests the name exactly as provided in the input component `c`.
- The resolver trusts the underlying filesystem to store the case as requested.
- After successful creation, the resolver MUST invalidate the parent directory cache (§13.1).
- The resolver MAY rebuild and report actual on-disk spelling for diagnostics but MUST NOT fail solely due to case preservation differences unless explicitly configured.

## 15. Rename/move semantics (including cross-directory)
Rename MUST follow destination final-component semantics consistent with §14.2.

Given `rename(src_path -> dst_path)`:
1. Resolve `src_path` to a unique existing entry; if NOT_FOUND or COLLISION, fail.
2. Resolve the destination parent directory (all intermediate components); if any intermediate COLLISION, fail.
3. Apply destination leaf matching in destination parent `Ddst` for destination leaf name `c_dst`:
   - If `fold_map[K(c_dst)]` is `Ambiguous`: fail `COLLISION`.
   - If exact `c_dst` exists: destination target is that exact entry.
   - Else if a single case-insensitive match exists: destination target is that existing entry (Windows-like).
   - Else: destination target is a new name spelled as requested.

4. Overwrite behavior:
   - If destination target exists (exact or case-insensitive match), rename MUST behave as “replace” where the OS supports it.
   - If OS cannot replace due to directory/non-empty constraints, return the OS-derived error (mapped to `PERMISSION_DENIED`, `NOT_A_DIRECTORY`, or `IO_ERROR` as applicable).

5. Invalidate caches:
   - Invalidate source parent and destination parent before returning success.

## 16. Cross-language handle strategy
### 16.1 Requirements
- Must support Fortran standard `OPEN(file=path, ...)` usage.
- Must support Python and Rust efficiently.
- Must maintain cache correctness for directory mutations.

### 16.2 Strategy
Provide:
1. Execute operations for mutations (mkdir/rename/unlink, etc.) so cache invalidation is centralized.
2. Two open-related execute variants:
   - `execute_open_return_path(...)`:
     - performs Windows-faithful target selection (including case-insensitive match)
     - performs any requested preconditions (e.g., mkdirs if configured)
     - returns the resolved OS path for the selected target
     - caller opens using native facilities (Fortran `OPEN`, Python `open`, Rust `File::open`)
     - **Ownership:** the returned path memory is owned by the resolver and MUST be released by the caller via `resolver_free_string(...)` (see §19).
   - `execute_open_return_fd(...)` (optional on Linux):
     - returns a POSIX fd for Rust/Python consumers
     - NOT required for Fortran
     - MAY be implemented on Windows as an optional convenience; if implemented, it MUST return a CRT fd (not a raw HANDLE).

## 17. Diagnostics and observability (mandatory baseline)
### 17.1 Diagnostics requirements
The resolver MUST provide structured diagnostics including:
- input contained backslashes (warning)
- root mapping applied (drive/UNC → OS path) or unsupported absolute path
- collision details (directory, requested name, colliding names)
- encoding warnings/errors (including safe byte representation)
- symlink loop/depth exceeded
- permission denied (when surfaced)

### 17.2 Metrics (mandatory baseline counters)
Expose counters (queryable via API):
- DirIndex cache hits
- DirIndex cache misses
- DirIndex rebuilds
- stamp validations performed
- collisions encountered
- invalid UTF-8 entries encountered (skipped) and encoding errors raised
- plans rejected as `STALE_PLAN`

## 18. Error priority / precedence
When multiple errors could apply, errors MUST be reported in the following order:
1. `PATH_TOO_LONG` / structural invalidity (limits, malformed input)
2. `ENCODING_ERROR` for invalid UTF-8 in input path
3. `UNSUPPORTED_ABSOLUTE_PATH` / `UNMAPPED_ROOT` (when absolute Windows forms on Linux are disabled/unmapped)
4. `ESCAPES_ROOT`
5. `BASE_DIR_INVALID`
6. `COLLISION` (if encountered during resolution)
7. `TOO_MANY_SYMLINKS`
8. `PERMISSION_DENIED` (when determinable)
9. Other `IO_ERROR` / `INVALID_PATH` / `NOT_A_DIRECTORY` / `NOT_FOUND` / `EXISTS` as applicable

## 19. Public API surface (C ABI)
Minimum:
- `resolver_create(config) -> handle`
- `resolver_destroy(handle)`
- `resolver_set_root_mapping(handle, mapping, out_diag) -> status` (optional if root mapping supported)
- `resolver_plan(handle, base_dir, input_path, intent, out_plan, out_diag) -> status`
- `resolver_execute_mkdirs(handle, base_dir, input_path, out_result, out_diag) -> status`
- `resolver_execute_rename(handle, base_dir, from_path, to_path, out_result, out_diag) -> status`
- `resolver_execute_unlink(handle, base_dir, input_path, out_result, out_diag) -> status`
- `resolver_execute_open_return_path(handle, base_dir, input_path, intent, out_resolved_path, out_diag) -> status`
- `resolver_get_metrics(handle, out_metrics) -> status`
- `resolver_free_string(value) -> void` (required if `resolver_execute_open_return_path` allocates)
- `resolver_free_buffer(value) -> void` (required if `resolver_plan` or diagnostics allocate buffers)

Optional:
- `resolver_execute_open_return_fd(handle, base_dir, input_path, intent, out_fd, out_diag) -> status`
- `resolver_execute_from_plan(handle, plan, out_result, out_diag) -> status`

Status codes MUST distinguish at least:
- OK
- NOT_FOUND
- EXISTS
- COLLISION
- UNMAPPED_ROOT
- UNSUPPORTED_ABSOLUTE_PATH
- ESCAPES_ROOT
- ENCODING_ERROR
- TOO_MANY_SYMLINKS
- NOT_A_DIRECTORY
- PERMISSION_DENIED
- BASE_DIR_INVALID
- PATH_TOO_LONG
- STALE_PLAN
- IO_ERROR
- INVALID_PATH

### 19.1 FFI string ownership
If `resolver_execute_open_return_path` returns a non-empty path via `ResolverResolvedPath`, the implementation MAY allocate the buffer. In that case:
- The caller MUST release the buffer with `resolver_free_string`.
- The buffer remains valid across subsequent resolver calls and after `resolver_destroy` (it is standalone heap memory).
- `resolver_free_string` MUST be safe to call with `{ ptr = NULL, len = 0 }`.

If `resolver_plan` returns a `ResolverPlanToken` with non-empty `dir_generations` or `touched_dir_stamps`, the implementation MAY allocate those buffers. In that case:
- The caller MUST release each buffer with `resolver_free_buffer` before reusing or discarding the plan.
- `resolver_free_buffer` MUST be safe to call with `{ ptr = NULL, len = 0 }`.

If diagnostics return a non-empty `ResolverDiag.entries` buffer, the implementation MAY allocate it. In that case:
- The caller MUST release the buffer with `resolver_free_buffer`.

Bindings:
- Fortran: `ISO_C_BINDING` wrappers.
- Python: `ctypes/cffi` mapping status to exceptions with diagnostics.
- Rust: safe wrapper mapping status to `Result`.

## 20. Test requirements (automated)
Cross-platform test corpus:
- Baseline Windows behavior using native OS calls.
- Linux behavior through resolver.

Test categories:
1. Separator handling (`\` vs `/`)
2. Empty paths:
   - `""`, `"."`, `"./././."` resolve to `base_dir` (and mapped root for absolute)
3. Case-insensitive read: `Foo.txt` referenced as `foo.TXT`
4. Write targeting existing different-case name
5. Create new name with distinct case
6. Collisions: directory with `Foo` and `foo` → COLLISION (intermediate and leaf)
7. Drive/UNC parsing and mapping (when enabled)
8. `..` handling:
   - `..` cancels only over verified non-symlink directory components under the selected policy
   - `..` that would cancel across a symlink boundary fails deterministically
   - escapes-root policy enforced (`ESCAPES_ROOT` or clamp)
9. Symlink loops:
   - self-referencing symlink detected (lstat-based visited set)
   - multi-link cycle detected
   - depth exceeds limit → TOO_MANY_SYMLINKS
10. Cache correctness under concurrency:
   - execute mutation invalidates before returning
   - plans created during mutation cannot be executed (`STALE_PLAN` via per-directory DirGeneration)
11. Encoding:
   - invalid UTF-8 entry present; valid UTF-8 opens still succeed (skip-invalid)
   - strict mode fails on any invalid entry
12. Permission denied scenarios → PERMISSION_DENIED
13. Rename semantics:
   - overwrite by case-insensitive match in destination
   - destination directory collision → COLLISION
   - cross-directory invalidation

## 21. Design decisions summary
- **Case key**: Unicode simple-uppercase, invariant, pinned; no normalization; no 1→many expansions.
- **Encoding**: UTF-8 required for input paths; invalid UTF-8 directory entries are skipped by default (optionally strict-fail).
- **Resolution**: exact-first, then `K`-keyed lookup in DirIndex.
- **Ambiguity**: collisions under `K` are fatal errors for both intermediate and leaf components.
- **Symlinks**: OS-native symlink target resolution; mandatory depth limit + mandatory cycle detection using lstat() of symlink entries.
- **`..` semantics**: cancellation validated against resolved traversal; cancellation across symlink boundaries is not permitted.
- **Caching**: per-directory `K` map keyed by directory identity; hybrid TTL+stat stamp; TTL configurable; stale reads within TTL accepted.
- **Concurrency**: resolver thread-safe; execute invalidates before returning; plans carry per-directory DirGeneration expectations to prevent stale plan execution across concurrent mutations.
- **API model**: Plan (no side effects) + Execute (mutates, invalidates); open-return-path for Fortran compatibility; optional open-return-fd for Rust/Python.
- **Root forms**: drive/UNC support optional on Linux; enabled only with explicit mapping; mapping updates invalidate dependent caches/plans.
- **Predictability**: explicit error precedence for consistent behavior and tests.

## 22. Platform Implementation Strategy

### 22.1 Native vs Emulation Modes

The resolver operates in two distinct modes depending on the target platform:

**Windows (Native Mode):**
- The resolver is a thin wrapper around Win32 APIs (FindFirstFileW/FindNextFileW, CreateFileW, MoveFileExW, etc.)
- Case-insensitive behavior, collision handling, and path semantics are delegated directly to NTFS/ReFS, **except** the resolver enforces `base_dir` confinement for relative paths (attempts to traverse above `base_dir` via `..` MUST fail with `ESCAPES_ROOT`).
- DirIndex caching is NOT used (Windows filesystem already provides efficient case-insensitive lookups)
- All operations use native Windows path handling
- The complex resolution logic described in §9-13 is NOT implemented on Windows

**Linux (Emulation Mode):**
- The resolver implements full DirIndex caching and case-insensitive resolution logic per §9-13
- Windows-compatible semantics are emulated on top of case-sensitive POSIX filesystems
- All collision detection, symlink handling, and caching logic applies
- Drive/UNC path support (§4.2) is enabled via root mapping tables

### 22.2 Behavioral Equivalence Requirement

The Linux emulation mode MUST produce equivalent results to Windows native mode for all operations defined in this spec, within the following constraints:

**Equivalence guarantees:**
- **Collision detection**: If Windows would report "file exists" due to case conflict, Linux must report `COLLISION`
- **Case-insensitive matching**: If Windows would open `FOO.txt` when asked for `foo.TXT`, Linux must do the same (when a unique match exists)
- **Final-component semantics**: Create, open, and rename operations must follow Windows behavior per §14-15
- **Error codes**: Mapping of platform-specific errors to spec status codes (§19) must produce equivalent diagnostics

**Acceptable differences:**
- **Encoding**: Windows UTF-16 handling maps to Linux UTF-8 requirement per §6; this is a necessary adaptation
- **Unicode version**: Linux emulation uses pinned Unicode simple-uppercase (§5.3); minor differences from Windows NlsUpCase/NtfsUpCase tables are acceptable and expected
- **Symlink handling**: Linux has richer symlink semantics than Windows; cycle detection (§9.3) applies to Linux but may not have Windows equivalent
- **Performance**: Timing characteristics differ significantly (see §22.3)

### 22.3 Performance Characteristics

Expected performance profiles differ significantly:

**Windows (Native Mode):**
- O(1) case-insensitive lookups (filesystem-native support)
- No DirIndex overhead
- No TTL validation overhead
- Direct Win32 API call latency only

**Linux (Emulation Mode):**
- First access to a directory: O(n) scan to build DirIndex
- Subsequent accesses: O(1) case-insensitive lookups (cache hit)
- Cache miss or TTL expiration: O(n) rescan
- TTL/stamp revalidation adds stat() latency per §10.5

**Performance tuning for Linux:**

Applications requiring high-performance case-insensitive access on Linux should:
- Use longer `ttl_fast` values (30-60s) for stable directory trees
- Pre-warm caches by traversing expected paths if predictable
- Monitor cache hit rates via metrics (§17.2)
- Consider native case-sensitive paths when performance is critical and Windows compatibility is not required

### 22.4 Conditional Compilation Structure

Implementations SHOULD use conditional compilation to select the appropriate platform implementation:

**Rust example:**
```rust
#[cfg(target_os = "windows")]
mod windows_native;

#[cfg(target_os = "linux")]
mod linux_emulation;

#[cfg(target_os = "windows")]
use windows_native as platform;

#[cfg(target_os = "linux")]
use linux_emulation as platform;

// Public C ABI remains identical
pub use platform::*;
```

**C++ example:**
```cpp
#ifdef _WIN32
#include "windows_native.hpp"
#else
#include "linux_emulation.hpp"
#endif
```

Both implementations MUST provide identical C ABI signatures per §19.

### 22.5 Testing Requirements

Cross-platform behavioral equivalence MUST be validated via:

**1. Baseline Windows tests (ground truth):**
- Execute all test cases (§20) using Windows native APIs
- Capture results (resolved paths, error codes, operation outcomes) as reference behavior
- Document any Windows-specific quirks or limitations

**2. Linux emulation tests (equivalence validation):**
- Execute identical test cases through the resolver on Linux
- Compare outputs to Windows baseline
- Flag any behavioral divergences for investigation

**3. Divergence documentation:**
- Any unavoidable behavioral differences must be documented with rationale
- Examples: Unicode version differences, symlink-specific behavior, filesystem-specific limitations
- Differences in performance characteristics do not require documentation (expected per §22.3)

**4. Platform-specific edge case tests:**
- Windows: UNC path handling, extended-length paths, case-preservation on case-insensitive filesystems
- Linux: Symlink cycles, non-UTF-8 filenames, case-sensitive collision scenarios

The test corpus (§20) serves dual purposes:
- Validation of Linux emulation correctness against Windows ground truth
- Regression testing for Windows wrapper (ensure Win32 API changes don't break compatibility)

### 22.6 Implementation Complexity Comparison

Expected implementation sizes (rough estimates):

**Windows Native Mode:**
- Path normalization: ~200 lines
- Win32 API wrappers: ~300 lines
- Error mapping: ~100 lines
- **Total: ~600 lines**

**Linux Emulation Mode:**
- Path parsing and normalization: ~400 lines
- Unicode key function: ~200 lines
- Resolution algorithm: ~500 lines
- DirIndex caching: ~800 lines
- Concurrency/locking: ~300 lines
- Mutation operations: ~400 lines
- Cache invalidation: ~200 lines
- Metrics and diagnostics: ~200 lines
- **Total: ~3000 lines**

This ~5x complexity difference justifies the platform-specific approach.
