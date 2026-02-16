# AGENTS.md — wcfss (Windows-compatible filesystem semantics)

This file describes the expected development workflow, environments, and invariants for agents/tools working in this repository.

If anything here conflicts with `docs/spec.md`, treat `docs/spec.md` as authoritative and update this file to match.

## 0) Purpose and scope

This repo implements a reusable component (Rust core + C ABI) to provide Windows-compatible filesystem semantics across:
- Rust
- Python
- Fortran

Target platforms:
- Windows
- Linux (initially Ubuntu 22.04 under WSL2)

The main behavioural requirements and contract are defined in `docs/spec.md`.

The repo layout is described in `docs/project_structure.md`.

## 1) Development environments

### 1.1 Windows checkout (native)
- OS: Windows 11 Pro (host system)
- Working tree: `~\devel\rust\wcfss` (`C:\Users\jaap.vandervelde` for profile)
- Toolchain:
  - `rustc 1.93.0` host: `x86_64-pc-windows-gnu`
  - rustup installed
  - git configured; SSH keys set up; push/pull should not prompt for auth

### 1.2 Linux checkout (WSL2)
- Distro: Ubuntu 22.04 LTS, WSL2 instance name: `ubuntu-wcfss`
- Working tree: `~/wcfss`
- Toolchain:
  - `rustc 1.93.0` host: `x86_64-unknown-linux-gnu`
  - rustup installed
  - git configured; SSH keys set up; push/pull should not prompt for auth
- System packages required for builds:
  - `build-essential` (provides `cc`)
  - `pkg-config` (commonly required by native deps)
  - Additional packages may be required depending on enabled features/crates.

### 1.3 Two-working-tree policy (important)
There are **two separate working trees** (Windows + WSL). Do not attempt to develop from `/mnt/c/...` in WSL.

Sync work between the two environments via git (commit/push/pull) or request the user do so.

## 2) High-level workflow

### 2.1 Where to edit and run what
- Windows window / checkout:
  - Use for Windows-native behaviour checks and Windows build/test.
- WSL window / checkout:
  - Use for Linux behaviour checks and Linux build/test.
  - Prefer editing and building on WSL filesystem (`~/wcfss`) for correctness and performance.

### 2.2 Syncing changes between environments
Preferred flow:
1. Make changes in one working tree.
2. Run `cargo fmt` and `cargo test` (or at least `cargo check`) in that environment.
3. Commit with a clear message.
4. Push to the personal remote.
5. Pull the branch in the other environment and run its build/tests there.

Avoid long-lived divergent local changes in both working trees simultaneously.

## 3) Commands (agent-safe defaults)

### 3.1 Common (both environments)
- Fast compile check:
  - `cargo check`
- Full tests:
  - `cargo test`
- Lints (when relevant):
  - `cargo clippy --all-targets --all-features`
- Formatting:
  - `cargo fmt`

Unless explicitly requested otherwise:
- Prefer running checks/tests in **both environments** before declaring work complete. Communicate with the user as needed to achieve this.

### 3.2 WSL-only setup checks (if builds fail unexpectedly)
- Verify `cc` exists:
  - `command -v cc`
- Install missing build tooling:
  - `sudo apt update && sudo apt install -y build-essential pkg-config`

Do not install or modify system packages unless it is needed to proceed and only after confirming with user; if you do, record it in this file.

## 4) Source of truth and invariants

### 4.1 Spec and structure
- `docs/spec.md` is the source of truth for behaviour and API contracts.
- `docs/project_structure.md` is the source of truth for repo layout and intended module boundaries.

When making changes that affect behaviour, update tests and/or documentation accordingly.

### 4.2 Cross-platform semantic goals
This project intentionally deals with differences between Windows and Linux filesystems, including (but not limited to):
- case sensitivity / case folding behaviour
- path parsing and separators
- collisions / ambiguity rules
- symlink handling and resolution rules
- error mapping

Do not “paper over” platform differences with ad-hoc special cases unless they are explicitly required by `docs/spec.md`.

## 5) Testing expectations

When implementing new behaviour or fixing a bug:
- Add or update tests that capture the intended semantics.
- Verify the same test intent on both platforms (even if platform-specific assertions are needed).
 - If tests cannot be fully implemented yet (e.g. partial platform support), add TODO tests marked `#[ignore]` with a short rationale and track what is missing.

If a test must be platform-specific:
- Make that explicit in the test name and comments.
- Link the rationale back to the relevant section of `docs/spec.md`.

## 6) Guidance for agents making changes

- Keep changes small and reviewable; prefer incremental commits.
- Do not rename/move files without checking `docs/project_structure.md` and updating it if needed.
- Do not assume the current working directory; use repo-relative paths.
- When invoking shell commands, state which environment they should run in (Windows vs WSL) if it matters.
- If a change affects build prerequisites, update:
  - this file (`AGENTS.md`) and/or
  - `docs/` setup documentation (if present).

## 7) What to do at the start of a new session

1. Read:
   - `docs/spec.md`
   - `docs/project_structure.md`
   - this file (`AGENTS.md`)
2. Identify which environment is needed for the current task (Windows, WSL, or both).
3. Ensure the working tree is up to date:
   - `git status`
   - `git fetch`
   - `git pull --ff-only` (or the project’s preferred update strategy)

## 8) Notes about rustc versions (reference)
Windows:
- `rustc 1.93.0 (254b59607 2026-01-19)`, host `x86_64-pc-windows-gnu`, LLVM `21.1.8`

WSL:
- `rustc 1.93.0 (254b59607 2026-01-19)`, host `x86_64-unknown-linux-gnu`, LLVM `21.1.8`

Toolchain drift is allowed, but if behaviour changes due to toolchain differences, note it and prefer pinning with a `rust-toolchain.toml` if that becomes a recurring issue.

## 9) Updating this file
Update `AGENTS.md` whenever:
- build prerequisites change
- the two-working-tree workflow changes
- new required commands/checks are introduced
- the default “definition of done” for changes is updated

Keep this file concise and operational. Longer rationale belongs in `docs/`.
