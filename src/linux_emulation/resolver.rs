use crate::common::types::*;
use crate::linux_emulation::cache::{evict_if_needed, DirCache};
use crate::linux_emulation::dirindex::{DirIndex, DirStamp, EntrySet};
use crate::linux_emulation::parser;
use crate::resolver::Resolver;

use core::ffi::c_char;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

const MAX_INPUT_PATH_BYTES: usize = 32 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const SYMLINK_DEPTH_LIMIT: usize = 40;
const DEFAULT_TTL_FAST_MS: u64 = 1000;
const DEFAULT_CACHE_MAX_ENTRIES: usize = 1000;
fn trace(msg: &str) {
    eprintln!("[wcfss][linux] {msg}");
}

#[derive(Debug)]
struct ComponentSelection {
    name: String,
    meta: fs::Metadata,
}

#[derive(Debug, Default)]
struct PlanTrace {
    dir_generations: HashMap<(u64, u64), u64>,
    dir_stamps: HashMap<(u64, u64), DirStamp>,
}

impl PlanTrace {
    fn record(&mut self, dir_id: (u64, u64), generation: u64) {
        self.dir_generations.entry(dir_id).or_insert(generation);
    }

    fn record_stamp(&mut self, dir_id: (u64, u64), stamp: DirStamp) {
        self.dir_stamps.entry(dir_id).or_insert(stamp);
    }
}

#[derive(Debug, Default)]
struct DiagCollector {
    entries: Vec<DiagEntryOwned>,
}

#[derive(Debug)]
struct DiagEntryOwned {
    code: ResolverDiagCode,
    severity: ResolverDiagSeverity,
    context: String,
    detail: String,
}

impl DiagCollector {
    fn push(&mut self, code: ResolverDiagCode, severity: ResolverDiagSeverity, context: String, detail: String) {
        self.entries.push(DiagEntryOwned {
            code,
            severity,
            context,
            detail,
        });
    }
}

#[derive(Debug, Default)]
struct MetricsCounters {
    dirindex_cache_hits: AtomicU64,
    dirindex_cache_misses: AtomicU64,
    dirindex_rebuilds: AtomicU64,
    stamp_validations: AtomicU64,
    collisions: AtomicU64,
    invalid_utf8_entries: AtomicU64,
    encoding_errors: AtomicU64,
    plans_rejected_stale: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RootMappingKey {
    Drive(char),
    Unc { server: String, share: String },
}

fn map_io_error(err: &io::Error) -> ResolverStatus {
    use io::ErrorKind;
    if let Some(code) = err.raw_os_error() {
        if code == libc::ELOOP {
            return ResolverStatus::TooManySymlinks;
        }
    }
    match err.kind() {
        ErrorKind::NotFound => ResolverStatus::NotFound,
        ErrorKind::PermissionDenied => ResolverStatus::PermissionDenied,
        ErrorKind::AlreadyExists => ResolverStatus::Exists,
        ErrorKind::InvalidInput => ResolverStatus::InvalidPath,
        ErrorKind::NotADirectory => ResolverStatus::NotADirectory,
        _ => ResolverStatus::IoError,
    }
}

fn string_view_to_string(view: *const ResolverStringView) -> Result<String, ResolverStatus> {
    let view = unsafe { view.as_ref() }.ok_or(ResolverStatus::InvalidPath)?;
    if view.ptr.is_null() && view.len != 0 {
        return Err(ResolverStatus::InvalidPath);
    }
    let bytes = unsafe { std::slice::from_raw_parts(view.ptr as *const u8, view.len) };
    if bytes.len() > MAX_INPUT_PATH_BYTES {
        return Err(ResolverStatus::PathTooLong);
    }
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| ResolverStatus::EncodingError)
}

fn base_dir_from_view(view: *const ResolverStringView) -> Result<String, ResolverStatus> {
    string_view_to_string(view).map_err(|_| ResolverStatus::BaseDirInvalid)
}

fn build_dir_index(
    dir: &Path,
    strict_utf8: bool,
    mut diag: Option<&mut DiagCollector>,
    metrics: &MetricsCounters,
) -> Result<DirIndex, ResolverStatus> {
    trace(&format!("DirIndex build start: {}", dir.display()));
    let mut map: HashMap<String, EntrySet> = HashMap::new();
    let meta = fs::metadata(dir).map_err(|err| map_io_error(&err))?;
    let dir_id = (meta.dev(), meta.ino());
    let stamp = DirStamp::from_meta(&meta);
    let diag_path = dir.to_string_lossy().into_owned();
    let entries = fs::read_dir(dir).map_err(|err| map_io_error(&err))?;
    let mut invalid_utf8_count = 0usize;
    let mut entry_count = 0usize;
    for entry in entries {
        let entry = entry.map_err(|err| map_io_error(&err))?;
        let name = entry.file_name();
        entry_count += 1;
        match std::str::from_utf8(name.as_bytes()) {
            Ok(valid) => {
                let key = parser::key_simple_uppercase(valid);
                let collision = crate::linux_emulation::dirindex::insert_entry(
                    &mut map,
                    key.clone(),
                    valid.to_string(),
                );
                if collision {
                    trace(&format!(
                        "DirIndex collision detected for key '{}'; entry='{}'.",
                        key, valid
                    ));
                } else {
                    trace(&format!(
                        "DirIndex indexed entry '{}' with key '{}'.",
                        valid, key
                    ));
                }
            }
            Err(_) => {
                invalid_utf8_count += 1;
                metrics.invalid_utf8_entries.fetch_add(1, Ordering::SeqCst);
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::InvalidUtf8EntrySkipped,
                        ResolverDiagSeverity::Warning,
                        dir.display().to_string(),
                        format!("{:?}", name),
                    );
                }
                trace(&format!(
                    "DirIndex skip invalid UTF-8 entry: {:?} (dir {})",
                    name,
                    dir.display()
                ));
                if strict_utf8 {
                    metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    if let Some(diag) = diag.as_deref_mut() {
                        diag.push(
                            ResolverDiagCode::EncodingError,
                            ResolverDiagSeverity::Error,
                            dir.display().to_string(),
                            "invalid UTF-8 entry encountered".to_string(),
                        );
                    }
                    return Err(ResolverStatus::EncodingError);
                }
            }
        }
    }
    trace(&format!(
        "DirIndex build complete: {} entries ({} invalid UTF-8 skipped)",
        entry_count, invalid_utf8_count
    ));
    Ok(DirIndex {
        dir_id,
        diag_path,
        fold_map: map,
        stamp,
        built_at: Instant::now(),
    })
}

fn normalize_input(input: &str) -> (String, bool) {
    let mut normalized = String::with_capacity(input.len());
    let mut had_backslash = false;
    for ch in input.chars() {
        if ch == '\\' {
            had_backslash = true;
            normalized.push('/');
        } else {
            normalized.push(ch);
        }
    }
    (normalized, had_backslash)
}

fn normalize_root_mapping_key(input: &str) -> Result<RootMappingKey, ResolverStatus> {
    let (normalized, _) = normalize_input(input);
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            if trimmed.len() == 2 {
                let drive = (bytes[0] as char).to_ascii_uppercase();
                return Ok(RootMappingKey::Drive(drive));
            }
            return Err(ResolverStatus::InvalidPath);
        }
    }

    if normalized.starts_with("//") {
        let mut parts = normalized[2..].split('/').filter(|p| !p.is_empty());
        let server = parts.next().ok_or(ResolverStatus::InvalidPath)?;
        let share = parts.next().ok_or(ResolverStatus::InvalidPath)?;
        if parts.next().is_some() {
            return Err(ResolverStatus::InvalidPath);
        }
        return Ok(RootMappingKey::Unc {
            server: parser::key_simple_uppercase(server),
            share: parser::key_simple_uppercase(share),
        });
    }

    Err(ResolverStatus::InvalidPath)
}

fn precheck_escapes_root(normalized: &str, skip_components: usize) -> Result<(), ResolverStatus> {
    let mut depth: isize = 0;
    let mut skipped = 0usize;
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if skipped < skip_components {
            skipped += 1;
            continue;
        }
        if part == ".." {
            if depth == 0 {
                return Err(ResolverStatus::EscapesRoot);
            }
            depth -= 1;
            continue;
        }
        depth += 1;
    }
    Ok(())
}

fn init_plan(plan: &mut ResolverPlan) {
    plan.size = std::mem::size_of::<ResolverPlan>() as u32;
    plan.status = ResolverStatus::Ok;
    plan.would_error = ResolverStatus::Ok;
    plan.flags = 0;
    plan.intent = ResolverIntent::StatExists;
    plan.resolved_parent = ResolverStringView {
        ptr: std::ptr::null(),
        len: 0,
    };
    plan.resolved_leaf = ResolverStringView {
        ptr: std::ptr::null(),
        len: 0,
    };
    plan.plan_token = ResolverPlanToken {
        size: std::mem::size_of::<ResolverPlanToken>() as u32,
        op_generation: 0,
        unicode_version_generation: 0,
        root_mapping_generation: 0,
        absolute_path_support_generation: 0,
        encoding_policy_generation: 0,
        symlink_policy_generation: 0,
        dir_generations: ResolverBufferView {
            ptr: std::ptr::null(),
            len: 0,
        },
        touched_dir_stamps: ResolverBufferView {
            ptr: std::ptr::null(),
            len: 0,
        },
        reserved: [0; 4],
    };
    plan.reserved = [0; 6];
}

fn write_plan_dir_generations(
    plan: &mut ResolverPlan,
    trace: &PlanTrace,
) -> Result<(), ResolverStatus> {
    // Caller must free any previous plan_token buffer via resolver_free_buffer
    // before reusing the plan.
    if trace.dir_generations.is_empty() {
        plan.plan_token.dir_generations = ResolverBufferView {
            ptr: std::ptr::null(),
            len: 0,
        };
        return Ok(());
    }
    let count = trace.dir_generations.len();
    let bytes = count * std::mem::size_of::<ResolverDirGeneration>();
    let ptr = unsafe { libc::malloc(bytes) } as *mut ResolverDirGeneration;
    if ptr.is_null() {
        return Err(ResolverStatus::IoError);
    }
    let mut entries: Vec<ResolverDirGeneration> = Vec::with_capacity(count);
    for (dir_id, generation) in trace.dir_generations.iter() {
        entries.push(ResolverDirGeneration {
            dev: dir_id.0,
            ino: dir_id.1,
            generation: *generation,
        });
    }
    unsafe {
        std::ptr::copy_nonoverlapping(entries.as_ptr(), ptr, count);
    }
    plan.plan_token.dir_generations = ResolverBufferView {
        ptr: ptr as *const core::ffi::c_void,
        len: count,
    };
    Ok(())
}

fn write_plan_dir_stamps(plan: &mut ResolverPlan, trace: &PlanTrace) -> Result<(), ResolverStatus> {
    if trace.dir_stamps.is_empty() {
        plan.plan_token.touched_dir_stamps = ResolverBufferView {
            ptr: std::ptr::null(),
            len: 0,
        };
        return Ok(());
    }
    let count = trace.dir_stamps.len();
    let bytes = count * std::mem::size_of::<ResolverDirStamp>();
    let ptr = unsafe { libc::malloc(bytes) } as *mut ResolverDirStamp;
    if ptr.is_null() {
        return Err(ResolverStatus::IoError);
    }
    let mut entries: Vec<ResolverDirStamp> = Vec::with_capacity(count);
    for (dir_id, stamp) in trace.dir_stamps.iter() {
        entries.push(ResolverDirStamp {
            dev: dir_id.0,
            ino: dir_id.1,
            mtime_sec: stamp.mtime_sec,
            mtime_nsec: stamp.mtime_nsec,
            ctime_sec: stamp.ctime_sec,
            ctime_nsec: stamp.ctime_nsec,
        });
    }
    unsafe {
        std::ptr::copy_nonoverlapping(entries.as_ptr(), ptr, count);
    }
    plan.plan_token.touched_dir_stamps = ResolverBufferView {
        ptr: ptr as *const core::ffi::c_void,
        len: count,
    };
    Ok(())
}

fn write_string_view(value: &str, out: &mut ResolverStringView) -> Result<(), ResolverStatus> {
    if value.is_empty() {
        out.ptr = std::ptr::null();
        out.len = 0;
        return Ok(());
    }
    let bytes = value.as_bytes();
    let ptr = unsafe { libc::malloc(bytes.len()) } as *mut u8;
    if ptr.is_null() {
        return Err(ResolverStatus::IoError);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    out.ptr = ptr as *const c_char;
    out.len = bytes.len();
    Ok(())
}

fn set_plan_paths(plan: &mut ResolverPlan, resolved: &Path) -> Result<(), ResolverStatus> {
    let parent = resolved.parent().unwrap_or(resolved);
    let parent_str = parent.to_string_lossy();
    let leaf_str = resolved
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "".into());
    write_string_view(&parent_str, &mut plan.resolved_parent)?;
    write_string_view(&leaf_str, &mut plan.resolved_leaf)?;
    Ok(())
}

fn write_diag_entries(out_diag: *mut ResolverDiag, collector: &DiagCollector) {
    let out_diag = unsafe { out_diag.as_mut() };
    let out_diag = match out_diag {
        Some(out) => out,
        None => return,
    };
    out_diag.size = std::mem::size_of::<ResolverDiag>() as u32;
    out_diag.entries = ResolverBufferView {
        ptr: std::ptr::null(),
        len: 0,
    };
    if collector.entries.is_empty() {
        return;
    }

    let count = collector.entries.len();
    let bytes = count * std::mem::size_of::<ResolverDiagEntry>();
    let ptr = unsafe { libc::malloc(bytes) } as *mut ResolverDiagEntry;
    if ptr.is_null() {
        return;
    }

    let mut entries: Vec<ResolverDiagEntry> = Vec::with_capacity(count);
    for entry in &collector.entries {
        let mut context = ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        };
        let mut detail = ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        };
        if write_string_view(&entry.context, &mut context).is_err()
            || write_string_view(&entry.detail, &mut detail).is_err()
        {
            // Best-effort: leave empty if allocation fails.
            context = ResolverStringView {
                ptr: std::ptr::null(),
                len: 0,
            };
            detail = ResolverStringView {
                ptr: std::ptr::null(),
                len: 0,
            };
        }
        entries.push(ResolverDiagEntry {
            code: entry.code as u32,
            severity: entry.severity as u32,
            context,
            detail,
        });
    }

    unsafe {
        std::ptr::copy_nonoverlapping(entries.as_ptr(), ptr, count);
    }
    out_diag.entries = ResolverBufferView {
        ptr: ptr as *const core::ffi::c_void,
        len: count,
    };
}

#[derive(Debug, Clone, Copy)]
struct ResolverGenerations {
    unicode_version_generation: u64,
    root_mapping_generation: u64,
    absolute_path_support_generation: u64,
    encoding_policy_generation: u64,
    symlink_policy_generation: u64,
}

fn combine_generations(gen: ResolverGenerations) -> u64 {
    let mut value = 0u64;
    let parts = [
        gen.unicode_version_generation,
        gen.root_mapping_generation,
        gen.absolute_path_support_generation,
        gen.encoding_policy_generation,
        gen.symlink_policy_generation,
    ];
    for part in parts {
        value = value
            .wrapping_mul(1_000_003)
            .wrapping_add(part.wrapping_add(0x9e37_79b9_7f4a_7c15));
    }
    value
}

fn validate_base_dir(base_dir: &str) -> Result<PathBuf, ResolverStatus> {
    if !base_dir.starts_with('/') {
        return Err(ResolverStatus::BaseDirInvalid);
    }
    let path = PathBuf::from(base_dir);
    let metadata = fs::metadata(&path).map_err(|_| ResolverStatus::BaseDirInvalid)?;
    if !metadata.is_dir() {
        return Err(ResolverStatus::BaseDirInvalid);
    }
    Ok(path)
}

#[derive(Debug)]
struct ResolvedInfo {
    path: PathBuf,
    target_exists: bool,
    target_is_dir: bool,
    would_create: bool,
    would_truncate: bool,
}

#[derive(Debug)]
struct MkdirPlan {
    final_path: PathBuf,
    create_paths: Vec<PathBuf>,
}

fn parse_ttl_fast(config_ttl_ms: Option<u64>) -> Duration {
    if let Some(value) = config_ttl_ms {
        if value > 0 {
            return Duration::from_millis(value);
        }
    }
    match std::env::var("WCFSS_TTL_FAST_MS") {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_millis(DEFAULT_TTL_FAST_MS)),
        Err(_) => Duration::from_millis(DEFAULT_TTL_FAST_MS),
    }
}

fn select_component(
    resolver: &LinuxResolver,
    current: &Path,
    component: &str,
    mut plan_trace: Option<&mut PlanTrace>,
    mut diag: Option<&mut DiagCollector>,
) -> Result<Option<ComponentSelection>, ResolverStatus> {
    let exact_path = current.join(component);
    match fs::symlink_metadata(&exact_path) {
        Ok(meta) => {
            if let Some(plan_trace) = plan_trace.as_deref_mut() {
                resolver.record_dir_generation_for_path(current, plan_trace);
                resolver.record_dir_stamp_for_path(current, plan_trace);
            }
            let _ = resolver.get_dir_index(
                current,
                plan_trace.as_deref_mut(),
                diag.as_deref_mut(),
            );
            Ok(Some(ComponentSelection {
                name: component.to_string(),
                meta,
            }))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let index = resolver.get_dir_index(
                current,
                plan_trace.as_deref_mut(),
                diag.as_deref_mut(),
            )?;
            let key = parser::key_simple_uppercase(component);
            match index.fold_map.get(&key) {
                None => Ok(None),
                Some(EntrySet::Ambiguous(list)) => {
                    trace(&format!("DirIndex collision for key '{}': {:?}", key, list));
                    resolver
                        .metrics
                        .collisions
                        .fetch_add(1, Ordering::SeqCst);
                    if let Some(diag) = diag.as_deref_mut() {
                        diag.push(
                            ResolverDiagCode::Collision,
                            ResolverDiagSeverity::Error,
                            current.display().to_string(),
                            list.join(", "),
                        );
                    }
                    Err(ResolverStatus::Collision)
                }
                Some(EntrySet::Unique(actual)) => {
                    let path = current.join(actual);
                    let meta = fs::symlink_metadata(&path).map_err(|err| map_io_error(&err))?;
                    Ok(Some(ComponentSelection {
                        name: actual.clone(),
                        meta,
                    }))
                }
            }
        }
        Err(err) => Err(map_io_error(&err)),
    }
}

fn resolve_path(
    resolver: &LinuxResolver,
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
    mut plan_trace: Option<&mut PlanTrace>,
    mut diag: Option<&mut DiagCollector>,
) -> Result<ResolvedInfo, ResolverStatus> {
    if input_path.as_bytes().len() > MAX_INPUT_PATH_BYTES {
        return Err(ResolverStatus::PathTooLong);
    }

    let (normalized, had_backslash) = normalize_input(input_path);
    if had_backslash {
        trace("Input contained backslashes; normalized to forward slashes.");
        if let Some(diag) = diag.as_deref_mut() {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.to_string(),
                "input contained backslashes".to_string(),
            );
        }
    }

    let (root, skip_components) = match resolver.classify_root(&normalized) {
        Ok(value) => value,
        Err(status) => {
            if let Some(diag) = diag.as_deref_mut() {
                match status {
                    ResolverStatus::UnsupportedAbsolutePath => diag.push(
                        ResolverDiagCode::UnsupportedAbsolutePath,
                        ResolverDiagSeverity::Error,
                        input_path.to_string(),
                        "unsupported absolute path".to_string(),
                    ),
                    ResolverStatus::UnmappedRoot => diag.push(
                        ResolverDiagCode::UnmappedRoot,
                        ResolverDiagSeverity::Error,
                        input_path.to_string(),
                        "unmapped root".to_string(),
                    ),
                    _ => {}
                }
            }
            return Err(status);
        }
    };
    if let Err(status) = precheck_escapes_root(&normalized, skip_components) {
        if let Some(diag) = diag.as_deref_mut() {
            diag.push(
                ResolverDiagCode::EscapesRoot,
                ResolverDiagSeverity::Error,
                input_path.to_string(),
                "path escapes root".to_string(),
            );
        }
        return Err(status);
    }
    let base_dir_path = validate_base_dir(base_dir)?;
    let mut current = root.unwrap_or_else(|| base_dir_path.to_path_buf());
    let mut stack: Vec<(PathBuf, bool)> = vec![(current.clone(), false)];

    let mut components: Vec<&str> = Vec::new();
    let mut skipped = 0usize;
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if skipped < skip_components {
            skipped += 1;
            continue;
        }
        if part.as_bytes().len() > MAX_COMPONENT_BYTES {
            return Err(ResolverStatus::PathTooLong);
        }
        components.push(part);
        if components.len() > MAX_COMPONENTS {
            return Err(ResolverStatus::PathTooLong);
        }
    }

    if components.is_empty() {
        let is_dir = fs::metadata(&current).map(|m| m.is_dir()).unwrap_or(false);
        return Ok(ResolvedInfo {
            path: current,
            target_exists: true,
            target_is_dir: is_dir,
            would_create: false,
            would_truncate: false,
        });
    }

    let mut visited_symlinks: HashSet<(u64, u64)> = HashSet::new();
    let mut symlink_depth = 0usize;

    let mut mkdirs_creates = false;
    let mut creating = false;

    for (idx, component) in components.iter().enumerate() {
        if *component == ".." {
            if stack.len() <= 1 {
                trace("Encountered .. at root boundary.");
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::EscapesRoot,
                        ResolverDiagSeverity::Error,
                        current.display().to_string(),
                        "path escapes root".to_string(),
                    );
                }
                return Err(ResolverStatus::EscapesRoot);
            }
            let (_, was_symlink) = stack.pop().unwrap();
            if was_symlink {
                trace("Encountered .. across symlink boundary.");
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::SymlinkLoop,
                        ResolverDiagSeverity::Error,
                        current.display().to_string(),
                        "path traversed across symlink boundary".to_string(),
                    );
                }
                return Err(ResolverStatus::InvalidPath);
            }
            current = stack.last().unwrap().0.clone();
            continue;
        }

        trace(&format!(
            "Resolving component '{}' in {}",
            component,
            current.display()
        ));
        let selection = if intent == ResolverIntent::Mkdirs && creating {
            None
        } else {
            match select_component(
                resolver,
                &current,
                component,
                plan_trace.as_deref_mut(),
                diag.as_deref_mut(),
            ) {
                Ok(value) => value,
                Err(status) => return Err(status),
            }
        };

        let (selected_name, selected_meta, missing_component) = match selection {
            Some(entry) => (entry.name, Some(entry.meta), false),
            None => (component.to_string(), None, true),
        };

        let next_path = current.join(&selected_name);
        if !missing_component {
            let selected_meta = selected_meta.as_ref().expect("meta for existing entry");
            if selected_meta.file_type().is_symlink() {
            trace(&format!("Encountered symlink: {}", next_path.display()));
            let dev = selected_meta.dev();
            let ino = selected_meta.ino();
            if visited_symlinks.contains(&(dev, ino)) {
                trace(&format!(
                    "Symlink cycle detected at dev={}, ino={}.",
                    dev, ino
                ));
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::SymlinkLoop,
                        ResolverDiagSeverity::Error,
                        next_path.display().to_string(),
                        "symlink cycle detected".to_string(),
                    );
                }
                return Err(ResolverStatus::TooManySymlinks);
            }
            if symlink_depth >= SYMLINK_DEPTH_LIMIT {
                trace(&format!(
                    "Symlink depth limit exceeded (limit={SYMLINK_DEPTH_LIMIT})."
                ));
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::SymlinkLoop,
                        ResolverDiagSeverity::Error,
                        next_path.display().to_string(),
                        "symlink depth limit exceeded".to_string(),
                    );
                }
                return Err(ResolverStatus::TooManySymlinks);
            }
            visited_symlinks.insert((dev, ino));
            symlink_depth += 1;
            trace(&format!(
                "Symlink visit recorded (depth={}, dev={}, ino={}).",
                symlink_depth, dev, ino
            ));
            }
        }

        let is_last = idx + 1 == components.len();
        if !is_last {
            if missing_component {
                if intent == ResolverIntent::Mkdirs {
                    creating = true;
                    mkdirs_creates = true;
                    trace("Intermediate component will be created for mkdirs.");
                } else {
                    return Err(ResolverStatus::NotFound);
                }
            } else {
                let meta = fs::metadata(&next_path).map_err(|err| map_io_error(&err))?;
                if !meta.is_dir() {
                    trace("Intermediate component is not a directory.");
                    return Err(ResolverStatus::NotADirectory);
                }
            }
            stack.push((
                next_path.clone(),
                !missing_component
                    && selected_meta
                        .as_ref()
                        .map(|meta| meta.file_type().is_symlink())
                        .unwrap_or(false),
            ));
            current = next_path;
            continue;
        }

        let (target_exists, target_is_dir) = if missing_component {
            (false, false)
        } else {
            let meta_follow = fs::metadata(&next_path);
            match meta_follow {
                Ok(meta) => (true, meta.is_dir()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => (false, false),
                Err(err) => return Err(map_io_error(&err)),
            }
        };

        let mut would_create = false;
        let mut would_truncate = false;
        match intent {
            ResolverIntent::Read | ResolverIntent::StatExists => {
                if !target_exists {
                    return Err(ResolverStatus::NotFound);
                }
            }
            ResolverIntent::WriteTruncate => {
                if target_exists {
                    would_truncate = true;
                } else {
                    would_create = true;
                }
            }
            ResolverIntent::WriteAppend => {
                if !target_exists {
                    would_create = true;
                }
            }
            ResolverIntent::CreateNew => {
                if target_exists {
                    return Err(ResolverStatus::Exists);
                }
                would_create = true;
            }
            ResolverIntent::Mkdirs => {
                if target_exists && !target_is_dir {
                    return Err(ResolverStatus::NotADirectory);
                }
                if !target_exists {
                    would_create = true;
                }
            }
            ResolverIntent::Rename => {
                return Err(ResolverStatus::InvalidPath);
            }
        }

        return Ok(ResolvedInfo {
            path: next_path,
            target_exists,
            target_is_dir,
            would_create: would_create || mkdirs_creates,
            would_truncate,
        });
    }

    Err(ResolverStatus::InvalidPath)
}

fn plan_mkdirs(
    resolver: &LinuxResolver,
    base_dir: &str,
    input_path: &str,
    mut plan_trace: Option<&mut PlanTrace>,
    mut diag: Option<&mut DiagCollector>,
) -> Result<MkdirPlan, ResolverStatus> {
    if input_path.as_bytes().len() > MAX_INPUT_PATH_BYTES {
        return Err(ResolverStatus::PathTooLong);
    }

    let (normalized, had_backslash) = normalize_input(input_path);
    if had_backslash {
        trace("Input contained backslashes; normalized to forward slashes.");
        if let Some(diag) = diag.as_deref_mut() {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.to_string(),
                "input contained backslashes".to_string(),
            );
        }
    }

    let (root, skip_components) = match resolver.classify_root(&normalized) {
        Ok(value) => value,
        Err(status) => {
            if let Some(diag) = diag.as_deref_mut() {
                match status {
                    ResolverStatus::UnsupportedAbsolutePath => diag.push(
                        ResolverDiagCode::UnsupportedAbsolutePath,
                        ResolverDiagSeverity::Error,
                        input_path.to_string(),
                        "unsupported absolute path".to_string(),
                    ),
                    ResolverStatus::UnmappedRoot => diag.push(
                        ResolverDiagCode::UnmappedRoot,
                        ResolverDiagSeverity::Error,
                        input_path.to_string(),
                        "unmapped root".to_string(),
                    ),
                    _ => {}
                }
            }
            return Err(status);
        }
    };
    if let Err(status) = precheck_escapes_root(&normalized, skip_components) {
        if let Some(diag) = diag.as_deref_mut() {
            diag.push(
                ResolverDiagCode::EscapesRoot,
                ResolverDiagSeverity::Error,
                input_path.to_string(),
                "path escapes root".to_string(),
            );
        }
        return Err(status);
    }
    let base_dir_path = validate_base_dir(base_dir)?;
    let mut current = root.unwrap_or_else(|| base_dir_path.to_path_buf());
    let mut stack: Vec<(PathBuf, bool)> = vec![(current.clone(), false)];

    let mut components: Vec<&str> = Vec::new();
    let mut skipped = 0usize;
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if skipped < skip_components {
            skipped += 1;
            continue;
        }
        if part.as_bytes().len() > MAX_COMPONENT_BYTES {
            return Err(ResolverStatus::PathTooLong);
        }
        components.push(part);
        if components.len() > MAX_COMPONENTS {
            return Err(ResolverStatus::PathTooLong);
        }
    }

    if components.is_empty() {
        return Ok(MkdirPlan {
            final_path: current,
            create_paths: Vec::new(),
        });
    }

    let mut visited_symlinks: HashSet<(u64, u64)> = HashSet::new();
    let mut symlink_depth = 0usize;
    let mut create_paths: Vec<PathBuf> = Vec::new();
    let mut creating = false;

    for (idx, component) in components.iter().enumerate() {
        if *component == ".." {
            if stack.len() <= 1 {
                trace("Encountered .. at root boundary.");
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::EscapesRoot,
                        ResolverDiagSeverity::Error,
                        current.display().to_string(),
                        "path escapes root".to_string(),
                    );
                }
                return Err(ResolverStatus::EscapesRoot);
            }
            let (_, was_symlink) = stack.pop().unwrap();
            if was_symlink {
                trace("Encountered .. across symlink boundary.");
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::SymlinkLoop,
                        ResolverDiagSeverity::Error,
                        current.display().to_string(),
                        "path traversed across symlink boundary".to_string(),
                    );
                }
                return Err(ResolverStatus::InvalidPath);
            }
            current = stack.last().unwrap().0.clone();
            continue;
        }

        if creating {
            let next_path = current.join(component);
            create_paths.push(next_path.clone());
            stack.push((next_path.clone(), false));
            current = next_path.clone();
            if idx + 1 == components.len() {
                return Ok(MkdirPlan {
                    final_path: next_path,
                    create_paths,
                });
            }
            continue;
        }

        trace(&format!(
            "Planning mkdirs component '{}' in {}",
            component,
            current.display()
        ));

        let selection = match select_component(
            resolver,
            &current,
            component,
            plan_trace.as_deref_mut(),
            diag.as_deref_mut(),
        ) {
            Ok(value) => value,
            Err(status) => return Err(status),
        };

        let (selected_name, selected_meta, missing_component) = match selection {
            Some(entry) => (entry.name, Some(entry.meta), false),
            None => (component.to_string(), None, true),
        };

        let next_path = current.join(&selected_name);
        if !missing_component {
            let selected_meta = selected_meta.as_ref().expect("meta for existing entry");
            if selected_meta.file_type().is_symlink() {
                trace(&format!("Encountered symlink: {}", next_path.display()));
                let dev = selected_meta.dev();
                let ino = selected_meta.ino();
            if visited_symlinks.contains(&(dev, ino)) {
                trace(&format!(
                    "Symlink cycle detected at dev={}, ino={}.",
                    dev, ino
                ));
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::SymlinkLoop,
                        ResolverDiagSeverity::Error,
                        next_path.display().to_string(),
                        "symlink cycle detected".to_string(),
                    );
                }
                return Err(ResolverStatus::TooManySymlinks);
            }
            if symlink_depth >= SYMLINK_DEPTH_LIMIT {
                trace(&format!(
                    "Symlink depth limit exceeded (limit={SYMLINK_DEPTH_LIMIT})."
                ));
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::SymlinkLoop,
                        ResolverDiagSeverity::Error,
                        next_path.display().to_string(),
                        "symlink depth limit exceeded".to_string(),
                    );
                }
                return Err(ResolverStatus::TooManySymlinks);
            }
                visited_symlinks.insert((dev, ino));
                symlink_depth += 1;
                trace(&format!(
                    "Symlink visit recorded (depth={}, dev={}, ino={}).",
                    symlink_depth, dev, ino
                ));
            }
        }

        let is_last = idx + 1 == components.len();
        if !is_last {
            if missing_component {
                create_paths.push(next_path.clone());
                creating = true;
                stack.push((next_path.clone(), false));
                current = next_path;
                continue;
            }
            let meta = fs::metadata(&next_path).map_err(|err| map_io_error(&err))?;
            if !meta.is_dir() {
                trace("Intermediate component is not a directory.");
                return Err(ResolverStatus::NotADirectory);
            }
            stack.push((
                next_path.clone(),
                selected_meta
                    .as_ref()
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false),
            ));
            current = next_path;
            continue;
        }

        if missing_component {
            create_paths.push(next_path.clone());
            return Ok(MkdirPlan {
                final_path: next_path,
                create_paths,
            });
        }

        let meta = fs::metadata(&next_path).map_err(|err| map_io_error(&err))?;
        if !meta.is_dir() {
            return Err(ResolverStatus::NotADirectory);
        }
        return Ok(MkdirPlan {
            final_path: next_path,
            create_paths,
        });
    }

    Err(ResolverStatus::InvalidPath)
}

pub struct LinuxResolver {
    strict_utf8: bool,
    ttl_fast: Duration,
    dir_cache: RwLock<DirCache>,
    cache_max_entries: usize,
    generations: RwLock<ResolverGenerations>,
    cache_generation: AtomicU64,
    op_generation: AtomicU64,
    mutation_lock: Mutex<()>,
    dir_generations: RwLock<HashMap<(u64, u64), u64>>,
    metrics: MetricsCounters,
    root_mapping_enabled: bool,
    root_mapping: RwLock<HashMap<RootMappingKey, PathBuf>>,
}

impl LinuxResolver {
    pub fn new(config: *const ResolverConfig) -> Self {
        let mut strict_utf8 = false;
        let mut config_ttl_ms = None;
        let mut root_mapping_enabled = false;
        if let Some(cfg) = unsafe { config.as_ref() } {
            strict_utf8 = cfg.flags & RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY != 0;
            root_mapping_enabled =
                cfg.flags & RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS != 0;
            if cfg.size as usize >= std::mem::size_of::<ResolverConfig>() {
                config_ttl_ms = Some(cfg.ttl_fast_ms);
            }
        }
        let encoding_policy_generation = if strict_utf8 { 1 } else { 0 };
        let absolute_path_support_generation = if root_mapping_enabled { 1 } else { 0 };
        let generations = ResolverGenerations {
            unicode_version_generation: 1,
            root_mapping_generation: 0,
            absolute_path_support_generation,
            encoding_policy_generation,
            symlink_policy_generation: 0,
        };
        let cache_generation = combine_generations(generations);
        let ttl_fast = parse_ttl_fast(config_ttl_ms);
        Self {
            strict_utf8,
            ttl_fast,
            dir_cache: RwLock::new(DirCache::new()),
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            generations: RwLock::new(generations),
            cache_generation: AtomicU64::new(cache_generation),
            op_generation: AtomicU64::new(0),
            mutation_lock: Mutex::new(()),
            dir_generations: RwLock::new(HashMap::new()),
            metrics: MetricsCounters::default(),
            root_mapping_enabled,
            root_mapping: RwLock::new(HashMap::new()),
        }
    }

    fn current_dir_index_generation(&self) -> u64 {
        let generations = self.generations.read().expect("generations lock poisoned");
        combine_generations(*generations)
    }

    fn invalidate_cache_if_needed(&self) {
        let current = self.current_dir_index_generation();
        if self.cache_generation.load(Ordering::SeqCst) != current {
            trace("DirIndex generation changed; clearing cache.");
            let mut cache = self.dir_cache.write().expect("dir_cache lock poisoned");
            cache.clear();
            self.cache_generation.store(current, Ordering::SeqCst);
        }
    }

    fn classify_root(
        &self,
        normalized: &str,
    ) -> Result<(Option<PathBuf>, usize), ResolverStatus> {
        let trimmed = normalized.trim_start_matches('/');
        let leading = normalized.len() - trimmed.len();
        if leading >= 2 {
            if !self.root_mapping_enabled {
                trace("UNC-style path detected on Linux (unsupported).");
                return Err(ResolverStatus::UnsupportedAbsolutePath);
            }
            let mut parts = trimmed.split('/').filter(|p| !p.is_empty());
            let server = parts.next().ok_or(ResolverStatus::InvalidPath)?;
            let share = parts.next().ok_or(ResolverStatus::InvalidPath)?;
            let key = RootMappingKey::Unc {
                server: parser::key_simple_uppercase(server),
                share: parser::key_simple_uppercase(share),
            };
            let mapping = self.root_mapping.read().expect("root_mapping lock poisoned");
            if let Some(root) = mapping.get(&key) {
                return Ok((Some(root.clone()), 2));
            }
            return Err(ResolverStatus::UnmappedRoot);
        }

        if normalized.len() >= 2 {
            let bytes = normalized.as_bytes();
            if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                if normalized.len() == 2 || !normalized.as_bytes()[2].eq(&b'/') {
                    return Err(ResolverStatus::InvalidPath);
                }
                if !self.root_mapping_enabled {
                    trace("Drive-letter path detected on Linux (unsupported).");
                    return Err(ResolverStatus::UnsupportedAbsolutePath);
                }
                let drive = (bytes[0] as char).to_ascii_uppercase();
                let key = RootMappingKey::Drive(drive);
                let mapping = self.root_mapping.read().expect("root_mapping lock poisoned");
                if let Some(root) = mapping.get(&key) {
                    return Ok((Some(root.clone()), 1));
                }
                return Err(ResolverStatus::UnmappedRoot);
            }
        }

        if normalized.starts_with('/') {
            return Ok((Some(PathBuf::from("/")), 0));
        }
        Ok((None, 0))
    }

    fn get_dir_index(
        &self,
        dir: &Path,
        plan_trace: Option<&mut PlanTrace>,
        diag: Option<&mut DiagCollector>,
    ) -> Result<DirIndex, ResolverStatus> {
        // Locking strategy:
        // - Never hold dir_cache locks during OS calls (metadata/read_dir).
        // - Use a read lock for cache lookups.
        // - Use a write lock only for in-memory updates/insertions/evictions.
        self.invalidate_cache_if_needed();
        let meta = fs::metadata(dir).map_err(|err| map_io_error(&err))?;
        let dir_id = (meta.dev(), meta.ino());
        let stamp = DirStamp::from_meta(&meta);
        let now = Instant::now();
        let dir_generation = self.current_dir_generation(dir_id);
        if let Some(plan_trace) = plan_trace {
            plan_trace.record(dir_id, dir_generation);
            plan_trace.record_stamp(dir_id, stamp.clone());
        }

        let cached = {
            let cache = self.dir_cache.read().expect("dir_cache lock poisoned");
            cache.get(&dir_id).cloned()
        };

        if let Some(entry) = cached {
            let age = now.duration_since(entry.built_at);
            if age < self.ttl_fast {
                self.metrics
                    .dirindex_cache_hits
                    .fetch_add(1, Ordering::SeqCst);
                trace(&format!(
                    "DirIndex cache hit (ttl_fast, age {:?}).",
                    age
                ));
                return Ok(entry);
            }
            if entry.stamp.matches(&stamp) {
                self.metrics
                    .stamp_validations
                    .fetch_add(1, Ordering::SeqCst);
                self.metrics
                    .dirindex_cache_hits
                    .fetch_add(1, Ordering::SeqCst);
                trace("DirIndex cache hit (stamp match); refreshing built_at.");
                let mut cache = self.dir_cache.write().expect("dir_cache lock poisoned");
                if let Some(existing) = cache.get_mut(&dir_id) {
                    if existing.stamp.matches(&stamp) {
                        existing.built_at = now;
                        return Ok(existing.clone());
                    }
                }
            }
            trace("DirIndex cache stale; rebuilding.");
        } else {
            self.metrics
                .dirindex_cache_misses
                .fetch_add(1, Ordering::SeqCst);
            trace("DirIndex cache miss; building.");
        }

        let index = build_dir_index(dir, self.strict_utf8, diag, &self.metrics)?;
        self.metrics
            .dirindex_rebuilds
            .fetch_add(1, Ordering::SeqCst);
        let mut cache = self.dir_cache.write().expect("dir_cache lock poisoned");
        cache.insert(index.dir_id, index.clone());
        evict_if_needed(&mut cache, self.cache_max_entries);
        Ok(index)
    }

    fn invalidate_dir_index(&self, dir: &Path) {
        // OS metadata lookup happens without holding the cache lock.
        if let Ok(meta) = fs::metadata(dir) {
            let dir_id = (meta.dev(), meta.ino());
            let mut cache = self.dir_cache.write().expect("dir_cache lock poisoned");
            cache.remove(&dir_id);
        }
    }

    fn begin_execute(&self) {
        // Lock ordering: mutation_lock -> (optional) dir_cache write.
        // We never hold this lock across OS calls; it only guards generation bumps.
        let _guard = self.mutation_lock.lock().expect("mutation_lock poisoned");
        self.op_generation.fetch_add(1, Ordering::SeqCst);
    }

    fn current_dir_generation(&self, dir_id: (u64, u64)) -> u64 {
        {
            let generations = self
                .dir_generations
                .read()
                .expect("dir_generations lock poisoned");
            if let Some(value) = generations.get(&dir_id) {
                return *value;
            }
        }
        let mut generations = self
            .dir_generations
            .write()
            .expect("dir_generations lock poisoned");
        *generations.entry(dir_id).or_insert(0)
    }

    fn record_dir_generation_for_path(&self, path: &Path, plan_trace: &mut PlanTrace) {
        if let Ok(meta) = fs::metadata(path) {
            let dir_id = (meta.dev(), meta.ino());
            let generation = self.current_dir_generation(dir_id);
            plan_trace.record(dir_id, generation);
        }
    }

    fn record_dir_stamp_for_path(&self, path: &Path, plan_trace: &mut PlanTrace) {
        if let Ok(meta) = fs::metadata(path) {
            let dir_id = (meta.dev(), meta.ino());
            let stamp = DirStamp::from_meta(&meta);
            plan_trace.record_stamp(dir_id, stamp);
        }
    }

    fn bump_dir_generations_for_paths(&self, paths: &[PathBuf]) {
        // OS metadata lookup happens without holding the dir_generations lock.
        let mut dir_ids = Vec::new();
        for path in paths {
            if let Ok(meta) = fs::metadata(path) {
                dir_ids.push((meta.dev(), meta.ino()));
            }
        }
        if dir_ids.is_empty() {
            return;
        }
        let mut generations = self
            .dir_generations
            .write()
            .expect("dir_generations lock poisoned");
        for dir_id in dir_ids {
            let entry = generations.entry(dir_id).or_insert(0);
            *entry = entry.wrapping_add(1);
        }
    }
}

impl Resolver for LinuxResolver {
    fn set_root_mapping(
        &self,
        mapping: *const ResolverRootMapping,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        if !self.root_mapping_enabled {
            return ResolverStatus::UnsupportedAbsolutePath;
        }
        let mapping = match unsafe { mapping.as_ref() } {
            Some(value) => value,
            None => return ResolverStatus::InvalidPath,
        };
        if mapping.entries.is_null() && mapping.len != 0 {
            return ResolverStatus::InvalidPath;
        }
        let entries = if mapping.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(mapping.entries, mapping.len) }
        };

        let mut table: HashMap<RootMappingKey, PathBuf> = HashMap::new();
        for entry in entries {
            let key_str = match string_view_to_string(&entry.key as *const ResolverStringView) {
                Ok(value) => value,
                Err(status) => return status,
            };
            let value_str = match string_view_to_string(&entry.value as *const ResolverStringView) {
                Ok(value) => value,
                Err(status) => return status,
            };
            let key = match normalize_root_mapping_key(&key_str) {
                Ok(value) => value,
                Err(status) => return status,
            };
            if !value_str.starts_with('/') {
                return ResolverStatus::InvalidPath;
            }
            table.insert(key, PathBuf::from(value_str));
        }

        {
            let mut mapping_guard = self.root_mapping.write().expect("root_mapping lock poisoned");
            *mapping_guard = table;
        }
        {
            let mut generations = self.generations.write().expect("generations lock poisoned");
            generations.root_mapping_generation =
                generations.root_mapping_generation.wrapping_add(1);
        }
        self.invalidate_cache_if_needed();
        ResolverStatus::Ok
    }

    fn plan(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_plan: *mut ResolverPlan,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        trace(&format!(
            "Plan start: base_dir='{}', input_path='{}', intent={:?}",
            base_dir, input_path, intent
        ));

        let plan_out = unsafe { out_plan.as_mut() };
        let mut diag = DiagCollector::default();

        let mut plan_trace = PlanTrace::default();
        match resolve_path(
            self,
            &base_dir,
            &input_path,
            intent,
            Some(&mut plan_trace),
            Some(&mut diag),
        ) {
            Ok(info) => {
                trace(&format!(
                    "Plan resolved: path='{}', exists={}, is_dir={}, would_create={}, would_truncate={}",
                    info.path.display(),
                    info.target_exists,
                    info.target_is_dir,
                    info.would_create,
                    info.would_truncate
                ));
                let mut flags = 0u32;
                if info.target_exists {
                    flags |= RESOLVER_PLAN_TARGET_EXISTS;
                }
                if info.target_is_dir {
                    flags |= RESOLVER_PLAN_TARGET_IS_DIR;
                }
                if info.would_create {
                    flags |= RESOLVER_PLAN_WOULD_CREATE;
                }
                if info.would_truncate {
                    flags |= RESOLVER_PLAN_WOULD_TRUNCATE;
                }
                if let Some(plan_out) = plan_out {
                    init_plan(plan_out);
                    plan_out.flags = flags;
                    plan_out.intent = intent;
                    plan_out.status = ResolverStatus::Ok;
                    plan_out.would_error = ResolverStatus::Ok;
                    let generations = self.generations.read().expect("generations lock poisoned");
                    plan_out.plan_token.op_generation =
                        self.op_generation.load(Ordering::SeqCst);
                    plan_out.plan_token.unicode_version_generation =
                        generations.unicode_version_generation;
                    plan_out.plan_token.root_mapping_generation = generations.root_mapping_generation;
                    plan_out.plan_token.absolute_path_support_generation =
                        generations.absolute_path_support_generation;
                    plan_out.plan_token.encoding_policy_generation =
                        generations.encoding_policy_generation;
                    plan_out.plan_token.symlink_policy_generation =
                        generations.symlink_policy_generation;
                    if let Err(status) = write_plan_dir_generations(plan_out, &plan_trace) {
                        plan_out.status = status;
                        plan_out.would_error = status;
                        write_diag_entries(out_diag, &diag);
                        return status;
                    }
                    if let Err(status) = write_plan_dir_stamps(plan_out, &plan_trace) {
                        plan_out.status = status;
                        plan_out.would_error = status;
                        write_diag_entries(out_diag, &diag);
                        return status;
                    }
                    if let Err(status) = set_plan_paths(plan_out, &info.path) {
                        plan_out.status = status;
                        plan_out.would_error = status;
                        write_diag_entries(out_diag, &diag);
                        return status;
                    }
                }
                write_diag_entries(out_diag, &diag);
                ResolverStatus::Ok
            }
            Err(status) => {
                trace(&format!("Plan failed with status {:?}", status));
                if let Some(plan_out) = plan_out {
                    init_plan(plan_out);
                    plan_out.status = status;
                    plan_out.would_error = status;
                    plan_out.intent = intent;
                    plan_out.plan_token.op_generation =
                        self.op_generation.load(Ordering::SeqCst);
                    let generations = self.generations.read().expect("generations lock poisoned");
                    plan_out.plan_token.unicode_version_generation =
                        generations.unicode_version_generation;
                    plan_out.plan_token.root_mapping_generation = generations.root_mapping_generation;
                    plan_out.plan_token.absolute_path_support_generation =
                        generations.absolute_path_support_generation;
                    plan_out.plan_token.encoding_policy_generation =
                        generations.encoding_policy_generation;
                    plan_out.plan_token.symlink_policy_generation =
                        generations.symlink_policy_generation;
                    let _ = write_plan_dir_generations(plan_out, &plan_trace);
                    let _ = write_plan_dir_stamps(plan_out, &plan_trace);
                }
                write_diag_entries(out_diag, &diag);
                status
            }
        }
    }

    fn execute_mkdirs(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        if let Some(out) = unsafe { out_result.as_mut() } {
            out.size = std::mem::size_of::<ResolverResult>() as u32;
            out.reserved = [0; 6];
        }

        let mut diag = DiagCollector::default();
        let plan = match plan_mkdirs(self, &base_dir, &input_path, None, Some(&mut diag)) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };

        if plan.create_paths.is_empty() {
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::Ok;
        }

        let mut parents_to_invalidate: HashSet<PathBuf> = HashSet::new();
        for create_path in &plan.create_paths {
            if let Some(parent) = create_path.parent() {
                parents_to_invalidate.insert(parent.to_path_buf());
            }
        }

        trace(&format!(
            "execute_mkdirs creating {} path(s), final '{}'",
            plan.create_paths.len(),
            plan.final_path.display()
        ));

        let parents: Vec<PathBuf> = parents_to_invalidate.iter().cloned().collect();
        self.bump_dir_generations_for_paths(&parents);

        for create_path in &plan.create_paths {
            match fs::create_dir(create_path) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    let meta = match fs::metadata(create_path) {
                        Ok(meta) => meta,
                        Err(err) => {
                            for parent in &parents_to_invalidate {
                                self.invalidate_dir_index(parent);
                            }
                            return map_io_error(&err);
                        }
                    };
                    if !meta.is_dir() {
                        for parent in &parents_to_invalidate {
                            self.invalidate_dir_index(parent);
                        }
                        write_diag_entries(out_diag, &diag);
                        return ResolverStatus::NotADirectory;
                    }
                }
                Err(err) => {
                    for parent in &parents_to_invalidate {
                        self.invalidate_dir_index(parent);
                    }
                    if err.kind() == io::ErrorKind::PermissionDenied {
                        diag.push(
                            ResolverDiagCode::PermissionDenied,
                            ResolverDiagSeverity::Error,
                            create_path.display().to_string(),
                            "permission denied creating directory".to_string(),
                        );
                    }
                    write_diag_entries(out_diag, &diag);
                    return map_io_error(&err);
                }
            }
        }

        for parent in &parents_to_invalidate {
            self.invalidate_dir_index(parent);
        }

        write_diag_entries(out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_rename(
        &self,
        base_dir: *const ResolverStringView,
        from_path: *const ResolverStringView,
        to_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let from_path = match string_view_to_string(from_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let to_path = match string_view_to_string(to_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        if let Some(out) = unsafe { out_result.as_mut() } {
            out.size = std::mem::size_of::<ResolverResult>() as u32;
            out.reserved = [0; 6];
        }

        let mut diag = DiagCollector::default();
        let source = match resolve_path(
            self,
            &base_dir,
            &from_path,
            ResolverIntent::Read,
            None,
            Some(&mut diag),
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };

        let destination =
            match resolve_path(
                self,
                &base_dir,
                &to_path,
                ResolverIntent::WriteTruncate,
                None,
                Some(&mut diag),
            ) {
                Ok(value) => value,
                Err(status) => {
                    write_diag_entries(out_diag, &diag);
                    return status;
                }
            };

        trace(&format!(
            "execute_rename '{}' -> '{}'",
            source.path.display(),
            destination.path.display()
        ));

        let mut parents = Vec::new();
        if let Some(parent) = source.path.parent() {
            parents.push(parent.to_path_buf());
        }
        if let Some(parent) = destination.path.parent() {
            parents.push(parent.to_path_buf());
        }
        self.bump_dir_generations_for_paths(&parents);

        if let Err(err) = fs::rename(&source.path, &destination.path) {
            if err.kind() == io::ErrorKind::PermissionDenied {
                diag.push(
                    ResolverDiagCode::PermissionDenied,
                    ResolverDiagSeverity::Error,
                    source.path.display().to_string(),
                    "permission denied renaming".to_string(),
                );
            }
            write_diag_entries(out_diag, &diag);
            return map_io_error(&err);
        }

        if let Some(parent) = source.path.parent() {
            self.invalidate_dir_index(parent);
        }
        if let Some(parent) = destination.path.parent() {
            self.invalidate_dir_index(parent);
        }

        write_diag_entries(out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_unlink(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        if let Some(out) = unsafe { out_result.as_mut() } {
            out.size = std::mem::size_of::<ResolverResult>() as u32;
            out.reserved = [0; 6];
        }

        let mut diag = DiagCollector::default();
        let info = match resolve_path(
            self,
            &base_dir,
            &input_path,
            ResolverIntent::Read,
            None,
            Some(&mut diag),
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };
        if info.target_is_dir {
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::NotADirectory;
        }

        trace(&format!(
            "execute_unlink deleting '{}'",
            info.path.display()
        ));
        if let Some(parent) = info.path.parent() {
            self.bump_dir_generations_for_paths(&[parent.to_path_buf()]);
        }
        if let Err(err) = fs::remove_file(&info.path) {
            if err.kind() == io::ErrorKind::PermissionDenied {
                diag.push(
                    ResolverDiagCode::PermissionDenied,
                    ResolverDiagSeverity::Error,
                    info.path.display().to_string(),
                    "permission denied removing file".to_string(),
                );
            }
            write_diag_entries(out_diag, &diag);
            return map_io_error(&err);
        }
        if let Some(parent) = info.path.parent() {
            self.invalidate_dir_index(parent);
        }
        write_diag_entries(out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_open_return_path(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_resolved_path: *mut ResolverResolvedPath,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        let mut diag = DiagCollector::default();
        let info = match resolve_path(
            self,
            &base_dir,
            &input_path,
            intent,
            None,
            Some(&mut diag),
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };

        let out_resolved_path = unsafe { out_resolved_path.as_mut() };
        let out_resolved_path = match out_resolved_path {
            Some(out) => out,
            None => return ResolverStatus::InvalidPath,
        };

        let utf8 = info.path.to_string_lossy();
        let bytes = utf8.as_bytes();
        if bytes.is_empty() {
            out_resolved_path.value.ptr = std::ptr::null();
            out_resolved_path.value.len = 0;
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::Ok;
        }
        let ptr = unsafe { libc::malloc(bytes.len()) } as *mut u8;
        if ptr.is_null() {
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::IoError;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        }
        out_resolved_path.value.ptr = ptr as *const core::ffi::c_char;
        out_resolved_path.value.len = bytes.len();
        write_diag_entries(out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_open_return_fd(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_fd: *mut i32,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        if out_fd.is_null() {
            return ResolverStatus::InvalidPath;
        }
        self.begin_execute();
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        let mut diag = DiagCollector::default();
        let info = match resolve_path(
            self,
            &base_dir,
            &input_path,
            intent,
            None,
            Some(&mut diag),
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };

        let flags = match intent {
            ResolverIntent::Read | ResolverIntent::StatExists => libc::O_RDONLY,
            ResolverIntent::WriteAppend => libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT,
            ResolverIntent::WriteTruncate => libc::O_WRONLY | libc::O_TRUNC | libc::O_CREAT,
            ResolverIntent::CreateNew => libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            ResolverIntent::Mkdirs | ResolverIntent::Rename => return ResolverStatus::InvalidPath,
        };

        let c_path = match std::ffi::CString::new(info.path.as_os_str().as_bytes()) {
            Ok(value) => value,
            Err(_) => return ResolverStatus::InvalidPath,
        };
        if info.would_create {
            if let Some(parent) = info.path.parent() {
                self.bump_dir_generations_for_paths(&[parent.to_path_buf()]);
            }
        }
        let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o666) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                diag.push(
                    ResolverDiagCode::PermissionDenied,
                    ResolverDiagSeverity::Error,
                    info.path.display().to_string(),
                    "permission denied opening file".to_string(),
                );
            }
            write_diag_entries(out_diag, &diag);
            return map_io_error(&err);
        }
        if info.would_create {
            if let Some(parent) = info.path.parent() {
                self.invalidate_dir_index(parent);
            }
        }
        unsafe {
            *out_fd = fd;
        }
        write_diag_entries(out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_from_plan(
        &self,
        plan: *const ResolverPlan,
        _out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let plan = unsafe { plan.as_ref() }.ok_or(ResolverStatus::InvalidPath);
        let plan = match plan {
            Ok(value) => value,
            Err(status) => return status,
        };

        let diag = DiagCollector::default();

        // Lock ordering: mutation_lock -> (optional) dir_cache write.
        // Validation happens under mutation_lock to prevent concurrent execute
        // operations from interleaving generation checks.
        let _guard = self.mutation_lock.lock().expect("mutation_lock poisoned");

        // Validate plan token generations and per-directory DirGeneration as required by §12.5.
        let expected_token_size = std::mem::size_of::<ResolverPlanToken>() as u32;
        let expected_plan_size = std::mem::size_of::<ResolverPlan>() as u32;
        if plan.size < expected_plan_size || plan.plan_token.size < expected_token_size {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::StalePlan;
        }

        let current = self.op_generation.load(Ordering::SeqCst);
        if plan.plan_token.op_generation != current {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::StalePlan;
        }

        {
            let generations = self.generations.read().expect("generations lock poisoned");
            if plan.plan_token.unicode_version_generation != generations.unicode_version_generation
                || plan.plan_token.root_mapping_generation != generations.root_mapping_generation
                || plan.plan_token.absolute_path_support_generation
                    != generations.absolute_path_support_generation
                || plan.plan_token.encoding_policy_generation != generations.encoding_policy_generation
                || plan.plan_token.symlink_policy_generation != generations.symlink_policy_generation
            {
                self.metrics
                    .plans_rejected_stale
                    .fetch_add(1, Ordering::SeqCst);
                write_diag_entries(out_diag, &diag);
                return ResolverStatus::StalePlan;
            }
        }

        let dir_view = plan.plan_token.dir_generations;
        if dir_view.len > 0 && dir_view.ptr.is_null() {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::StalePlan;
        }
        if dir_view.len > 0 {
            let entries = unsafe {
                std::slice::from_raw_parts(
                    dir_view.ptr as *const ResolverDirGeneration,
                    dir_view.len,
                )
            };
            for entry in entries {
                let dir_id = (entry.dev, entry.ino);
                let current = self.current_dir_generation(dir_id);
                if current != entry.generation {
                    self.metrics
                        .plans_rejected_stale
                        .fetch_add(1, Ordering::SeqCst);
                    write_diag_entries(out_diag, &diag);
                    return ResolverStatus::StalePlan;
                }
            }
        }

        let stamp_view = plan.plan_token.touched_dir_stamps;
        if stamp_view.len > 0 && stamp_view.ptr.is_null() {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(out_diag, &diag);
            return ResolverStatus::StalePlan;
        }
        if stamp_view.len > 0 {
            let entries = unsafe {
                std::slice::from_raw_parts(
                    stamp_view.ptr as *const ResolverDirStamp,
                    stamp_view.len,
                )
            };
            for entry in entries {
                let dir_id = (entry.dev, entry.ino);
                let diag_path = {
                    let cache = self.dir_cache.read().expect("dir_cache lock poisoned");
                    cache.get(&dir_id).map(|entry| entry.diag_path.clone())
                };
                let diag_path = match diag_path {
                    Some(value) => value,
                    None => {
                        self.metrics
                            .plans_rejected_stale
                            .fetch_add(1, Ordering::SeqCst);
                        write_diag_entries(out_diag, &diag);
                        return ResolverStatus::StalePlan;
                    }
                };
                let meta = match fs::metadata(&diag_path) {
                    Ok(meta) => meta,
                    Err(_) => {
                        self.metrics
                            .plans_rejected_stale
                            .fetch_add(1, Ordering::SeqCst);
                        write_diag_entries(out_diag, &diag);
                        return ResolverStatus::StalePlan;
                    }
                };
                let stamp = DirStamp::from_meta(&meta);
                if stamp.dev != dir_id.0
                    || stamp.ino != dir_id.1
                    || stamp.mtime_sec != entry.mtime_sec
                    || stamp.mtime_nsec != entry.mtime_nsec
                    || stamp.ctime_sec != entry.ctime_sec
                    || stamp.ctime_nsec != entry.ctime_nsec
                {
                    self.metrics
                        .plans_rejected_stale
                        .fetch_add(1, Ordering::SeqCst);
                    write_diag_entries(out_diag, &diag);
                    return ResolverStatus::StalePlan;
                }
            }
        }

        // Increment at the start of the mutation phase (before any filesystem mutation).
        self.op_generation.fetch_add(1, Ordering::SeqCst);

        let parent = match string_view_to_string(&plan.resolved_parent as *const ResolverStringView)
        {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };
        let leaf = match string_view_to_string(&plan.resolved_leaf as *const ResolverStringView) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(out_diag, &diag);
                return status;
            }
        };
        let mut path = PathBuf::from(parent);
        if !leaf.is_empty() {
            path = path.join(leaf);
        }

        let intent = plan.intent;
        match intent {
            ResolverIntent::StatExists | ResolverIntent::Read => {
                let meta = fs::metadata(&path);
                if let Err(err) = meta {
                    let status = map_io_error(&err);
                    write_diag_entries(out_diag, &diag);
                    return status;
                }
                write_diag_entries(out_diag, &diag);
                ResolverStatus::Ok
            }
            ResolverIntent::Mkdirs => {
                let mut parents = Vec::new();
                for ancestor in path.ancestors().skip(1) {
                    parents.push(ancestor.to_path_buf());
                }
                self.bump_dir_generations_for_paths(&parents);
                let status = match fs::create_dir_all(&path) {
                    Ok(_) => ResolverStatus::Ok,
                    Err(err) => map_io_error(&err),
                };
                if status == ResolverStatus::Ok {
                    if let Some(parent) = path.parent() {
                        self.invalidate_dir_index(parent);
                    }
                }
                write_diag_entries(out_diag, &diag);
                status
            }
            ResolverIntent::WriteTruncate
            | ResolverIntent::WriteAppend
            | ResolverIntent::CreateNew => {
                let flags = match intent {
                    ResolverIntent::WriteAppend => libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT,
                    ResolverIntent::WriteTruncate => libc::O_WRONLY | libc::O_TRUNC | libc::O_CREAT,
                    ResolverIntent::CreateNew => libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    _ => libc::O_RDONLY,
                };
                if (plan.flags & RESOLVER_PLAN_WOULD_CREATE) != 0 {
                    if let Some(parent) = path.parent() {
                        self.bump_dir_generations_for_paths(&[parent.to_path_buf()]);
                    }
                }
                let c_path = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
                    Ok(value) => value,
                    Err(_) => {
                        write_diag_entries(out_diag, &diag);
                        return ResolverStatus::InvalidPath;
                    }
                };
                let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o666) };
                if fd < 0 {
                    let err = io::Error::last_os_error();
                    write_diag_entries(out_diag, &diag);
                    return map_io_error(&err);
                }
                unsafe {
                    libc::close(fd);
                }
                if (plan.flags & RESOLVER_PLAN_WOULD_CREATE) != 0 {
                    if let Some(parent) = path.parent() {
                        self.invalidate_dir_index(parent);
                    }
                }
                write_diag_entries(out_diag, &diag);
                ResolverStatus::Ok
            }
            ResolverIntent::Rename => {
                write_diag_entries(out_diag, &diag);
                ResolverStatus::InvalidPath
            }
        }
    }

    fn get_metrics(&self, out_metrics: *mut ResolverMetrics) -> ResolverStatus {
        let out_metrics = unsafe { out_metrics.as_mut() };
        let out_metrics = match out_metrics {
            Some(out) => out,
            None => return ResolverStatus::InvalidPath,
        };
        out_metrics.size = std::mem::size_of::<ResolverMetrics>() as u32;
        out_metrics.dirindex_cache_hits =
            self.metrics.dirindex_cache_hits.load(Ordering::SeqCst);
        out_metrics.dirindex_cache_misses =
            self.metrics.dirindex_cache_misses.load(Ordering::SeqCst);
        out_metrics.dirindex_rebuilds = self.metrics.dirindex_rebuilds.load(Ordering::SeqCst);
        out_metrics.stamp_validations = self.metrics.stamp_validations.load(Ordering::SeqCst);
        out_metrics.collisions = self.metrics.collisions.load(Ordering::SeqCst);
        out_metrics.invalid_utf8_entries =
            self.metrics.invalid_utf8_entries.load(Ordering::SeqCst);
        out_metrics.encoding_errors = self.metrics.encoding_errors.load(Ordering::SeqCst);
        out_metrics.plans_rejected_stale =
            self.metrics.plans_rejected_stale.load(Ordering::SeqCst);
        out_metrics.reserved = [0; 4];
        ResolverStatus::Ok
    }
}
