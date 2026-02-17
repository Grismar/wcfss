use crate::common::types::*;
use crate::resolver::Resolver;

use core::ffi::c_char;
use super::win32;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
};

const MAX_INPUT_PATH_BYTES: usize = 32 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;

pub struct WindowsResolver {
    _private: (),
    metrics: MetricsCounters,
    generations: RwLock<ResolverGenerations>,
    op_generation: AtomicU64,
    mutation_lock: Mutex<()>,
    dir_generations: RwLock<HashMap<(u64, u64), u64>>,
}

impl WindowsResolver {
    pub fn new(_config: *const ResolverConfig) -> Self {
        // TODO(windows): parse config, initialize native state.
        let generations = ResolverGenerations {
            unicode_version_generation: 1,
            root_mapping_generation: 0,
            absolute_path_support_generation: 1,
            encoding_policy_generation: 0,
            symlink_policy_generation: 0,
        };
        Self {
            _private: (),
            metrics: MetricsCounters::default(),
            generations: RwLock::new(generations),
            op_generation: AtomicU64::new(0),
            mutation_lock: Mutex::new(()),
            dir_generations: RwLock::new(HashMap::new()),
        }
    }

    fn begin_execute(&self) {
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
        if let Ok(dir_id) = win32::get_file_id(path) {
            let generation = self.current_dir_generation(dir_id);
            plan_trace.record(dir_id, generation);
        }
    }

    fn bump_dir_generations_for_paths(&self, paths: &[PathBuf]) {
        let mut dir_ids = Vec::new();
        for path in paths {
            if let Ok(dir_id) = win32::get_file_id(path) {
                dir_ids.push(dir_id);
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

fn status_invalid_ptr() -> ResolverStatus {
    ResolverStatus::InvalidPath
}

unsafe fn string_view_to_string(view: *const ResolverStringView) -> Result<String, ResolverStatus> {
    let view = view.as_ref().ok_or(status_invalid_ptr())?;
    if view.ptr.is_null() && view.len != 0 {
        return Err(status_invalid_ptr());
    }
    let bytes = std::slice::from_raw_parts(view.ptr as *const u8, view.len);
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

fn validate_base_dir(base_dir: &str) -> Result<(), ResolverStatus> {
    use std::path::{Component, Prefix};

    let path = Path::new(base_dir);
    if !path.is_absolute() {
        return Err(ResolverStatus::BaseDirInvalid);
    }

    let mut has_prefix = false;
    let mut has_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                has_prefix = true;
                match prefix.kind() {
                    Prefix::Disk(_) | Prefix::UNC(_, _) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => {}
                    _ => return Err(ResolverStatus::BaseDirInvalid),
                }
            }
            Component::RootDir => has_root = true,
            _ => {}
        }
    }

    if has_root && !has_prefix {
        return Err(ResolverStatus::BaseDirInvalid);
    }

    let attrs = win32::get_file_attributes(path).map_err(|_| ResolverStatus::BaseDirInvalid)?;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
        return Err(ResolverStatus::BaseDirInvalid);
    }
    Ok(())
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

#[derive(Debug, Default)]
struct PlanTrace {
    dir_generations: HashMap<(u64, u64), u64>,
}

impl PlanTrace {
    fn record(&mut self, dir_id: (u64, u64), generation: u64) {
        self.dir_generations.entry(dir_id).or_insert(generation);
    }
}

#[derive(Debug, Clone, Copy)]
struct ResolverGenerations {
    unicode_version_generation: u64,
    root_mapping_generation: u64,
    absolute_path_support_generation: u64,
    encoding_policy_generation: u64,
    symlink_policy_generation: u64,
}

fn is_create_intent(intent: ResolverIntent) -> bool {
    matches!(
        intent,
        ResolverIntent::WriteTruncate
            | ResolverIntent::WriteAppend
            | ResolverIntent::CreateNew
            | ResolverIntent::Rename
    )
}

#[derive(Debug, Clone)]
enum ParsedComponent {
    Parent,
    Normal(OsString),
}

fn is_symlink_attr(attrs: u32) -> bool {
    (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
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

fn resolve_base_and_components(
    base_dir: &str,
    input_path: &str,
) -> Result<(PathBuf, Vec<ParsedComponent>), ResolverStatus> {
    let input = input_path.replace('/', "\\");
    let path = Path::new(&input);

    let mut components: Vec<ParsedComponent> = Vec::new();
    let mut prefix: Option<OsString> = None;
    let mut has_root = false;
    let mut component_count = 0usize;
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix_component) => {
                prefix = Some(prefix_component.as_os_str().to_os_string())
            }
            std::path::Component::RootDir => {
                has_root = true;
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.push(ParsedComponent::Parent);
                component_count += 1;
                if component_count > MAX_COMPONENTS {
                    return Err(ResolverStatus::PathTooLong);
                }
            }
            std::path::Component::Normal(name) => {
                let name_str = name.to_string_lossy();
                if name_str.as_bytes().len() > MAX_COMPONENT_BYTES {
                    return Err(ResolverStatus::PathTooLong);
                }
                components.push(ParsedComponent::Normal(name.to_os_string()));
                component_count += 1;
                if component_count > MAX_COMPONENTS {
                    return Err(ResolverStatus::PathTooLong);
                }
            }
        }
    }

    if prefix.is_some() && !path.is_absolute() {
        return Err(ResolverStatus::InvalidPath);
    }

    let start = if path.is_absolute() {
        match (prefix, has_root) {
            (Some(prefix), true) => {
                let mut prefix_str = prefix.to_string_lossy().into_owned();
                prefix_str.push('\\');
                PathBuf::from(prefix_str)
            }
            (Some(prefix), false) => PathBuf::from(prefix),
            (None, true) => PathBuf::from("\\"),
            (None, false) => PathBuf::from(path),
        }
    } else {
        PathBuf::from(base_dir)
    };

    Ok((start, components))
}

fn resolve_final(
    resolver: &WindowsResolver,
    parent: &Path,
    leaf: &OsString,
    intent: ResolverIntent,
    mut diag: Option<&mut DiagCollector>,
    mut plan_trace: Option<&mut PlanTrace>,
) -> Result<OsString, ResolverStatus> {
    if let Some(plan_trace) = plan_trace.as_deref_mut() {
        resolver.record_dir_generation_for_path(parent, plan_trace);
    }
    let match_result = match win32::find_match(parent, leaf) {
        Ok(value) => value,
        Err(status) => {
            if status == ResolverStatus::PermissionDenied {
                if let Some(diag) = diag.as_deref_mut() {
                    diag.push(
                        ResolverDiagCode::PermissionDenied,
                        ResolverDiagSeverity::Error,
                        parent.display().to_string(),
                        "permission denied listing directory".to_string(),
                    );
                }
            }
            return Err(status);
        }
    };
    if match_result.count > 1 {
        resolver.metrics.collisions.fetch_add(1, Ordering::SeqCst);
        if let Some(diag) = diag.as_deref_mut() {
            diag.push(
                ResolverDiagCode::Collision,
                ResolverDiagSeverity::Error,
                parent.display().to_string(),
                leaf.to_string_lossy().into_owned(),
            );
        }
        return Err(ResolverStatus::Collision);
    }
    if match_result.count == 1 {
        if intent == ResolverIntent::CreateNew {
            return Err(ResolverStatus::Exists);
        }
        return Ok(match_result.unique_name.unwrap_or_else(|| leaf.clone()));
    }

    if is_create_intent(intent) || intent == ResolverIntent::Mkdirs {
        Ok(leaf.clone())
    } else {
        Err(ResolverStatus::NotFound)
    }
}

fn resolve_path_for_intent(
    resolver: &WindowsResolver,
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
    mut diag: Option<&mut DiagCollector>,
    mut plan_trace: Option<&mut PlanTrace>,
) -> Result<PathBuf, ResolverStatus> {
    let (start, components) = resolve_base_and_components(base_dir, input_path)?;
    if components.is_empty() {
        if let Some(plan_trace) = plan_trace.as_deref_mut() {
            resolver.record_dir_generation_for_path(&start, plan_trace);
        }
        return Ok(start);
    }

    let mut current = start;
    let mut stack: Vec<(PathBuf, bool)> = vec![(current.clone(), false)];
    for (idx, component) in components.iter().enumerate() {
        match component {
            ParsedComponent::Parent => {
                if stack.len() <= 1 {
                    return Err(ResolverStatus::EscapesRoot);
                }
                let (_, was_symlink) = stack.pop().unwrap();
                if was_symlink {
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
            }
            ParsedComponent::Normal(name) => {
                let is_last = idx + 1 == components.len();
                if is_last {
                    let leaf_name = resolve_final(
                        resolver,
                        &current,
                        name,
                        intent,
                        diag.as_deref_mut(),
                        plan_trace.as_deref_mut(),
                    )?;
                    return Ok(win32::join_path(&current, &leaf_name));
                }
                if let Some(plan_trace) = plan_trace.as_deref_mut() {
                    resolver.record_dir_generation_for_path(&current, plan_trace);
                }
                let match_result = match win32::find_match(&current, name) {
                    Ok(value) => value,
                    Err(status) => {
                        if status == ResolverStatus::PermissionDenied {
                            if let Some(diag) = diag.as_deref_mut() {
                                diag.push(
                                    ResolverDiagCode::PermissionDenied,
                                    ResolverDiagSeverity::Error,
                                    current.display().to_string(),
                                    "permission denied listing directory".to_string(),
                                );
                            }
                        }
                        return Err(status);
                    }
                };
                if match_result.count == 0 {
                    return Err(ResolverStatus::NotFound);
                }
                if match_result.count > 1 {
                    resolver.metrics.collisions.fetch_add(1, Ordering::SeqCst);
                    if let Some(diag) = diag.as_deref_mut() {
                        diag.push(
                            ResolverDiagCode::Collision,
                            ResolverDiagSeverity::Error,
                            current.display().to_string(),
                            name.to_string_lossy().into_owned(),
                        );
                    }
                    return Err(ResolverStatus::Collision);
                }
                let actual = match_result.unique_name.unwrap_or_else(|| name.clone());
                if (match_result.unique_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    return Err(ResolverStatus::NotADirectory);
                }
                let next_path = win32::join_path(&current, &actual);
                stack.push((next_path.clone(), is_symlink_attr(match_result.unique_attrs)));
                current = next_path;
            }
        }
    }

    Ok(current)
}

fn resolve_parent_and_leaf(
    resolver: &WindowsResolver,
    base_dir: &str,
    input_path: &str,
    mut diag: Option<&mut DiagCollector>,
) -> Result<(PathBuf, OsString), ResolverStatus> {
    let (start, components) = resolve_base_and_components(base_dir, input_path)?;
    if components.is_empty() {
        return Err(ResolverStatus::InvalidPath);
    }

    let mut current = start;
    let mut stack: Vec<(PathBuf, bool)> = vec![(current.clone(), false)];
    for (idx, component) in components.iter().enumerate() {
        let is_last = idx + 1 == components.len();
        match component {
            ParsedComponent::Parent => {
                if is_last {
                    return Err(ResolverStatus::InvalidPath);
                }
                if stack.len() <= 1 {
                    return Err(ResolverStatus::EscapesRoot);
                }
                let (_, was_symlink) = stack.pop().unwrap();
                if was_symlink {
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
            }
            ParsedComponent::Normal(name) => {
                if is_last {
                    return Ok((current, name.clone()));
                }
                let match_result = match win32::find_match(&current, name) {
                    Ok(value) => value,
                    Err(status) => {
                        if status == ResolverStatus::PermissionDenied {
                            if let Some(diag) = diag.as_deref_mut() {
                                diag.push(
                                    ResolverDiagCode::PermissionDenied,
                                    ResolverDiagSeverity::Error,
                                    current.display().to_string(),
                                    "permission denied listing directory".to_string(),
                                );
                            }
                        }
                        return Err(status);
                    }
                };
                if match_result.count == 0 {
                    return Err(ResolverStatus::NotFound);
                }
                if match_result.count > 1 {
                    resolver.metrics.collisions.fetch_add(1, Ordering::SeqCst);
                    if let Some(diag) = diag.as_deref_mut() {
                        diag.push(
                            ResolverDiagCode::Collision,
                            ResolverDiagSeverity::Error,
                            current.display().to_string(),
                            name.to_string_lossy().into_owned(),
                        );
                    }
                    return Err(ResolverStatus::Collision);
                }
                let actual = match_result.unique_name.unwrap_or_else(|| name.clone());
                if (match_result.unique_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    return Err(ResolverStatus::NotADirectory);
                }
                let next_path = win32::join_path(&current, &actual);
                stack.push((next_path.clone(), is_symlink_attr(match_result.unique_attrs)));
                current = next_path;
            }
        }
    }

    Err(ResolverStatus::InvalidPath)
}

fn map_io_error(err: &std::io::Error) -> ResolverStatus {
    if let Some(code) = err.raw_os_error() {
        return win32::map_win32_error(code as u32);
    }
    ResolverStatus::IoError
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

fn write_resolved_path(
    path: &Path,
    out_resolved_path: *mut ResolverResolvedPath,
) -> ResolverStatus {
    let out_resolved_path = unsafe { out_resolved_path.as_mut() };
    let out_resolved_path = match out_resolved_path {
        Some(out) => out,
        None => return status_invalid_ptr(),
    };

    let utf8 = path.to_string_lossy();
    let bytes = utf8.as_bytes();
    if bytes.is_empty() {
        out_resolved_path.value.ptr = std::ptr::null();
        out_resolved_path.value.len = 0;
        return ResolverStatus::Ok;
    }
    let ptr = unsafe { libc::malloc(bytes.len()) } as *mut u8;
    if ptr.is_null() {
        return ResolverStatus::IoError;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    out_resolved_path.value.ptr = ptr as *const core::ffi::c_char;
    out_resolved_path.value.len = bytes.len();
    // Caller must release via resolver_free_string.
    ResolverStatus::Ok
}

impl Resolver for WindowsResolver {
    fn set_root_mapping(
        &self,
        _mapping: *const ResolverRootMapping,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(windows): apply root mapping (optional feature).
        ResolverStatus::UnsupportedAbsolutePath
    }

    fn plan(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_plan: *mut ResolverPlan,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let mut diag = DiagCollector::default();
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if input_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if let Err(status) = validate_base_dir(&base_dir) {
            write_diag_entries(_out_diag, &diag);
            return status;
        }

        let plan_out = unsafe { out_plan.as_mut() };
        let mut plan_trace = PlanTrace::default();

        let status = match resolve_path_for_intent(
            self,
            &base_dir,
            &input_path,
            intent,
            Some(&mut diag),
            Some(&mut plan_trace),
        ) {
            Ok(path) => {
                let meta = std::fs::metadata(&path);
                let (target_exists, target_is_dir) = match meta {
                    Ok(meta) => (true, meta.is_dir()),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (false, false),
                    Err(_) => return ResolverStatus::IoError,
                };
                let mut flags = 0u32;
                if target_exists {
                    flags |= RESOLVER_PLAN_TARGET_EXISTS;
                }
                if target_is_dir {
                    flags |= RESOLVER_PLAN_TARGET_IS_DIR;
                }
                let mut would_create = false;
                let mut would_truncate = false;
                match intent {
                    ResolverIntent::Read | ResolverIntent::StatExists => {}
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
                        if !target_exists {
                            would_create = true;
                        }
                    }
                    ResolverIntent::Mkdirs => {
                        if !target_exists {
                            would_create = true;
                        }
                    }
                    ResolverIntent::Rename => {}
                }
                if would_create {
                    flags |= RESOLVER_PLAN_WOULD_CREATE;
                }
                if would_truncate {
                    flags |= RESOLVER_PLAN_WOULD_TRUNCATE;
                }
                if let Some(plan_out) = plan_out {
                    init_plan(plan_out);
                    plan_out.flags = flags;
                    plan_out.status = ResolverStatus::Ok;
                    plan_out.would_error = ResolverStatus::Ok;
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
                    if let Err(status) = write_plan_dir_generations(plan_out, &plan_trace) {
                        plan_out.status = status;
                        plan_out.would_error = status;
                        write_diag_entries(_out_diag, &diag);
                        return status;
                    }
                    if let Err(status) = set_plan_paths(plan_out, &path) {
                        plan_out.status = status;
                        plan_out.would_error = status;
                        return status;
                    }
                }
                ResolverStatus::Ok
            }
            Err(status) => {
                if let Some(plan_out) = plan_out {
                    init_plan(plan_out);
                    plan_out.status = status;
                    plan_out.would_error = status;
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
                }
                status
            }
        };
        write_diag_entries(_out_diag, &diag);
        status
    }

    fn execute_mkdirs(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let mut diag = DiagCollector::default();
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if input_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if let Err(status) = validate_base_dir(&base_dir) {
            write_diag_entries(_out_diag, &diag);
            return status;
        }

        let (start, components) = match resolve_base_and_components(&base_dir, &input_path) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        let mut current = start;
        let mut stack: Vec<(PathBuf, bool)> = vec![(current.clone(), false)];
        for component in components {
            match component {
                ParsedComponent::Parent => {
                    if stack.len() <= 1 {
                        write_diag_entries(_out_diag, &diag);
                        return ResolverStatus::EscapesRoot;
                    }
                    let (_, was_symlink) = stack.pop().unwrap();
                    if was_symlink {
                        diag.push(
                            ResolverDiagCode::SymlinkLoop,
                            ResolverDiagSeverity::Error,
                            current.display().to_string(),
                            "path traversed across symlink boundary".to_string(),
                        );
                        write_diag_entries(_out_diag, &diag);
                        return ResolverStatus::InvalidPath;
                    }
                    current = stack.last().unwrap().0.clone();
                }
                ParsedComponent::Normal(name) => {
                    let match_result = match win32::find_match(&current, &name) {
                        Ok(value) => value,
                        Err(status) => {
                            if status == ResolverStatus::PermissionDenied {
                                diag.push(
                                    ResolverDiagCode::PermissionDenied,
                                    ResolverDiagSeverity::Error,
                                    current.display().to_string(),
                                    "permission denied listing directory".to_string(),
                                );
                            }
                            write_diag_entries(_out_diag, &diag);
                            return status;
                        }
                    };
                    if match_result.count > 1 {
                        self.metrics.collisions.fetch_add(1, Ordering::SeqCst);
                        diag.push(
                            ResolverDiagCode::Collision,
                            ResolverDiagSeverity::Error,
                            current.display().to_string(),
                            name.to_string_lossy().into_owned(),
                        );
                        write_diag_entries(_out_diag, &diag);
                        return ResolverStatus::Collision;
                    }
                    if match_result.count == 1 {
                        let actual = match_result.unique_name.unwrap_or(name.clone());
                        if (match_result.unique_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                            write_diag_entries(_out_diag, &diag);
                            return ResolverStatus::NotADirectory;
                        }
                        let next_path = win32::join_path(&current, &actual);
                        stack.push((next_path.clone(), is_symlink_attr(match_result.unique_attrs)));
                        current = next_path;
                        continue;
                    }
                    let next_path = win32::join_path(&current, &name);
                    self.bump_dir_generations_for_paths(&[current.clone()]);
                    if let Err(status) = win32::create_directory(&next_path) {
                        if status == ResolverStatus::PermissionDenied {
                            diag.push(
                                ResolverDiagCode::PermissionDenied,
                                ResolverDiagSeverity::Error,
                                next_path.display().to_string(),
                                "permission denied creating directory".to_string(),
                            );
                        }
                        write_diag_entries(_out_diag, &diag);
                        return status;
                    }
                    current = next_path;
                    stack.push((current.clone(), false));
                }
            }
        }
        write_diag_entries(_out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_rename(
        &self,
        base_dir: *const ResolverStringView,
        from_path: *const ResolverStringView,
        to_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let mut diag = DiagCollector::default();
        let from_path = match unsafe { string_view_to_string(from_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        let to_path = match unsafe { string_view_to_string(to_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if from_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                from_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        if to_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                to_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if let Err(status) = validate_base_dir(&base_dir) {
            write_diag_entries(_out_diag, &diag);
            return status;
        }

        let src = match resolve_path_for_intent(
            self,
            &base_dir,
            &from_path,
            ResolverIntent::Read,
            Some(&mut diag),
            None,
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };

        let (parent, leaf) = match resolve_parent_and_leaf(
            self,
            &base_dir,
            &to_path,
            Some(&mut diag),
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        let leaf_name = match resolve_final(
            self,
            &parent,
            &leaf,
            ResolverIntent::Rename,
            Some(&mut diag),
            None,
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        let dst = win32::join_path(&parent, &leaf_name);
        let mut parents = Vec::new();
        if let Some(parent) = src.parent() {
            parents.push(parent.to_path_buf());
        }
        if let Some(parent) = dst.parent() {
            parents.push(parent.to_path_buf());
        }
        self.bump_dir_generations_for_paths(&parents);
        let status = match win32::move_file_replace(&src, &dst) {
            Ok(()) => ResolverStatus::Ok,
            Err(status) => status,
        };
        if status == ResolverStatus::PermissionDenied {
            diag.push(
                ResolverDiagCode::PermissionDenied,
                ResolverDiagSeverity::Error,
                src.display().to_string(),
                "permission denied renaming".to_string(),
            );
        }
        write_diag_entries(_out_diag, &diag);
        status
    }

    fn execute_unlink(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let mut diag = DiagCollector::default();
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if input_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if let Err(status) = validate_base_dir(&base_dir) {
            write_diag_entries(_out_diag, &diag);
            return status;
        }
        let path = match resolve_path_for_intent(
            self,
            &base_dir,
            &input_path,
            ResolverIntent::Read,
            Some(&mut diag),
            None,
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        match win32::get_file_attributes(&path) {
            Ok(attrs) if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 => {
                write_diag_entries(_out_diag, &diag);
                return ResolverStatus::NotADirectory;
            }
            Ok(_) => {}
            Err(status) => {
                if status == ResolverStatus::PermissionDenied {
                    diag.push(
                        ResolverDiagCode::PermissionDenied,
                        ResolverDiagSeverity::Error,
                        path.display().to_string(),
                        "permission denied reading attributes".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        }
        if let Some(parent) = path.parent() {
            self.bump_dir_generations_for_paths(&[parent.to_path_buf()]);
        }
        let status = match win32::delete_file(&path) {
            Ok(()) => ResolverStatus::Ok,
            Err(status) => status,
        };
        if status == ResolverStatus::PermissionDenied {
            diag.push(
                ResolverDiagCode::PermissionDenied,
                ResolverDiagSeverity::Error,
                path.display().to_string(),
                "permission denied removing file".to_string(),
            );
        }
        write_diag_entries(_out_diag, &diag);
        status
    }

    fn execute_open_return_path(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_resolved_path: *mut ResolverResolvedPath,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        self.begin_execute();
        let mut diag = DiagCollector::default();
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if input_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if let Err(status) = validate_base_dir(&base_dir) {
            write_diag_entries(_out_diag, &diag);
            return status;
        }
        let resolved = match resolve_path_for_intent(
            self,
            &base_dir,
            &input_path,
            intent,
            Some(&mut diag),
            None,
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        let status = write_resolved_path(&resolved, out_resolved_path);
        write_diag_entries(_out_diag, &diag);
        status
    }

    fn execute_open_return_fd(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_fd: *mut i32,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        if out_fd.is_null() {
            return status_invalid_ptr();
        }
        self.begin_execute();
        let mut diag = DiagCollector::default();
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => {
                if status == ResolverStatus::EncodingError {
                    self.metrics.encoding_errors.fetch_add(1, Ordering::SeqCst);
                    diag.push(
                        ResolverDiagCode::EncodingError,
                        ResolverDiagSeverity::Error,
                        "".to_string(),
                        "invalid UTF-8 input".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if input_path.contains('/') {
            diag.push(
                ResolverDiagCode::BackslashNormalized,
                ResolverDiagSeverity::Warning,
                input_path.clone(),
                "input contained forward slashes".to_string(),
            );
        }
        let base_dir = match base_dir_from_view(base_dir) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        if let Err(status) = validate_base_dir(&base_dir) {
            write_diag_entries(_out_diag, &diag);
            return status;
        }
        let resolved = match resolve_path_for_intent(
            self,
            &base_dir,
            &input_path,
            intent,
            Some(&mut diag),
            None,
        ) {
            Ok(value) => value,
            Err(status) => {
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };
        let open_intent = match intent {
            ResolverIntent::Read => win32::OpenIntent::Read,
            ResolverIntent::WriteTruncate => win32::OpenIntent::WriteTruncate,
            ResolverIntent::WriteAppend => win32::OpenIntent::WriteAppend,
            ResolverIntent::CreateNew => win32::OpenIntent::CreateNew,
            ResolverIntent::StatExists => win32::OpenIntent::Stat,
            ResolverIntent::Mkdirs | ResolverIntent::Rename => {
                return ResolverStatus::InvalidPath;
            }
        };

        let mut would_create = matches!(
            intent,
            ResolverIntent::WriteAppend | ResolverIntent::WriteTruncate | ResolverIntent::CreateNew
        );
        if would_create {
            match win32::get_file_attributes(&resolved) {
                Ok(_) => {
                    would_create = false;
                }
                Err(status) if status == ResolverStatus::NotFound => {}
                Err(status) => {
                    if status == ResolverStatus::PermissionDenied {
                        diag.push(
                            ResolverDiagCode::PermissionDenied,
                            ResolverDiagSeverity::Error,
                            resolved.display().to_string(),
                            "permission denied reading attributes".to_string(),
                        );
                    }
                    write_diag_entries(_out_diag, &diag);
                    return status;
                }
            }
        }
        if would_create {
            if let Some(parent) = resolved.parent() {
                self.bump_dir_generations_for_paths(&[parent.to_path_buf()]);
            }
        }

        let handle = match win32::open_file(&resolved, open_intent) {
            Ok(handle) if handle != INVALID_HANDLE_VALUE => handle,
            Ok(_) => {
                write_diag_entries(_out_diag, &diag);
                return ResolverStatus::IoError;
            }
            Err(status) => {
                if status == ResolverStatus::PermissionDenied {
                    diag.push(
                        ResolverDiagCode::PermissionDenied,
                        ResolverDiagSeverity::Error,
                        resolved.display().to_string(),
                        "permission denied opening file".to_string(),
                    );
                }
                write_diag_entries(_out_diag, &diag);
                return status;
            }
        };

        let flags = match intent {
            ResolverIntent::Read | ResolverIntent::StatExists => libc::O_RDONLY,
            ResolverIntent::WriteAppend => libc::O_WRONLY | libc::O_APPEND,
            ResolverIntent::WriteTruncate | ResolverIntent::CreateNew => libc::O_WRONLY,
            ResolverIntent::Mkdirs | ResolverIntent::Rename => libc::O_RDONLY,
        };

        let fd = unsafe { libc::open_osfhandle(handle as isize, flags) };
        if fd == -1 {
            unsafe {
                CloseHandle(handle);
            }
            write_diag_entries(_out_diag, &diag);
            return ResolverStatus::IoError;
        }

        unsafe {
            *out_fd = fd;
        }
        write_diag_entries(_out_diag, &diag);
        ResolverStatus::Ok
    }

    fn execute_from_plan(
        &self,
        _plan: *const ResolverPlan,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let plan = unsafe { _plan.as_ref() }.ok_or(ResolverStatus::InvalidPath);
        let plan = match plan {
            Ok(value) => value,
            Err(status) => return status,
        };

        let mut diag = DiagCollector::default();

        let _guard = self.mutation_lock.lock().expect("mutation_lock poisoned");

        let expected_token_size = std::mem::size_of::<ResolverPlanToken>() as u32;
        let expected_plan_size = std::mem::size_of::<ResolverPlan>() as u32;
        if plan.size < expected_plan_size || plan.plan_token.size < expected_token_size {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(_out_diag, &diag);
            return ResolverStatus::StalePlan;
        }

        let current = self.op_generation.load(Ordering::SeqCst);
        if plan.plan_token.op_generation != current {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(_out_diag, &diag);
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
                write_diag_entries(_out_diag, &diag);
                return ResolverStatus::StalePlan;
            }
        }

        let dir_view = plan.plan_token.dir_generations;
        if dir_view.len > 0 && dir_view.ptr.is_null() {
            self.metrics
                .plans_rejected_stale
                .fetch_add(1, Ordering::SeqCst);
            write_diag_entries(_out_diag, &diag);
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
                    write_diag_entries(_out_diag, &diag);
                    return ResolverStatus::StalePlan;
                }
            }
        }

        // Increment at the start of the mutation phase (before any filesystem mutation).
        self.op_generation.fetch_add(1, Ordering::SeqCst);

        let parent =
            match unsafe { string_view_to_string(&plan.resolved_parent as *const ResolverStringView) }
            {
                Ok(value) => value,
                Err(status) => {
                    write_diag_entries(_out_diag, &diag);
                    return status;
                }
            };
        let leaf =
            match unsafe { string_view_to_string(&plan.resolved_leaf as *const ResolverStringView) }
            {
                Ok(value) => value,
                Err(status) => {
                    write_diag_entries(_out_diag, &diag);
                    return status;
                }
            };
        let mut path = PathBuf::from(parent);
        if !leaf.is_empty() {
            path = path.join(leaf);
        }

        let intent = plan.intent;
        let status = match intent {
            ResolverIntent::StatExists | ResolverIntent::Read => {
                match win32::get_file_attributes(&path) {
                    Ok(_) => ResolverStatus::Ok,
                    Err(status) => status,
                }
            }
            ResolverIntent::Mkdirs => {
                let mut parents = Vec::new();
                for ancestor in path.ancestors().skip(1) {
                    parents.push(ancestor.to_path_buf());
                }
                self.bump_dir_generations_for_paths(&parents);
                match std::fs::create_dir_all(&path) {
                    Ok(_) => ResolverStatus::Ok,
                    Err(err) => map_io_error(&err),
                }
            }
            ResolverIntent::WriteTruncate
            | ResolverIntent::WriteAppend
            | ResolverIntent::CreateNew => {
                if (plan.flags & RESOLVER_PLAN_WOULD_CREATE) != 0 {
                    if let Some(parent) = path.parent() {
                        self.bump_dir_generations_for_paths(&[parent.to_path_buf()]);
                    }
                }
                let open_intent = match intent {
                    ResolverIntent::WriteAppend => win32::OpenIntent::WriteAppend,
                    ResolverIntent::WriteTruncate => win32::OpenIntent::WriteTruncate,
                    ResolverIntent::CreateNew => win32::OpenIntent::CreateNew,
                    _ => win32::OpenIntent::Read,
                };
                match win32::open_file(&path, open_intent) {
                    Ok(handle) if handle != INVALID_HANDLE_VALUE => {
                        unsafe {
                            CloseHandle(handle);
                        }
                        ResolverStatus::Ok
                    }
                    Ok(_) => ResolverStatus::IoError,
                    Err(status) => status,
                }
            }
            ResolverIntent::Rename => ResolverStatus::InvalidPath,
        };

        if status == ResolverStatus::PermissionDenied {
            diag.push(
                ResolverDiagCode::PermissionDenied,
                ResolverDiagSeverity::Error,
                path.display().to_string(),
                "permission denied executing plan".to_string(),
            );
        }
        write_diag_entries(_out_diag, &diag);
        status
    }

    fn get_metrics(&self, _out_metrics: *mut ResolverMetrics) -> ResolverStatus {
        let out_metrics = unsafe { _out_metrics.as_mut() };
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
