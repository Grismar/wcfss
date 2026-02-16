use crate::common::types::*;
use crate::linux_emulation::parser;
use crate::resolver::Resolver;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

const MAX_INPUT_PATH_BYTES: usize = 32 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const SYMLINK_DEPTH_LIMIT: usize = 40;
fn trace(msg: &str) {
    eprintln!("[wcfss][linux] {msg}");
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

#[derive(Debug)]
enum EntrySet {
    Unique(String),
    Ambiguous(Vec<String>),
}

fn insert_entry(map: &mut HashMap<String, EntrySet>, key: String, name: String) {
    match map.get_mut(&key) {
        None => {
            map.insert(key, EntrySet::Unique(name));
        }
        Some(EntrySet::Unique(existing)) => {
            if existing != &name {
                let mut list = vec![existing.clone(), name];
                list.sort();
                list.dedup();
                *map.get_mut(&key).unwrap() = EntrySet::Ambiguous(list);
            }
        }
        Some(EntrySet::Ambiguous(list)) => {
            if !list.iter().any(|entry| entry == &name) {
                list.push(name);
                list.sort();
                list.dedup();
            }
        }
    }
}

fn build_dir_index(
    dir: &Path,
    strict_utf8: bool,
) -> Result<HashMap<String, EntrySet>, ResolverStatus> {
    trace(&format!("DirIndex build start: {}", dir.display()));
    let mut map: HashMap<String, EntrySet> = HashMap::new();
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
                insert_entry(&mut map, key, valid.to_string());
            }
            Err(_) => {
                invalid_utf8_count += 1;
                trace(&format!(
                    "DirIndex skip invalid UTF-8 entry: {:?} (dir {})",
                    name,
                    dir.display()
                ));
                if strict_utf8 {
                    return Err(ResolverStatus::EncodingError);
                }
            }
        }
    }
    trace(&format!(
        "DirIndex build complete: {} entries ({} invalid UTF-8 skipped)",
        entry_count, invalid_utf8_count
    ));
    Ok(map)
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

fn classify_root(normalized: &str) -> Result<Option<PathBuf>, ResolverStatus> {
    let trimmed = normalized.trim_start_matches('/');
    let leading = normalized.len() - trimmed.len();
    if leading >= 2 {
        let mut parts = trimmed.split('/').filter(|p| !p.is_empty());
        if parts.next().is_some() && parts.next().is_some() {
            trace("UNC-style path detected on Linux (unsupported).");
            return Err(ResolverStatus::UnsupportedAbsolutePath);
        }
    }

    if normalized.len() >= 2 {
        let bytes = normalized.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            if normalized.len() == 2 || !normalized.as_bytes()[2].eq(&b'/') {
                return Err(ResolverStatus::InvalidPath);
            }
            trace("Drive-letter path detected on Linux (unsupported).");
            return Err(ResolverStatus::UnsupportedAbsolutePath);
        }
    }

    if normalized.starts_with('/') {
        return Ok(Some(PathBuf::from("/")));
    }
    Ok(None)
}

#[derive(Debug)]
struct ResolvedInfo {
    path: PathBuf,
    target_exists: bool,
    target_is_dir: bool,
    would_create: bool,
    would_truncate: bool,
}

fn resolve_path_no_cache(
    base_dir: &Path,
    input_path: &str,
    intent: ResolverIntent,
    strict_utf8: bool,
) -> Result<ResolvedInfo, ResolverStatus> {
    if input_path.as_bytes().len() > MAX_INPUT_PATH_BYTES {
        return Err(ResolverStatus::PathTooLong);
    }

    let (normalized, had_backslash) = normalize_input(input_path);
    if had_backslash {
        trace("Input contained backslashes; normalized to forward slashes.");
    }

    let root = classify_root(&normalized)?;
    let mut current = root.unwrap_or_else(|| base_dir.to_path_buf());
    let mut stack: Vec<(PathBuf, bool)> = vec![(current.clone(), false)];

    let mut components: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
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

    for (idx, component) in components.iter().enumerate() {
        if *component == ".." {
            if stack.len() <= 1 {
                trace("Encountered .. at root boundary.");
                return Err(ResolverStatus::EscapesRoot);
            }
            let (_, was_symlink) = stack.pop().unwrap();
            if was_symlink {
                trace("Encountered .. across symlink boundary.");
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
        let exact_path = current.join(component);
        let exact_meta = fs::symlink_metadata(&exact_path);
        let (selected_name, selected_meta, missing_component) = match exact_meta {
            Ok(meta) => {
                trace("Exact match found.");
                (component.to_string(), meta, false)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                trace("Exact match not found; building temporary DirIndex.");
                let index = build_dir_index(&current, strict_utf8)?;
                let key = parser::key_simple_uppercase(component);
                match index.get(&key) {
                    None => {
                        trace("DirIndex had no match for component.");
                        if intent == ResolverIntent::Mkdirs {
                            let fake_meta =
                                fs::symlink_metadata(&current).map_err(|err| map_io_error(&err))?;
                            (component.to_string(), fake_meta, true)
                        } else {
                            return Err(ResolverStatus::NotFound);
                        }
                    }
                    Some(EntrySet::Ambiguous(list)) => {
                        trace(&format!("DirIndex collision for key '{}': {:?}", key, list));
                        return Err(ResolverStatus::Collision);
                    }
                    Some(EntrySet::Unique(actual)) => {
                        trace(&format!("DirIndex resolved to '{}'.", actual));
                        let path = current.join(actual);
                        let meta = fs::symlink_metadata(&path).map_err(|err| map_io_error(&err))?;
                        (actual.clone(), meta, false)
                    }
                }
            }
            Err(err) => {
                trace(&format!("Exact lookup error: {err}"));
                return Err(map_io_error(&err));
            }
        };

        let next_path = current.join(&selected_name);
        if !missing_component && selected_meta.file_type().is_symlink() {
            trace(&format!("Encountered symlink: {}", next_path.display()));
            let dev = selected_meta.dev();
            let ino = selected_meta.ino();
            if visited_symlinks.contains(&(dev, ino)) {
                trace("Symlink cycle detected.");
                return Err(ResolverStatus::TooManySymlinks);
            }
            if symlink_depth >= SYMLINK_DEPTH_LIMIT {
                trace("Symlink depth limit exceeded.");
                return Err(ResolverStatus::TooManySymlinks);
            }
            visited_symlinks.insert((dev, ino));
            symlink_depth += 1;
        }

        let is_last = idx + 1 == components.len();
        if !is_last {
            if missing_component {
                mkdirs_creates = true;
                trace("Intermediate component will be created for mkdirs.");
            } else {
                let meta = fs::metadata(&next_path).map_err(|err| map_io_error(&err))?;
                if !meta.is_dir() {
                    trace("Intermediate component is not a directory.");
                    return Err(ResolverStatus::NotADirectory);
                }
            }
            stack.push((
                next_path.clone(),
                !missing_component && selected_meta.file_type().is_symlink(),
            ));
            current = next_path;
            continue;
        }

        let meta_follow = if missing_component {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing leaf"))
        } else {
            fs::metadata(&next_path)
        };
        let (target_exists, target_is_dir) = match meta_follow {
            Ok(meta) => (true, meta.is_dir()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => (false, false),
            Err(err) => return Err(map_io_error(&err)),
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

pub struct LinuxResolver {
    strict_utf8: bool,
}

impl LinuxResolver {
    pub fn new(config: *const ResolverConfig) -> Self {
        // TODO(linux): initialize caches and Unicode tables.
        let strict_utf8 = unsafe { config.as_ref() }
            .map(|cfg| cfg.flags & RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY != 0)
            .unwrap_or(false);
        Self { strict_utf8 }
    }
}

impl Resolver for LinuxResolver {
    fn set_root_mapping(
        &self,
        _mapping: *const ResolverRootMapping,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): update root mapping table and generations.
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
        let base_dir = match string_view_to_string(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };

        trace(&format!(
            "Plan start: base_dir='{}', input_path='{}', intent={:?}",
            base_dir, input_path, intent
        ));

        let base_dir_path = match validate_base_dir(&base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        let plan_out = unsafe { out_plan.as_mut() };
        if plan_out.is_none() {
            return ResolverStatus::InvalidPath;
        }
        let plan_out = plan_out.unwrap();
        plan_out.size = std::mem::size_of::<ResolverPlan>() as u32;
        plan_out.reserved = [0; 8];

        match resolve_path_no_cache(&base_dir_path, &input_path, intent, self.strict_utf8) {
            Ok(info) => {
                trace(&format!(
                    "Plan resolved: path='{}', exists={}, is_dir={}, would_create={}, would_truncate={}",
                    info.path.display(),
                    info.target_exists,
                    info.target_is_dir,
                    info.would_create,
                    info.would_truncate
                ));
                ResolverStatus::Ok
            }
            Err(status) => status,
        }
    }

    fn execute_mkdirs(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let base_dir = match string_view_to_string(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir_path = match validate_base_dir(&base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        if let Some(out) = unsafe { out_result.as_mut() } {
            out.size = std::mem::size_of::<ResolverResult>() as u32;
            out.reserved = [0; 6];
        }

        let info = match resolve_path_no_cache(
            &base_dir_path,
            &input_path,
            ResolverIntent::Mkdirs,
            self.strict_utf8,
        ) {
            Ok(value) => value,
            Err(status) => return status,
        };

        if info.target_exists {
            return ResolverStatus::Ok;
        }

        trace(&format!(
            "execute_mkdirs creating path '{}'",
            info.path.display()
        ));
        if let Err(err) = fs::create_dir_all(&info.path) {
            return map_io_error(&err);
        }
        ResolverStatus::Ok
    }

    fn execute_rename(
        &self,
        _base_dir: *const ResolverStringView,
        _from_path: *const ResolverStringView,
        _to_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement rename/move with invalidation.
        ResolverStatus::IoError
    }

    fn execute_unlink(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let base_dir = match string_view_to_string(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir_path = match validate_base_dir(&base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        if let Some(out) = unsafe { out_result.as_mut() } {
            out.size = std::mem::size_of::<ResolverResult>() as u32;
            out.reserved = [0; 6];
        }

        let info = match resolve_path_no_cache(
            &base_dir_path,
            &input_path,
            ResolverIntent::Read,
            self.strict_utf8,
        ) {
            Ok(value) => value,
            Err(status) => return status,
        };
        if info.target_is_dir {
            return ResolverStatus::NotADirectory;
        }

        trace(&format!(
            "execute_unlink deleting '{}'",
            info.path.display()
        ));
        if let Err(err) = fs::remove_file(&info.path) {
            return map_io_error(&err);
        }
        ResolverStatus::Ok
    }

    fn execute_open_return_path(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_resolved_path: *mut ResolverResolvedPath,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let base_dir = match string_view_to_string(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir_path = match validate_base_dir(&base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        let info = match resolve_path_no_cache(
            &base_dir_path,
            &input_path,
            intent,
            self.strict_utf8,
        ) {
            Ok(value) => value,
            Err(status) => return status,
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
        ResolverStatus::Ok
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
            return ResolverStatus::InvalidPath;
        }
        let base_dir = match string_view_to_string(base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match string_view_to_string(input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let base_dir_path = match validate_base_dir(&base_dir) {
            Ok(value) => value,
            Err(status) => return status,
        };

        let info = match resolve_path_no_cache(
            &base_dir_path,
            &input_path,
            intent,
            self.strict_utf8,
        ) {
            Ok(value) => value,
            Err(status) => return status,
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
        let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o666) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return map_io_error(&err);
        }
        unsafe {
            *out_fd = fd;
        }
        ResolverStatus::Ok
    }

    fn execute_from_plan(
        &self,
        _plan: *const ResolverPlan,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): validate plan token and execute.
        ResolverStatus::IoError
    }

    fn get_metrics(&self, _out_metrics: *mut ResolverMetrics) -> ResolverStatus {
        // TODO(linux): populate metrics counters.
        ResolverStatus::Ok
    }
}
