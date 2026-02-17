use crate::common::types::*;
use crate::resolver::Resolver;

use core::ffi::c_char;
use super::win32;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;

pub struct WindowsResolver {
    _private: (),
}

impl WindowsResolver {
    pub fn new(_config: *const ResolverConfig) -> Self {
        // TODO(windows): parse config, initialize native state.
        Self { _private: () }
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
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| ResolverStatus::EncodingError)
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

fn resolve_base_and_components(
    base_dir: &str,
    input_path: &str,
) -> Result<(PathBuf, Vec<OsString>), ResolverStatus> {
    let input = input_path.replace('/', "\\");
    let path = Path::new(&input);

    let mut components: Vec<OsString> = Vec::new();
    let mut prefix: Option<OsString> = None;
    let mut has_root = false;
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
                if components.is_empty() {
                    return Err(ResolverStatus::EscapesRoot);
                }
                components.pop();
            }
            std::path::Component::Normal(name) => components.push(name.to_os_string()),
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

fn resolve_intermediate(
    mut current: PathBuf,
    components: &[OsString],
) -> Result<PathBuf, ResolverStatus> {
    for component in components {
        let match_result = win32::find_match(&current, component)?;
        if match_result.count == 0 {
            return Err(ResolverStatus::NotFound);
        }
        if match_result.count > 1 {
            return Err(ResolverStatus::Collision);
        }
        let name = match_result.unique_name.ok_or(ResolverStatus::NotFound)?;
        if (match_result.unique_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
            return Err(ResolverStatus::NotADirectory);
        }
        current = win32::join_path(&current, &name);
    }
    Ok(current)
}

fn resolve_final(
    parent: &Path,
    leaf: &OsString,
    intent: ResolverIntent,
) -> Result<OsString, ResolverStatus> {
    let match_result = win32::find_match(parent, leaf)?;
    if match_result.count > 1 {
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

fn resolve_absolute_path(path: &Path, intent: ResolverIntent) -> Result<PathBuf, ResolverStatus> {
    let parent = match path.parent() {
        Some(parent) => parent,
        None => return Ok(PathBuf::from(path)),
    };

    let attrs = win32::get_file_attributes(parent)?;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
        return Err(ResolverStatus::NotADirectory);
    }

    let leaf = match path.file_name() {
        Some(name) => name.to_os_string(),
        None => return Ok(PathBuf::from(path)),
    };

    let leaf_name = resolve_final(parent, &leaf, intent)?;
    Ok(win32::join_path(parent, &leaf_name))
}

fn resolve_path_for_intent(
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
) -> Result<PathBuf, ResolverStatus> {
    let normalized = input_path.replace('/', "\\");
    let path = Path::new(&normalized);
    if path.is_absolute() {
        return resolve_absolute_path(path, intent);
    }

    let (start, components) = resolve_base_and_components(base_dir, &normalized)?;
    if components.is_empty() {
        return Ok(start);
    }
    let (intermediate, leaf) = components.split_at(components.len() - 1);
    let parent = resolve_intermediate(start, intermediate)?;
    let leaf_name = resolve_final(&parent, &leaf[0], intent)?;
    Ok(win32::join_path(&parent, &leaf_name))
}

fn init_plan(plan: &mut ResolverPlan) {
    plan.size = std::mem::size_of::<ResolverPlan>() as u32;
    plan.status = ResolverStatus::Ok;
    plan.would_error = ResolverStatus::Ok;
    plan.flags = 0;
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
        reserved: [0; 6],
    };
    plan.reserved = [0; 6];
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
        let base_dir = match unsafe { string_view_to_string(base_dir) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        let plan_out = unsafe { out_plan.as_mut() };

        match resolve_path_for_intent(&base_dir, &input_path, intent) {
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
                    plan_out.plan_token.op_generation = 0;
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
                    plan_out.plan_token.op_generation = 0;
                }
                status
            }
        }
    }

    fn execute_mkdirs(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let base_dir = match unsafe { string_view_to_string(base_dir) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        let (start, components) = match resolve_base_and_components(&base_dir, &input_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let mut current = start;
        for component in components {
            let match_result = match win32::find_match(&current, &component) {
                Ok(value) => value,
                Err(status) => return status,
            };
            if match_result.count > 1 {
                return ResolverStatus::Collision;
            }
            if match_result.count == 1 {
                let name = match_result.unique_name.unwrap_or(component.clone());
                if (match_result.unique_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    return ResolverStatus::NotADirectory;
                }
                current = win32::join_path(&current, &name);
                continue;
            }
            let next_path = win32::join_path(&current, &component);
            if let Err(status) = win32::create_directory(&next_path) {
                return status;
            }
            current = next_path;
        }
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
        let base_dir = match unsafe { string_view_to_string(base_dir) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let from_path = match unsafe { string_view_to_string(from_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let to_path = match unsafe { string_view_to_string(to_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        let src = match resolve_path_for_intent(&base_dir, &from_path, ResolverIntent::Read) {
            Ok(value) => value,
            Err(status) => return status,
        };

        let (dst_base, dst_components) = match resolve_base_and_components(&base_dir, &to_path) {
            Ok(value) => value,
            Err(status) => return status,
        };
        if dst_components.is_empty() {
            return ResolverStatus::InvalidPath;
        }
        let (intermediate, leaf) = dst_components.split_at(dst_components.len() - 1);
        let parent = match resolve_intermediate(dst_base, intermediate) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let leaf_name = match resolve_final(&parent, &leaf[0], ResolverIntent::Rename) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let dst = win32::join_path(&parent, &leaf_name);
        match win32::move_file_replace(&src, &dst) {
            Ok(()) => ResolverStatus::Ok,
            Err(status) => status,
        }
    }

    fn execute_unlink(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let base_dir = match unsafe { string_view_to_string(base_dir) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let path = match resolve_path_for_intent(&base_dir, &input_path, ResolverIntent::Read) {
            Ok(value) => value,
            Err(status) => return status,
        };
        match win32::get_file_attributes(&path) {
            Ok(attrs) if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 => {
                return ResolverStatus::NotADirectory;
            }
            Ok(_) => {}
            Err(status) => return status,
        }
        match win32::delete_file(&path) {
            Ok(()) => ResolverStatus::Ok,
            Err(status) => status,
        }
    }

    fn execute_open_return_path(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_resolved_path: *mut ResolverResolvedPath,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        let base_dir = match unsafe { string_view_to_string(base_dir) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let resolved = match resolve_path_for_intent(&base_dir, &input_path, intent) {
            Ok(value) => value,
            Err(status) => return status,
        };
        write_resolved_path(&resolved, out_resolved_path)
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
        let base_dir = match unsafe { string_view_to_string(base_dir) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let input_path = match unsafe { string_view_to_string(input_path) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let resolved = match resolve_path_for_intent(&base_dir, &input_path, intent) {
            Ok(value) => value,
            Err(status) => return status,
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

        let handle = match win32::open_file(&resolved, open_intent) {
            Ok(handle) if handle != INVALID_HANDLE_VALUE => handle,
            Ok(_) => return ResolverStatus::IoError,
            Err(status) => return status,
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
            return ResolverStatus::IoError;
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
        // TODO(windows): implement execute-from-plan with plan token validation.
        ResolverStatus::IoError
    }

    fn get_metrics(&self, _out_metrics: *mut ResolverMetrics) -> ResolverStatus {
        // TODO(windows): populate metrics.
        ResolverStatus::Ok
    }
}
