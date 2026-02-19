//! Safe Rust wrapper over the wcfss C ABI.
//!
//! This module assumes the C ABI is available as a shared library named `wcfss`.
//! If you are linking statically, adjust the `#[link]` attribute accordingly.
//!
//! Error handling example:
//! ```text
//! let resolver = Resolver::new(None);
//! match resolver {
//!     Ok(r) => {
//!         let _plan = r.plan("/tmp", "file.txt", Intent::StatExists);
//!     }
//!     Err(Error::Status(status)) => {
//!         eprintln!("resolver failed: {:?}", status);
//!     }
//!     Err(err) => eprintln!("resolver error: {:?}", err),
//! }
//! ```

use std::ffi::{CString, NulError};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    Exists = 2,
    Collision = 3,
    UnmappedRoot = 4,
    UnsupportedAbsolutePath = 5,
    EscapesRoot = 6,
    EncodingError = 7,
    TooManySymlinks = 8,
    NotADirectory = 9,
    PermissionDenied = 10,
    BaseDirInvalid = 11,
    PathTooLong = 12,
    StalePlan = 13,
    IoError = 14,
    InvalidPath = 15,
}

#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Intent {
    StatExists = 0,
    Read = 1,
    WriteTruncate = 2,
    WriteAppend = 3,
    CreateNew = 4,
    Mkdirs = 5,
    Rename = 6,
}

#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

pub const RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY: u32 = 1 << 0;
pub const RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS: u32 = 1 << 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverConfig {
    pub size: u32,
    pub flags: u32,
    pub ttl_fast_ms: u64,
    pub reserved: [u64; 5],
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            size: std::mem::size_of::<ResolverConfig>() as u32,
            flags: 0,
            ttl_fast_ms: 0,
            reserved: [0; 5],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverStringView {
    pub ptr: *const c_char,
    pub len: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverBufferView {
    pub ptr: *const c_void,
    pub len: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverRootMappingEntry {
    pub key: ResolverStringView,
    pub value: ResolverStringView,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverRootMapping {
    pub entries: *const ResolverRootMappingEntry,
    pub len: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverDirGeneration {
    pub dev: u64,
    pub ino: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverDirStamp {
    pub dev: u64,
    pub ino: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverPlanToken {
    pub size: u32,
    pub op_generation: u64,
    pub unicode_version_generation: u64,
    pub root_mapping_generation: u64,
    pub absolute_path_support_generation: u64,
    pub encoding_policy_generation: u64,
    pub symlink_policy_generation: u64,
    pub dir_generations: ResolverBufferView,
    pub touched_dir_stamps: ResolverBufferView,
    pub reserved: [u64; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverPlan {
    pub size: u32,
    pub status: Status,
    pub would_error: Status,
    pub flags: u32,
    pub intent: Intent,
    pub resolved_parent: ResolverStringView,
    pub resolved_leaf: ResolverStringView,
    pub plan_token: ResolverPlanToken,
    pub reserved: [u64; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverResult {
    pub size: u32,
    pub reserved: [u64; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverDiagEntry {
    pub code: u32,
    pub severity: u32,
    pub context: ResolverStringView,
    pub detail: ResolverStringView,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverDiag {
    pub size: u32,
    pub entries: ResolverBufferView,
    pub reserved: [u64; 7],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverMetrics {
    pub size: u32,
    pub dirindex_cache_hits: u64,
    pub dirindex_cache_misses: u64,
    pub dirindex_rebuilds: u64,
    pub stamp_validations: u64,
    pub collisions: u64,
    pub invalid_utf8_entries: u64,
    pub encoding_errors: u64,
    pub plans_rejected_stale: u64,
    pub reserved: [u64; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverResolvedPath {
    pub value: ResolverStringView,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverLogRecord {
    pub level: LogLevel,
    pub target: ResolverStringView,
    pub message: ResolverStringView,
    pub file: ResolverStringView,
    pub line: u32,
}

pub type LogCallback = Option<extern "C" fn(record: *const ResolverLogRecord, user_data: *mut c_void)>;

#[repr(C)]
pub struct ResolverHandle {
    _private: [u8; 0],
}

#[link(name = "wcfss")]
extern "C" {
    fn resolver_log_set_stderr(level: LogLevel) -> Status;
    fn resolver_log_set_callback(callback: LogCallback, user_data: *mut c_void, level: LogLevel) -> Status;
    fn resolver_log_set_level(level: LogLevel) -> Status;
    fn resolver_log_disable() -> Status;
    fn resolver_create(config: *const ResolverConfig) -> *mut ResolverHandle;
    fn resolver_destroy(handle: *mut ResolverHandle);
    fn resolver_set_root_mapping(
        handle: *mut ResolverHandle,
        mapping: *const ResolverRootMapping,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_plan(
        handle: *mut ResolverHandle,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: Intent,
        out_plan: *mut ResolverPlan,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_execute_mkdirs(
        handle: *mut ResolverHandle,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_execute_rename(
        handle: *mut ResolverHandle,
        base_dir: *const ResolverStringView,
        from_path: *const ResolverStringView,
        to_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_execute_unlink(
        handle: *mut ResolverHandle,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_execute_open_return_path(
        handle: *mut ResolverHandle,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: Intent,
        out_resolved_path: *mut ResolverResolvedPath,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_execute_open_return_fd(
        handle: *mut ResolverHandle,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: Intent,
        out_fd: *mut c_int,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_execute_from_plan(
        handle: *mut ResolverHandle,
        plan: *const ResolverPlan,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> Status;
    fn resolver_get_metrics(handle: *mut ResolverHandle, out_metrics: *mut ResolverMetrics) -> Status;
    fn resolver_free_string(value: ResolverStringView);
    fn resolver_free_buffer(value: ResolverBufferView);
}

pub fn enable_stderr_logging(level: LogLevel) -> Result<()> {
    let status = unsafe { resolver_log_set_stderr(level) };
    if status == Status::Ok {
        Ok(())
    } else {
        Err(Error::Status(status))
    }
}

pub fn set_log_callback(callback: LogCallback, user_data: *mut c_void, level: LogLevel) -> Result<()> {
    let status = unsafe { resolver_log_set_callback(callback, user_data, level) };
    if status == Status::Ok {
        Ok(())
    } else {
        Err(Error::Status(status))
    }
}

pub fn set_log_level(level: LogLevel) -> Result<()> {
    let status = unsafe { resolver_log_set_level(level) };
    if status == Status::Ok {
        Ok(())
    } else {
        Err(Error::Status(status))
    }
}

pub fn disable_logging() -> Result<()> {
    let status = unsafe { resolver_log_disable() };
    if status == Status::Ok {
        Ok(())
    } else {
        Err(Error::Status(status))
    }
}

#[derive(Debug)]
pub enum Error {
    Nul(NulError),
    Status(Status),
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::Nul(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn cstring(s: &str) -> Result<CString> {
    Ok(CString::new(s)?)
}

fn view_from_cstring(s: &CString) -> ResolverStringView {
    ResolverStringView {
        ptr: s.as_ptr(),
        len: s.as_bytes().len(),
    }
}

fn map_status(status: Status) -> Result<()> {
    if status == Status::Ok {
        Ok(())
    } else {
        Err(Error::Status(status))
    }
}

pub struct Resolver {
    handle: *mut ResolverHandle,
}

impl Resolver {
    /// Create a resolver. Pass `None` for default configuration.
    pub fn new(config: Option<ResolverConfig>) -> Result<Self> {
        let handle = unsafe {
            resolver_create(
                config
                    .as_ref()
                    .map(|c| c as *const ResolverConfig)
                    .unwrap_or(ptr::null()),
            )
        };
        if handle.is_null() {
            return Err(Error::Status(Status::InvalidPath));
        }
        Ok(Self { handle })
    }

    pub fn set_root_mapping(&self, entries: &[(String, String)]) -> Result<()> {
        let mut cstrings: Vec<CString> = Vec::with_capacity(entries.len() * 2);
        let mut mapping_entries: Vec<ResolverRootMappingEntry> = Vec::with_capacity(entries.len());
        for (k, v) in entries {
            let ks = cstring(k)?;
            let vs = cstring(v)?;
            let key_view = view_from_cstring(&ks);
            let val_view = view_from_cstring(&vs);
            cstrings.push(ks);
            cstrings.push(vs);
            mapping_entries.push(ResolverRootMappingEntry {
                key: key_view,
                value: val_view,
            });
        }
        let mapping = ResolverRootMapping {
            entries: mapping_entries.as_ptr(),
            len: mapping_entries.len(),
        };
        let status = unsafe { resolver_set_root_mapping(self.handle, &mapping, ptr::null_mut()) };
        map_status(status)
    }

    pub fn plan(&self, base_dir: &str, input_path: &str, intent: Intent) -> Result<Plan> {
        let base_c = cstring(base_dir)?;
        let input_c = cstring(input_path)?;
        let mut plan = ResolverPlan {
            size: std::mem::size_of::<ResolverPlan>() as u32,
            status: Status::Ok,
            would_error: Status::Ok,
            flags: 0,
            intent,
            resolved_parent: ResolverStringView {
                ptr: ptr::null(),
                len: 0,
            },
            resolved_leaf: ResolverStringView {
                ptr: ptr::null(),
                len: 0,
            },
            plan_token: ResolverPlanToken {
                size: std::mem::size_of::<ResolverPlanToken>() as u32,
                op_generation: 0,
                unicode_version_generation: 0,
                root_mapping_generation: 0,
                absolute_path_support_generation: 0,
                encoding_policy_generation: 0,
                symlink_policy_generation: 0,
                dir_generations: ResolverBufferView {
                    ptr: ptr::null(),
                    len: 0,
                },
                touched_dir_stamps: ResolverBufferView {
                    ptr: ptr::null(),
                    len: 0,
                },
                reserved: [0; 4],
            },
            reserved: [0; 6],
        };
        let status = unsafe {
            resolver_plan(
                self.handle,
                &view_from_cstring(&base_c),
                &view_from_cstring(&input_c),
                intent,
                &mut plan,
                ptr::null_mut(),
            )
        };
        map_status(status)?;
        Ok(Plan { plan })
    }

    pub fn execute_from_plan(&self, plan: &Plan) -> Result<()> {
        let mut result = ResolverResult {
            size: std::mem::size_of::<ResolverResult>() as u32,
            reserved: [0; 6],
        };
        let status = unsafe {
            resolver_execute_from_plan(self.handle, &plan.plan, &mut result, ptr::null_mut())
        };
        map_status(status)
    }

    pub fn execute_open_return_path(
        &self,
        base_dir: &str,
        input_path: &str,
        intent: Intent,
    ) -> Result<String> {
        let base_c = cstring(base_dir)?;
        let input_c = cstring(input_path)?;
        let mut resolved = ResolverResolvedPath {
            value: ResolverStringView {
                ptr: ptr::null(),
                len: 0,
            },
        };
        let status = unsafe {
            resolver_execute_open_return_path(
                self.handle,
                &view_from_cstring(&base_c),
                &view_from_cstring(&input_c),
                intent,
                &mut resolved,
                ptr::null_mut(),
            )
        };
        map_status(status)?;
        let value = unsafe {
            let bytes = std::slice::from_raw_parts(resolved.value.ptr as *const u8, resolved.value.len);
            String::from_utf8_lossy(bytes).into_owned()
        };
        unsafe { resolver_free_string(resolved.value) };
        Ok(value)
    }

    pub fn execute_open_return_fd(
        &self,
        base_dir: &str,
        input_path: &str,
        intent: Intent,
    ) -> Result<i32> {
        let base_c = cstring(base_dir)?;
        let input_c = cstring(input_path)?;
        let mut fd: c_int = -1;
        let status = unsafe {
            resolver_execute_open_return_fd(
                self.handle,
                &view_from_cstring(&base_c),
                &view_from_cstring(&input_c),
                intent,
                &mut fd,
                ptr::null_mut(),
            )
        };
        map_status(status)?;
        Ok(fd)
    }

    pub fn execute_mkdirs(&self, base_dir: &str, input_path: &str) -> Result<()> {
        let base_c = cstring(base_dir)?;
        let input_c = cstring(input_path)?;
        let mut result = ResolverResult {
            size: std::mem::size_of::<ResolverResult>() as u32,
            reserved: [0; 6],
        };
        let status = unsafe {
            resolver_execute_mkdirs(
                self.handle,
                &view_from_cstring(&base_c),
                &view_from_cstring(&input_c),
                &mut result,
                ptr::null_mut(),
            )
        };
        map_status(status)
    }

    pub fn execute_unlink(&self, base_dir: &str, input_path: &str) -> Result<()> {
        let base_c = cstring(base_dir)?;
        let input_c = cstring(input_path)?;
        let mut result = ResolverResult {
            size: std::mem::size_of::<ResolverResult>() as u32,
            reserved: [0; 6],
        };
        let status = unsafe {
            resolver_execute_unlink(
                self.handle,
                &view_from_cstring(&base_c),
                &view_from_cstring(&input_c),
                &mut result,
                ptr::null_mut(),
            )
        };
        map_status(status)
    }

    pub fn execute_rename(
        &self,
        base_dir: &str,
        from_path: &str,
        to_path: &str,
    ) -> Result<()> {
        let base_c = cstring(base_dir)?;
        let from_c = cstring(from_path)?;
        let to_c = cstring(to_path)?;
        let mut result = ResolverResult {
            size: std::mem::size_of::<ResolverResult>() as u32,
            reserved: [0; 6],
        };
        let status = unsafe {
            resolver_execute_rename(
                self.handle,
                &view_from_cstring(&base_c),
                &view_from_cstring(&from_c),
                &view_from_cstring(&to_c),
                &mut result,
                ptr::null_mut(),
            )
        };
        map_status(status)
    }

    pub fn get_metrics(&self) -> Result<ResolverMetrics> {
        let mut metrics = ResolverMetrics {
            size: std::mem::size_of::<ResolverMetrics>() as u32,
            dirindex_cache_hits: 0,
            dirindex_cache_misses: 0,
            dirindex_rebuilds: 0,
            stamp_validations: 0,
            collisions: 0,
            invalid_utf8_entries: 0,
            encoding_errors: 0,
            plans_rejected_stale: 0,
            reserved: [0; 4],
        };
        let status = unsafe { resolver_get_metrics(self.handle, &mut metrics) };
        map_status(status)?;
        Ok(metrics)
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        unsafe { resolver_destroy(self.handle) };
    }
}

pub struct Plan {
    plan: ResolverPlan,
}

impl Plan {
    pub fn raw(&self) -> &ResolverPlan {
        &self.plan
    }
}

impl Drop for Plan {
    fn drop(&mut self) {
        unsafe {
            resolver_free_buffer(self.plan.plan_token.dir_generations);
            resolver_free_buffer(self.plan.plan_token.touched_dir_stamps);
            resolver_free_string(self.plan.resolved_parent);
            resolver_free_string(self.plan.resolved_leaf);
        }
    }
}

// Example:
//
// let resolver = Resolver::new(None)?;
// let plan = resolver.plan("/tmp", "file.txt", Intent::StatExists)?;
// resolver.execute_from_plan(&plan)?;
