use core::ffi::c_char;
use core::ffi::c_void;

#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResolverStatus {
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
pub enum ResolverIntent {
    StatExists = 0,
    Read = 1,
    WriteTruncate = 2,
    WriteAppend = 3,
    CreateNew = 4,
    Mkdirs = 5,
    Rename = 6,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverConfig {
    pub size: u32,
    pub flags: u32,
    pub ttl_fast_ms: u64,
    pub reserved: [u64; 5],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverRootMapping {
    pub entries: *const ResolverRootMappingEntry,
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
    pub status: ResolverStatus,
    pub would_error: ResolverStatus,
    pub flags: u32,
    pub intent: ResolverIntent,
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

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResolverDiagSeverity {
    Info = 0,
    Warning = 1,
    Error = 2,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResolverDiagCode {
    BackslashNormalized = 1,
    RootMappingApplied = 2,
    Collision = 3,
    InvalidUtf8EntrySkipped = 4,
    EncodingError = 5,
    SymlinkLoop = 6,
    PermissionDenied = 7,
    UnsupportedAbsolutePath = 8,
    UnmappedRoot = 9,
    EscapesRoot = 10,
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

pub const RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY: u32 = 1 << 0;
pub const RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS: u32 = 1 << 1;
pub const RESOLVER_PLAN_TARGET_EXISTS: u32 = 1 << 0;
pub const RESOLVER_PLAN_TARGET_IS_DIR: u32 = 1 << 1;
pub const RESOLVER_PLAN_WOULD_CREATE: u32 = 1 << 2;
pub const RESOLVER_PLAN_WOULD_TRUNCATE: u32 = 1 << 3;
