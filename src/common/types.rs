use core::ffi::c_char;

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
    pub reserved: [u64; 6],
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
pub struct ResolverPlan {
    pub size: u32,
    pub reserved: [u64; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverResult {
    pub size: u32,
    pub reserved: [u64; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverDiag {
    pub size: u32,
    pub reserved: [u64; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverMetrics {
    pub size: u32,
    pub reserved: [u64; 12],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResolverResolvedPath {
    pub value: ResolverStringView,
}

pub const RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY: u32 = 1 << 0;
