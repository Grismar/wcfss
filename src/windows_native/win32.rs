use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    BOOL, CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BAD_PATHNAME,
    ERROR_DIRECTORY, ERROR_FILENAME_EXCED_RANGE, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_NAME, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FindClose, FindFirstFileW, FindNextFileW,
    GetFileAttributesW, GetFileInformationByHandle, MoveFileExW, BY_HANDLE_FILE_INFORMATION,
    CREATE_ALWAYS, CREATE_NEW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, OPEN_ALWAYS,
    OPEN_EXISTING, WIN32_FIND_DATAW,
};

use crate::common::types::ResolverStatus;

pub struct MatchResult {
    pub count: u32,
    pub exact_name: Option<OsString>,
    pub unique_name: Option<OsString>,
    pub unique_attrs: u32,
}

pub fn map_win32_error(err: u32) -> ResolverStatus {
    match err {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => ResolverStatus::NotFound,
        ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => ResolverStatus::Exists,
        ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION => ResolverStatus::PermissionDenied,
        ERROR_DIRECTORY => ResolverStatus::NotADirectory,
        ERROR_INVALID_NAME | ERROR_BAD_PATHNAME => ResolverStatus::InvalidPath,
        ERROR_FILENAME_EXCED_RANGE => ResolverStatus::PathTooLong,
        _ => ResolverStatus::IoError,
    }
}

pub fn os_str_to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_slice_from_find_data(name: &[u16]) -> &[u16] {
    let nul = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    &name[..nul]
}

fn compare_ordinal(a: &[u16], b: &[u16], ignore_case: bool) -> bool {
    (unsafe {
        CompareStringOrdinal(
            a.as_ptr(),
            a.len() as i32,
            b.as_ptr(),
            b.len() as i32,
            ignore_case as BOOL,
        )
    }) == CSTR_EQUAL
}

pub fn join_path(dir: &Path, name: &OsStr) -> PathBuf {
    let mut path = PathBuf::from(dir);
    path.push(name);
    path
}

pub fn get_file_attributes(path: &Path) -> Result<u32, ResolverStatus> {
    let wide = os_str_to_wide(path.as_os_str());
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    Ok(attrs)
}

pub fn get_file_id(path: &Path) -> Result<(u64, u64), ResolverStatus> {
    let wide = os_str_to_wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let status = if ok == 0 {
        Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }))
    } else {
        let ino = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        Ok((info.dwVolumeSerialNumber as u64, ino))
    };
    unsafe {
        CloseHandle(handle);
    }
    status
}

pub fn find_match(dir: &Path, target: &OsStr) -> Result<MatchResult, ResolverStatus> {
    let mut pattern = PathBuf::from(dir);
    pattern.push("*");
    let pattern_wide = os_str_to_wide(pattern.as_os_str());

    let mut find_data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let handle = unsafe { FindFirstFileW(pattern_wide.as_ptr(), &mut find_data) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }

    let target_wide: Vec<u16> = target.encode_wide().collect();
    let mut result = MatchResult {
        count: 0,
        exact_name: None,
        unique_name: None,
        unique_attrs: 0,
    };

    let mut keep_going = true;
    while keep_going {
        let name_slice = wide_slice_from_find_data(&find_data.cFileName);
        if name_slice != [b'.' as u16] && name_slice != [b'.' as u16, b'.' as u16] {
            if compare_ordinal(name_slice, &target_wide, true) {
                result.count += 1;
                let os_name = OsString::from_wide(name_slice);
                if result.count == 1 {
                    result.unique_name = Some(os_name.clone());
                    result.unique_attrs = find_data.dwFileAttributes;
                }
                if compare_ordinal(name_slice, &target_wide, false) {
                    result.exact_name = Some(os_name);
                }
            }
        }
        keep_going = unsafe { FindNextFileW(handle, &mut find_data) } != 0;
    }

    unsafe {
        FindClose(handle);
    }

    Ok(result)
}

pub fn find_all_matches(dir: &Path, target: &OsStr) -> Result<Vec<OsString>, ResolverStatus> {
    let mut pattern = PathBuf::from(dir);
    pattern.push("*");
    let pattern_wide = os_str_to_wide(pattern.as_os_str());

    let mut find_data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let handle = unsafe { FindFirstFileW(pattern_wide.as_ptr(), &mut find_data) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }

    let target_wide: Vec<u16> = target.encode_wide().collect();
    let mut matches: Vec<OsString> = Vec::new();

    let mut keep_going = true;
    while keep_going {
        let name_slice = wide_slice_from_find_data(&find_data.cFileName);
        if name_slice != [b'.' as u16] && name_slice != [b'.' as u16, b'.' as u16] {
            if compare_ordinal(name_slice, &target_wide, true) {
                matches.push(OsString::from_wide(name_slice));
            }
        }
        keep_going = unsafe { FindNextFileW(handle, &mut find_data) } != 0;
    }

    unsafe {
        FindClose(handle);
    }

    matches.sort_by_key(|value| value.to_string_lossy().to_lowercase());
    matches.dedup_by_key(|value| value.to_string_lossy().to_lowercase());
    Ok(matches)
}

pub fn create_directory(path: &Path) -> Result<(), ResolverStatus> {
    let wide = os_str_to_wide(path.as_os_str());
    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), std::ptr::null_mut()) };
    if ok == 0 {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    Ok(())
}

pub fn delete_file(path: &Path) -> Result<(), ResolverStatus> {
    let wide = os_str_to_wide(path.as_os_str());
    let ok = unsafe { DeleteFileW(wide.as_ptr()) };
    if ok == 0 {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    Ok(())
}

pub fn move_file_replace(src: &Path, dst: &Path) -> Result<(), ResolverStatus> {
    let src_wide = os_str_to_wide(src.as_os_str());
    let dst_wide = os_str_to_wide(dst.as_os_str());
    let ok = unsafe {
        MoveFileExW(
            src_wide.as_ptr(),
            dst_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING,
        )
    };
    if ok == 0 {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    Ok(())
}

pub fn open_file(path: &Path, intent: OpenIntent) -> Result<HANDLE, ResolverStatus> {
    let (access, disposition) = match intent {
        OpenIntent::Read => (FILE_GENERIC_READ, OPEN_EXISTING),
        OpenIntent::WriteTruncate => (FILE_GENERIC_WRITE, CREATE_ALWAYS),
        OpenIntent::WriteAppend => (FILE_APPEND_DATA, OPEN_ALWAYS),
        OpenIntent::CreateNew => (FILE_GENERIC_WRITE, CREATE_NEW),
        OpenIntent::Stat => (FILE_GENERIC_READ, OPEN_EXISTING),
    };

    let wide = os_str_to_wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_win32_error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    Ok(handle)
}

pub enum OpenIntent {
    Read,
    WriteTruncate,
    WriteAppend,
    CreateNew,
    Stat,
}
