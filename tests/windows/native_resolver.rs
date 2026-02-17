use std::ffi::c_char;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wcfss::*;

struct TestResolver {
    handle: *mut ResolverHandle,
}

impl TestResolver {
    fn new() -> Self {
        let config = ResolverConfig {
            size: std::mem::size_of::<ResolverConfig>() as u32,
            flags: 0,
            ttl_fast_ms: 0,
            reserved: [0; 5],
        };
        let handle = resolver_create(&config);
        Self { handle }
    }
}

impl Drop for TestResolver {
    fn drop(&mut self) {
        resolver_destroy(self.handle);
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("wcfss_{label}_{}_{}", std::process::id(), nanos));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn make_view(value: &str) -> (Vec<u8>, ResolverStringView) {
    let bytes = value.as_bytes().to_vec();
    let view = ResolverStringView {
        ptr: bytes.as_ptr() as *const c_char,
        len: bytes.len(),
    };
    (bytes, view)
}

fn open_return_path_raw(
    resolver: &TestResolver,
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
) -> Result<ResolverStringView, ResolverStatus> {
    let (_base_buf, base_view) = make_view(base_dir);
    let (_input_buf, input_view) = make_view(input_path);
    let mut resolved = ResolverResolvedPath {
        value: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
    };
    let status = resolver_execute_open_return_path(
        resolver.handle,
        &base_view,
        &input_view,
        intent,
        &mut resolved,
        std::ptr::null_mut(),
    );
    if status != ResolverStatus::Ok {
        return Err(status);
    }
    Ok(resolved.value)
}

fn read_view(view: ResolverStringView) -> Result<String, ResolverStatus> {
    if view.ptr.is_null() && view.len != 0 {
        return Err(ResolverStatus::InvalidPath);
    }
    if view.len == 0 {
        return Ok(String::new());
    }
    let bytes = unsafe { std::slice::from_raw_parts(view.ptr as *const u8, view.len) };
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn free_view(view: ResolverStringView) {
    resolver_free_string(view);
}

fn open_return_path(
    resolver: &TestResolver,
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
) -> Result<String, ResolverStatus> {
    let view = open_return_path_raw(resolver, base_dir, input_path, intent)?;
    let value = read_view(view)?;
    free_view(view);
    Ok(value)
}

fn open_return_fd(
    resolver: &TestResolver,
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
) -> Result<i32, ResolverStatus> {
    let (_base_buf, base_view) = make_view(base_dir);
    let (_input_buf, input_view) = make_view(input_path);
    let mut fd: i32 = -1;
    let status = resolver_execute_open_return_fd(
        resolver.handle,
        &base_view,
        &input_view,
        intent,
        &mut fd,
        std::ptr::null_mut(),
    );
    if status != ResolverStatus::Ok {
        return Err(status);
    }
    Ok(fd)
}

fn execute_mkdirs(
    resolver: &TestResolver,
    base_dir: &str,
    input_path: &str,
) -> ResolverStatus {
    let (_base_buf, base_view) = make_view(base_dir);
    let (_input_buf, input_view) = make_view(input_path);
    resolver_execute_mkdirs(
        resolver.handle,
        &base_view,
        &input_view,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

fn execute_rename(
    resolver: &TestResolver,
    base_dir: &str,
    from_path: &str,
    to_path: &str,
) -> ResolverStatus {
    let (_base_buf, base_view) = make_view(base_dir);
    let (_from_buf, from_view) = make_view(from_path);
    let (_to_buf, to_view) = make_view(to_path);
    resolver_execute_rename(
        resolver.handle,
        &base_view,
        &from_view,
        &to_view,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

fn execute_unlink(
    resolver: &TestResolver,
    base_dir: &str,
    input_path: &str,
) -> ResolverStatus {
    let (_base_buf, base_view) = make_view(base_dir);
    let (_input_buf, input_view) = make_view(input_path);
    resolver_execute_unlink(
        resolver.handle,
        &base_view,
        &input_view,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

fn assert_path_ends_with(resolved: &str, tail: &Path) {
    let resolved_path = Path::new(resolved);
    assert!(
        resolved_path.ends_with(tail),
        "expected {:?} to end with {:?}",
        resolved_path,
        tail
    );
}

#[test]
fn separator_handling() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("separators");
    let subdir = temp.path.join("SubDir");
    fs::create_dir_all(&subdir).expect("create subdir");
    let file_path = subdir.join("MiXeD.txt");
    fs::write(&file_path, b"hello").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let resolved_slash =
        open_return_path(&resolver, &base, "SubDir/MiXeD.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved_slash, Path::new("SubDir").join("MiXeD.txt").as_path());

    let resolved_backslash =
        open_return_path(&resolver, &base, "SubDir\\MiXeD.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved_backslash, Path::new("SubDir").join("MiXeD.txt").as_path());
}

#[test]
fn case_insensitive_matching() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("case_match");
    let subdir = temp.path.join("SubDir");
    fs::create_dir_all(&subdir).expect("create subdir");
    let file_path = subdir.join("MiXeD.txt");
    fs::write(&file_path, b"hello").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let resolved =
        open_return_path(&resolver, &base, "subdir\\mixed.TXT", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new("SubDir").join("MiXeD.txt").as_path());
}

#[test]
fn collision_detection_when_supported() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("collision");
    let base = temp.path.to_string_lossy().into_owned();

    let first = temp.path.join("Foo.txt");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&first)
        .expect("create Foo.txt");
    file.write_all(b"one").unwrap();

    let second = temp.path.join("foo.TXT");
    match fs::OpenOptions::new().create_new(true).write(true).open(&second) {
        Ok(mut f) => {
            f.write_all(b"two").unwrap();
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("collision test skipped: case-sensitive entries not supported");
            return;
        }
        Err(err) => panic!("unexpected error creating second entry: {err}"),
    }

    let status = open_return_path(&resolver, &base, "FOO.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Collision);
}

#[test]
fn drive_absolute_paths() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("drive_abs");
    let file_path = temp.path.join("abs.txt");
    fs::write(&file_path, b"data").expect("write file");

    let base = TempDir::new("drive_base");
    let base_str = base.path.to_string_lossy().into_owned();
    let input = file_path.to_string_lossy().into_owned();
    let resolved = open_return_path(&resolver, &base_str, &input, ResolverIntent::Read).unwrap();
    assert_eq!(Path::new(&resolved), file_path.as_path());
}

#[test]
fn unc_paths_when_provided() {
    let resolver = TestResolver::new();
    let Ok(unc_base) = std::env::var("WCFSS_UNC_BASE") else {
        eprintln!("UNC test skipped: set WCFSS_UNC_BASE to a writable UNC path");
        return;
    };
    let unc_base_path = PathBuf::from(&unc_base);
    fs::create_dir_all(&unc_base_path).expect("create UNC base");
    let file_path = unc_base_path.join("unc.txt");
    fs::write(&file_path, b"data").expect("write unc file");

    let base = TempDir::new("unc_base");
    let base_str = base.path.to_string_lossy().into_owned();
    let input = file_path.to_string_lossy().into_owned();
    let resolved = open_return_path(&resolver, &base_str, &input, ResolverIntent::Read).unwrap();
    assert_eq!(Path::new(&resolved), file_path.as_path());
}

#[test]
fn empty_paths_resolve_to_base_dir() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("empty_path");
    let base = temp.path.to_string_lossy().into_owned();

    let resolved_empty =
        open_return_path(&resolver, &base, "", ResolverIntent::StatExists).unwrap();
    assert_eq!(Path::new(&resolved_empty), temp.path.as_path());

    let resolved_dot =
        open_return_path(&resolver, &base, ".", ResolverIntent::StatExists).unwrap();
    assert_eq!(Path::new(&resolved_dot), temp.path.as_path());
}

#[test]
fn permission_denied_write_truncate() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("perm_denied");
    let file_path = temp.path.join("readonly.txt");
    fs::write(&file_path, b"data").expect("write file");

    let mut perms = fs::metadata(&file_path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&file_path, perms).unwrap();

    let base = temp.path.to_string_lossy().into_owned();
    let input = file_path.file_name().unwrap().to_string_lossy().into_owned();
    match open_return_fd(&resolver, &base, &input, ResolverIntent::WriteTruncate) {
        Err(ResolverStatus::PermissionDenied) => {}
        Ok(fd) => {
            unsafe {
                libc::close(fd);
            }
            eprintln!("permission test skipped: write succeeded on readonly file");
        }
        Err(other) => panic!("unexpected status: {other:?}"),
    }

    let mut perms = fs::metadata(&file_path).unwrap().permissions();
    perms.set_readonly(false);
    let _ = fs::set_permissions(&file_path, perms);
}

#[test]
fn ffi_resolved_path_lifetime_across_calls() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("ffi_lifetime_calls");
    let file_path = temp.path.join("value.txt");
    fs::write(&file_path, b"data").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let view1 = open_return_path_raw(&resolver, &base, "value.txt", ResolverIntent::Read).unwrap();
    let view1_value = read_view(view1).unwrap();

    let view2 = open_return_path_raw(&resolver, &base, "value.txt", ResolverIntent::Read).unwrap();
    let view1_value_after = read_view(view1).unwrap();
    let view2_value = read_view(view2).unwrap();

    assert_eq!(view1_value, view1_value_after);
    assert_eq!(view1_value, view2_value);

    free_view(view1);
    free_view(view2);
}

#[test]
fn ffi_resolved_path_lifetime_after_plan() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("ffi_lifetime_plan");
    let file_path = temp.path.join("plan.txt");
    fs::write(&file_path, b"data").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let view = open_return_path_raw(&resolver, &base, "plan.txt", ResolverIntent::Read).unwrap();
    let view_value = read_view(view).unwrap();

    let (_base_buf, base_view) = make_view(&base);
    let (_input_buf, input_view) = make_view("plan.txt");
    let status = resolver_plan(
        resolver.handle,
        &base_view,
        &input_view,
        ResolverIntent::StatExists,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_eq!(status, ResolverStatus::Ok);

    let view_value_after = read_view(view).unwrap();
    assert_eq!(view_value, view_value_after);
    free_view(view);
}

#[test]
fn ffi_free_after_destroy() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("ffi_free_after_destroy");
    let file_path = temp.path.join("destroy.txt");
    fs::write(&file_path, b"data").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let view = open_return_path_raw(&resolver, &base, "destroy.txt", ResolverIntent::Read).unwrap();
    drop(resolver);
    free_view(view);
}

#[test]
fn dotdot_traversal_within_base() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("dotdot_ok");
    let subdir = temp.path.join("SubDir");
    fs::create_dir_all(&subdir).expect("create subdir");
    let file_path = temp.path.join("root.txt");
    fs::write(&file_path, b"hello").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let resolved =
        open_return_path(&resolver, &base, "SubDir\\..\\root.txt", ResolverIntent::Read).unwrap();
    assert_eq!(Path::new(&resolved), file_path.as_path());
}

#[test]
fn dotdot_escape_base_is_rejected() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("dotdot_escape");
    let base = temp.path.to_string_lossy().into_owned();
    let status = open_return_path(&resolver, &base, "..\\escape.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::EscapesRoot);
}

#[test]
fn multiple_separators() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("multi_sep");
    let subdir = temp.path.join("SubDir");
    fs::create_dir_all(&subdir).expect("create subdir");
    let file_path = subdir.join("MiXeD.txt");
    fs::write(&file_path, b"hello").expect("write file");

    let base = temp.path.to_string_lossy().into_owned();
    let resolved_backslashes =
        open_return_path(&resolver, &base, "SubDir\\\\MiXeD.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved_backslashes, Path::new("SubDir").join("MiXeD.txt").as_path());

    let resolved_slashes =
        open_return_path(&resolver, &base, "SubDir//MiXeD.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved_slashes, Path::new("SubDir").join("MiXeD.txt").as_path());
}

#[test]
fn trailing_separators_directory() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("trailing_sep");
    let subdir = temp.path.join("SubDir");
    fs::create_dir_all(&subdir).expect("create subdir");

    let base = temp.path.to_string_lossy().into_owned();
    let resolved =
        open_return_path(&resolver, &base, "SubDir\\", ResolverIntent::StatExists).unwrap();
    assert_eq!(Path::new(&resolved), subdir.as_path());
}

#[test]
fn drive_relative_paths_rejected() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("drive_relative");
    let base = temp.path.to_string_lossy().into_owned();
    let status = open_return_path(&resolver, &base, "C:foo\\bar", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::InvalidPath);
}

#[test]
fn reserved_names_treated_as_missing() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("reserved_names");
    let base = temp.path.to_string_lossy().into_owned();

    for name in ["CON", "NUL", "PRN"] {
        let status = open_return_path(&resolver, &base, name, ResolverIntent::Read)
            .err()
            .unwrap_or(ResolverStatus::Ok);
        assert_eq!(status, ResolverStatus::NotFound);
    }
}

#[test]
fn cache_invalidation_after_create() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("invalidate_create");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("Seed.txt"), b"seed").expect("write seed file");
    let _ = open_return_path(&resolver, &base, "SEED.txt", ResolverIntent::Read)
        .expect("warm cache");

    let fd = open_return_fd(&resolver, &base, "NewFile.txt", ResolverIntent::CreateNew)
        .expect("create file");
    unsafe {
        libc::close(fd);
    }

    let resolved =
        open_return_path(&resolver, &base, "newfile.TXT", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new("NewFile.txt"));
}

#[test]
fn cache_invalidation_after_mkdirs() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("invalidate_mkdirs");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("Seed.txt"), b"seed").expect("write seed file");
    let _ = open_return_path(&resolver, &base, "SEED.txt", ResolverIntent::Read)
        .expect("warm cache");

    let status = execute_mkdirs(&resolver, &base, "NewDir/SubDir");
    assert_eq!(status, ResolverStatus::Ok);

    let resolved =
        open_return_path(&resolver, &base, "newdir", ResolverIntent::StatExists).unwrap();
    assert_path_ends_with(&resolved, Path::new("NewDir"));
}

#[test]
fn cache_invalidation_after_rename() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("invalidate_rename");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("OldName.txt"), b"data").expect("write file");
    let _ = open_return_path(&resolver, &base, "OLDNAME.TXT", ResolverIntent::Read)
        .expect("warm cache");

    let status = execute_rename(&resolver, &base, "OldName.txt", "NewName.txt");
    assert_eq!(status, ResolverStatus::Ok);

    let resolved =
        open_return_path(&resolver, &base, "newname.TXT", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new("NewName.txt"));
}

#[test]
fn cache_invalidation_after_unlink() {
    let resolver = TestResolver::new();
    let temp = TempDir::new("invalidate_unlink");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("Gone.txt"), b"one").expect("write file");
    let _ = open_return_path(&resolver, &base, "GONE.txt", ResolverIntent::Read)
        .expect("warm cache");

    let status = execute_unlink(&resolver, &base, "Gone.txt");
    assert_eq!(status, ResolverStatus::Ok);

    let status = open_return_path(&resolver, &base, "GONE.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::NotFound);
}
