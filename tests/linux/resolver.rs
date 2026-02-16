use std::ffi::c_char;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wcfss::*;

#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

struct TestResolver {
    handle: *mut ResolverHandle,
}

impl TestResolver {
    fn new(flags: u32) -> Self {
        let config = ResolverConfig {
            size: std::mem::size_of::<ResolverConfig>() as u32,
            flags,
            reserved: [0; 6],
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
        path.push(format!("wcfss_linux_{label}_{}_{}", std::process::id(), nanos));
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

fn open_return_path(
    resolver: &TestResolver,
    base_dir: &str,
    input_path: &str,
    intent: ResolverIntent,
) -> Result<String, ResolverStatus> {
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
    let bytes = unsafe { std::slice::from_raw_parts(resolved.value.ptr as *const u8, resolved.value.len) };
    let value = String::from_utf8_lossy(bytes).into_owned();
    resolver_free_string(resolved.value);
    Ok(value)
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
fn collision_detection_case_insensitive() {
    let resolver = TestResolver::new(0);
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
fn collision_detection_exact_match() {
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("collision_exact");
    let base = temp.path.to_string_lossy().into_owned();

    let first = temp.path.join("Bar.txt");
    fs::write(&first, b"one").expect("create Bar.txt");

    let second = temp.path.join("bar.TXT");
    match fs::OpenOptions::new().create_new(true).write(true).open(&second) {
        Ok(mut f) => {
            f.write_all(b"two").unwrap();
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("collision exact test skipped: case-sensitive entries not supported");
            return;
        }
        Err(err) => panic!("unexpected error creating second entry: {err}"),
    }

    let status = open_return_path(&resolver, &base, "Bar.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Collision);
}

#[test]
fn collision_detection_intermediate_component() {
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("collision_intermediate");
    let base = temp.path.to_string_lossy().into_owned();

    let dir_a = temp.path.join("Dir");
    let dir_b = temp.path.join("dir");
    fs::create_dir_all(&dir_a).expect("create Dir");
    match fs::create_dir_all(&dir_b) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("collision intermediate test skipped: case-sensitive entries not supported");
            return;
        }
        Err(err) => panic!("unexpected error creating second directory: {err}"),
    }
    fs::write(dir_a.join("file.txt"), b"data").expect("write file");

    let status = open_return_path(&resolver, &base, "DIR/file.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Collision);
}

#[test]
fn symlink_cycle_detection() {
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("symlink_loop");
    let base = temp.path.to_string_lossy().into_owned();

    let loop_path = temp.path.join("loop");
    #[cfg(target_os = "linux")]
    symlink("loop", &loop_path).expect("create symlink loop");

    let status = open_return_path(&resolver, &base, "loop/file.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::TooManySymlinks);
}

#[test]
fn symlink_cycle_detection_revisit() {
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("symlink_revisit");
    let base = temp.path.to_string_lossy().into_owned();

    let file_path = temp.path.join("file.txt");
    fs::write(&file_path, b"data").expect("write file");

    let loop_path = temp.path.join("loop");
    #[cfg(target_os = "linux")]
    symlink(".", &loop_path).expect("create symlink to self directory");

    let status = open_return_path(&resolver, &base, "loop/loop/file.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::TooManySymlinks);
}

#[test]
fn invalid_utf8_entries_skip_or_fail() {
    let temp = TempDir::new("invalid_utf8");
    let base = temp.path.to_string_lossy().into_owned();

    let valid_name = "Valid.txt";
    fs::write(temp.path.join(valid_name), b"data").expect("write valid file");

    let invalid_bytes = [0xff, 0xfe, 0x00];
    let invalid_name = std::ffi::OsStr::from_bytes(&invalid_bytes[..2]);
    let invalid_path = temp.path.join(invalid_name);
    if let Err(err) = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&invalid_path)
    {
        eprintln!("invalid utf8 test skipped: could not create invalid entry: {err}");
        return;
    }

    let resolver = TestResolver::new(0);
    let resolved = open_return_path(&resolver, &base, "valid.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new(valid_name));

    let strict_resolver =
        TestResolver::new(RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY);
    let status =
        open_return_path(&strict_resolver, &base, "valid.txt", ResolverIntent::Read)
            .err()
            .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::EncodingError);
}
