use std::ffi::c_char;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use wcfss::*;

#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

struct TestResolver {
    handle: *mut ResolverHandle,
}

unsafe impl Send for TestResolver {}
unsafe impl Sync for TestResolver {}

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

fn bump_root_mapping_generation(resolver: &TestResolver) -> ResolverStatus {
    let mapping = ResolverRootMapping {
        entries: std::ptr::null(),
        len: 0,
    };
    resolver_set_root_mapping(resolver.handle, &mapping, std::ptr::null_mut())
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

    let resolved =
        open_return_path(&resolver, &base, "Bar.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new("Bar.txt"));
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
fn dirindex_ttl_refresh_detects_changes() {
    std::env::set_var("WCFSS_TTL_FAST_MS", "1000");
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("ttl_refresh");
    let base = temp.path.to_string_lossy().into_owned();

    let first = temp.path.join("Ttl.txt");
    fs::write(&first, b"one").expect("create Ttl.txt");
    let resolved = open_return_path(&resolver, &base, "TTL.txt", ResolverIntent::Read)
        .expect("resolve before collision");
    assert_path_ends_with(&resolved, Path::new("Ttl.txt"));

    std::thread::sleep(std::time::Duration::from_millis(1200));
    let second = temp.path.join("ttl.TXT");
    match fs::OpenOptions::new().create_new(true).write(true).open(&second) {
        Ok(mut f) => {
            f.write_all(b"two").unwrap();
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("ttl test skipped: case-sensitive entries not supported");
            return;
        }
        Err(err) => panic!("unexpected error creating second entry: {err}"),
    }

    let status = open_return_path(&resolver, &base, "TTL.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Collision);
}

#[test]
fn dirindex_generation_invalidation_clears_cache() {
    std::env::set_var("WCFSS_TTL_FAST_MS", "10_000");
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("generation_invalidate");
    let base = temp.path.to_string_lossy().into_owned();

    let first = temp.path.join("Gen.txt");
    fs::write(&first, b"one").expect("create Gen.txt");
    let resolved = open_return_path(&resolver, &base, "GEN.txt", ResolverIntent::Read)
        .expect("resolve before collision");
    assert_path_ends_with(&resolved, Path::new("Gen.txt"));

    let second = temp.path.join("gen.TXT");
    match fs::OpenOptions::new().create_new(true).write(true).open(&second) {
        Ok(mut f) => {
            f.write_all(b"two").unwrap();
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("generation test skipped: case-sensitive entries not supported");
            return;
        }
        Err(err) => panic!("unexpected error creating second entry: {err}"),
    }

    let status = open_return_path(&resolver, &base, "GEN.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Ok);

    let bump_status = bump_root_mapping_generation(&resolver);
    assert_eq!(bump_status, ResolverStatus::Ok);

    let status = open_return_path(&resolver, &base, "GEN.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Collision);
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

#[test]
fn cache_invalidation_after_create() {
    std::env::set_var("WCFSS_TTL_FAST_MS", "10_000");
    let resolver = TestResolver::new(0);
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
    std::env::set_var("WCFSS_TTL_FAST_MS", "10_000");
    let resolver = TestResolver::new(0);
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
    std::env::set_var("WCFSS_TTL_FAST_MS", "10_000");
    let resolver = TestResolver::new(0);
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
fn cache_invalidation_after_unlink_collision() {
    std::env::set_var("WCFSS_TTL_FAST_MS", "10_000");
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("invalidate_unlink");
    let base = temp.path.to_string_lossy().into_owned();

    let first = temp.path.join("Gone.txt");
    fs::write(&first, b"one").expect("create Gone.txt");
    let second = temp.path.join("gone.TXT");
    match fs::OpenOptions::new().create_new(true).write(true).open(&second) {
        Ok(mut f) => {
            f.write_all(b"two").unwrap();
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("unlink invalidate test skipped: case-sensitive entries not supported");
            return;
        }
        Err(err) => panic!("unexpected error creating second entry: {err}"),
    }

    let status = open_return_path(&resolver, &base, "GONE.txt", ResolverIntent::Read)
        .err()
        .unwrap_or(ResolverStatus::Ok);
    assert_eq!(status, ResolverStatus::Collision);

    let status = execute_unlink(&resolver, &base, "Gone.txt");
    assert_eq!(status, ResolverStatus::Ok);

    let resolved =
        open_return_path(&resolver, &base, "GONE.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new("gone.TXT"));
}

#[test]
fn plan_token_stale_after_execute() {
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("plan_token_stale");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("Plan.txt"), b"data").expect("write file");
    let (_base_buf, base_view) = make_view(&base);
    let (_input_buf, input_view) = make_view("Plan.txt");
    let mut plan = ResolverPlan {
        size: std::mem::size_of::<ResolverPlan>() as u32,
        status: ResolverStatus::Ok,
        would_error: ResolverStatus::Ok,
        flags: 0,
        resolved_parent: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
        resolved_leaf: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
        plan_token: ResolverPlanToken {
            size: std::mem::size_of::<ResolverPlanToken>() as u32,
            op_generation: 0,
            dir_generations: ResolverBufferView {
                ptr: std::ptr::null(),
                len: 0,
            },
            reserved: [0; 6],
        },
        reserved: [0; 6],
    };
    let status = resolver_plan(
        resolver.handle,
        &base_view,
        &input_view,
        ResolverIntent::StatExists,
        &mut plan,
        std::ptr::null_mut(),
    );
    assert_eq!(status, ResolverStatus::Ok);

    // Any execute bumps op_generation, which should make the plan stale.
    let _ = open_return_path(&resolver, &base, "Plan.txt", ResolverIntent::Read)
        .expect("execute to bump op_generation");

    let status = resolver_execute_from_plan(
        resolver.handle,
        &plan,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_eq!(status, ResolverStatus::StalePlan);
    resolver_free_buffer(plan.plan_token.dir_generations);
    resolver_free_string(plan.resolved_parent);
    resolver_free_string(plan.resolved_leaf);
}

#[test]
fn stress_concurrent_reads_and_writes() {
    let resolver = Arc::new(TestResolver::new(0));
    let temp = TempDir::new("stress_threads");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("File.txt"), b"data").expect("write file");

    let mut threads = Vec::new();
    for _ in 0..4 {
        let resolver = Arc::clone(&resolver);
        let base = base.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = open_return_path(&resolver, &base, "file.TXT", ResolverIntent::Read);
            }
        }));
    }

    let writer_resolver = Arc::clone(&resolver);
    let writer_base = base.clone();
    threads.push(thread::spawn(move || {
        for idx in 0..50 {
            let name = format!("Temp_{idx}.txt");
            let fd = open_return_fd(
                &writer_resolver,
                &writer_base,
                &name,
                ResolverIntent::CreateNew,
            );
            if let Ok(fd) = fd {
                unsafe {
                    libc::close(fd);
                }
            }
            let _ = execute_unlink(&writer_resolver, &writer_base, &name);
        }
    }));

    for handle in threads {
        handle.join().expect("thread join");
    }

    let resolved = open_return_path(&resolver, &base, "FILE.txt", ResolverIntent::Read).unwrap();
    assert_path_ends_with(&resolved, Path::new("File.txt"));
}

#[test]
fn plan_token_dir_generation_stale_after_mutation() {
    let resolver = TestResolver::new(0);
    let temp = TempDir::new("plan_dirgen_stale");
    let base = temp.path.to_string_lossy().into_owned();

    fs::write(temp.path.join("Plan.txt"), b"data").expect("write file");

    let (_base_buf, base_view) = make_view(&base);
    let (_input_buf, input_view) = make_view("Plan.txt");

    let mut plan_before = ResolverPlan {
        size: std::mem::size_of::<ResolverPlan>() as u32,
        status: ResolverStatus::Ok,
        would_error: ResolverStatus::Ok,
        flags: 0,
        resolved_parent: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
        resolved_leaf: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
        plan_token: ResolverPlanToken {
            size: std::mem::size_of::<ResolverPlanToken>() as u32,
            op_generation: 0,
            dir_generations: ResolverBufferView {
                ptr: std::ptr::null(),
                len: 0,
            },
            reserved: [0; 6],
        },
        reserved: [0; 6],
    };
    let status = resolver_plan(
        resolver.handle,
        &base_view,
        &input_view,
        ResolverIntent::StatExists,
        &mut plan_before,
        std::ptr::null_mut(),
    );
    assert_eq!(status, ResolverStatus::Ok);

    let status = execute_mkdirs(&resolver, &base, "NewDir");
    assert_eq!(status, ResolverStatus::Ok);

    let mut plan_after = ResolverPlan {
        size: std::mem::size_of::<ResolverPlan>() as u32,
        status: ResolverStatus::Ok,
        would_error: ResolverStatus::Ok,
        flags: 0,
        resolved_parent: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
        resolved_leaf: ResolverStringView {
            ptr: std::ptr::null(),
            len: 0,
        },
        plan_token: ResolverPlanToken {
            size: std::mem::size_of::<ResolverPlanToken>() as u32,
            op_generation: 0,
            dir_generations: ResolverBufferView {
                ptr: std::ptr::null(),
                len: 0,
            },
            reserved: [0; 6],
        },
        reserved: [0; 6],
    };
    let status = resolver_plan(
        resolver.handle,
        &base_view,
        &input_view,
        ResolverIntent::StatExists,
        &mut plan_after,
        std::ptr::null_mut(),
    );
    assert_eq!(status, ResolverStatus::Ok);

    plan_before.plan_token.op_generation = plan_after.plan_token.op_generation;

    let status = resolver_execute_from_plan(
        resolver.handle,
        &plan_before,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_eq!(status, ResolverStatus::StalePlan);

    resolver_free_buffer(plan_before.plan_token.dir_generations);
    resolver_free_buffer(plan_after.plan_token.dir_generations);
    resolver_free_string(plan_before.resolved_parent);
    resolver_free_string(plan_before.resolved_leaf);
    resolver_free_string(plan_after.resolved_parent);
    resolver_free_string(plan_after.resolved_leaf);
}
