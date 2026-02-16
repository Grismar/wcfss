use crate::common::types::*;
use crate::resolver::Resolver;
use crate::PlatformResolver;

#[repr(C)]
pub struct ResolverHandle {
    inner: Box<dyn Resolver>,
}

fn status_invalid_handle() -> ResolverStatus {
    ResolverStatus::InvalidPath
}

#[no_mangle]
pub extern "C" fn resolver_create(config: *const ResolverConfig) -> *mut ResolverHandle {
    // TODO(ffi): validate config and handle allocation failures.
    let resolver = PlatformResolver::new(config);
    let handle = ResolverHandle {
        inner: Box::new(resolver),
    };
    Box::into_raw(Box::new(handle))
}

#[no_mangle]
pub extern "C" fn resolver_destroy(handle: *mut ResolverHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn resolver_set_root_mapping(
    handle: *mut ResolverHandle,
    mapping: *const ResolverRootMapping,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate inputs and thread-safety requirements.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h.inner.set_root_mapping(mapping, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_plan(
    handle: *mut ResolverHandle,
    base_dir: *const ResolverStringView,
    input_path: *const ResolverStringView,
    intent: ResolverIntent,
    out_plan: *mut ResolverPlan,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate pointers and sizes for out_plan/out_diag.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h
            .inner
            .plan(base_dir, input_path, intent, out_plan, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_execute_mkdirs(
    handle: *mut ResolverHandle,
    base_dir: *const ResolverStringView,
    input_path: *const ResolverStringView,
    out_result: *mut ResolverResult,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate pointers and sizes for out_result/out_diag.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h
            .inner
            .execute_mkdirs(base_dir, input_path, out_result, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_execute_rename(
    handle: *mut ResolverHandle,
    base_dir: *const ResolverStringView,
    from_path: *const ResolverStringView,
    to_path: *const ResolverStringView,
    out_result: *mut ResolverResult,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate pointers and sizes for out_result/out_diag.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h
            .inner
            .execute_rename(base_dir, from_path, to_path, out_result, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_execute_unlink(
    handle: *mut ResolverHandle,
    base_dir: *const ResolverStringView,
    input_path: *const ResolverStringView,
    out_result: *mut ResolverResult,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate pointers and sizes for out_result/out_diag.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h
            .inner
            .execute_unlink(base_dir, input_path, out_result, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_execute_open_return_path(
    handle: *mut ResolverHandle,
    base_dir: *const ResolverStringView,
    input_path: *const ResolverStringView,
    intent: ResolverIntent,
    out_resolved_path: *mut ResolverResolvedPath,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate pointers and sizes for out_resolved_path/out_diag.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h.inner.execute_open_return_path(
            base_dir,
            input_path,
            intent,
            out_resolved_path,
            out_diag,
        ),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_execute_open_return_fd(
    handle: *mut ResolverHandle,
    base_dir: *const ResolverStringView,
    input_path: *const ResolverStringView,
    intent: ResolverIntent,
    out_fd: *mut i32,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate pointers and out_fd.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h
            .inner
            .execute_open_return_fd(base_dir, input_path, intent, out_fd, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_execute_from_plan(
    handle: *mut ResolverHandle,
    plan: *const ResolverPlan,
    out_result: *mut ResolverResult,
    out_diag: *mut ResolverDiag,
) -> ResolverStatus {
    // TODO(ffi): validate plan pointer and sizes.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h.inner.execute_from_plan(plan, out_result, out_diag),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_get_metrics(
    handle: *mut ResolverHandle,
    out_metrics: *mut ResolverMetrics,
) -> ResolverStatus {
    // TODO(ffi): validate out_metrics pointer and size.
    let handle = unsafe { handle.as_ref() };
    match handle {
        Some(h) => h.inner.get_metrics(out_metrics),
        None => status_invalid_handle(),
    }
}

#[no_mangle]
pub extern "C" fn resolver_free_string(value: ResolverStringView) {
    if value.ptr.is_null() {
        return;
    }
    unsafe {
        libc::free(value.ptr as *mut libc::c_void);
    }
}
