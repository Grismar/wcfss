use crate::common::types::*;
use crate::resolver::Resolver;
use crate::PlatformResolver;

#[repr(C)]
pub struct ResolverHandle {
    inner: Box<dyn Resolver>,
}

fn validate_out_plan(out_plan: *mut ResolverPlan) -> Result<(), ResolverStatus> {
    if out_plan.is_null() {
        return Err(ResolverStatus::InvalidPath);
    }
    unsafe {
        let size = (*out_plan).size;
        if size != 0 && size < std::mem::size_of::<ResolverPlan>() as u32 {
            return Err(ResolverStatus::InvalidPath);
        }
    }
    Ok(())
}

fn validate_out_diag(out_diag: *mut ResolverDiag) -> Result<(), ResolverStatus> {
    if out_diag.is_null() {
        return Ok(());
    }
    unsafe {
        let size = (*out_diag).size;
        if size != 0 && size < std::mem::size_of::<ResolverDiag>() as u32 {
            return Err(ResolverStatus::InvalidPath);
        }
    }
    Ok(())
}

fn validate_out_result(out_result: *mut ResolverResult) -> Result<(), ResolverStatus> {
    if out_result.is_null() {
        return Ok(());
    }
    unsafe {
        let size = (*out_result).size;
        if size != 0 && size < std::mem::size_of::<ResolverResult>() as u32 {
            return Err(ResolverStatus::InvalidPath);
        }
    }
    Ok(())
}

fn validate_out_resolved_path(out_resolved_path: *mut ResolverResolvedPath) -> Result<(), ResolverStatus> {
    if out_resolved_path.is_null() {
        return Err(ResolverStatus::InvalidPath);
    }
    Ok(())
}

fn validate_out_fd(out_fd: *mut i32) -> Result<(), ResolverStatus> {
    if out_fd.is_null() {
        return Err(ResolverStatus::InvalidPath);
    }
    Ok(())
}

fn validate_plan_ptr(plan: *const ResolverPlan) -> Result<(), ResolverStatus> {
    if plan.is_null() {
        return Err(ResolverStatus::InvalidPath);
    }
    unsafe {
        let size = (*plan).size;
        if size != 0 && size < std::mem::size_of::<ResolverPlan>() as u32 {
            return Err(ResolverStatus::InvalidPath);
        }
    }
    Ok(())
}

fn validate_out_metrics(out_metrics: *mut ResolverMetrics) -> Result<(), ResolverStatus> {
    if out_metrics.is_null() {
        return Err(ResolverStatus::InvalidPath);
    }
    unsafe {
        let size = (*out_metrics).size;
        if size != 0 && size < std::mem::size_of::<ResolverMetrics>() as u32 {
            return Err(ResolverStatus::InvalidPath);
        }
    }
    Ok(())
}

fn status_invalid_handle() -> ResolverStatus {
    ResolverStatus::InvalidPath
}

#[no_mangle]
pub extern "C" fn resolver_create(config: *const ResolverConfig) -> *mut ResolverHandle {
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
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_plan(out_plan) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_result(out_result) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_result(out_result) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_result(out_result) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_resolved_path(out_resolved_path) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_fd(out_fd) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_plan_ptr(plan) {
        return status;
    }
    if let Err(status) = validate_out_result(out_result) {
        return status;
    }
    if let Err(status) = validate_out_diag(out_diag) {
        return status;
    }
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
    if let Err(status) = validate_out_metrics(out_metrics) {
        return status;
    }
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

#[no_mangle]
pub extern "C" fn resolver_free_buffer(value: ResolverBufferView) {
    if value.ptr.is_null() {
        return;
    }
    unsafe {
        libc::free(value.ptr as *mut libc::c_void);
    }
}
