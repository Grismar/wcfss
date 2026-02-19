use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use wcfss::{
    resolver_log_disable, resolver_log_set_callback, resolver_log_set_level, ResolverLogLevel,
    ResolverLogRecord, ResolverStatus,
};

static LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOG_MUTEX: Mutex<()> = Mutex::new(());
const TARGET: &str = "wcfss::logging_test";

extern "C" fn log_callback(record: *const ResolverLogRecord, user_data: *mut c_void) {
    if record.is_null() {
        return;
    }
    let rec = unsafe { &*record };
    let target = unsafe { std::slice::from_raw_parts(rec.target.ptr as *const u8, rec.target.len) };
    if target != TARGET.as_bytes() {
        return;
    }
    LOG_COUNT.fetch_add(1, Ordering::SeqCst);
    if !user_data.is_null() {
        let counter = unsafe { &*(user_data as *const AtomicUsize) };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn logging_callback_receives_records() {
    let _guard = LOG_MUTEX.lock().unwrap();
    resolver_log_disable();
    LOG_COUNT.store(0, Ordering::SeqCst);

    let user_counter = Box::new(AtomicUsize::new(0));
    let user_ptr = Box::into_raw(user_counter) as *mut c_void;

    let status = resolver_log_set_callback(Some(log_callback), user_ptr, ResolverLogLevel::Info);
    assert_eq!(status, ResolverStatus::Ok);

    log::info!(target: TARGET, "logging smoke test");
    log::debug!(target: TARGET, "debug should be filtered");

    assert!(LOG_COUNT.load(Ordering::SeqCst) >= 1);
    let user_count = unsafe { &*(user_ptr as *const AtomicUsize) }.load(Ordering::SeqCst);
    assert!(user_count >= 1);

    resolver_log_disable();
    unsafe { drop(Box::from_raw(user_ptr as *mut AtomicUsize)) };
}

#[test]
fn logging_level_off_suppresses_records() {
    let _guard = LOG_MUTEX.lock().unwrap();
    resolver_log_disable();
    LOG_COUNT.store(0, Ordering::SeqCst);

    let status = resolver_log_set_callback(Some(log_callback), std::ptr::null_mut(), ResolverLogLevel::Info);
    assert_eq!(status, ResolverStatus::Ok);

    let status = resolver_log_set_level(ResolverLogLevel::Off);
    assert_eq!(status, ResolverStatus::Ok);

    log::info!(target: TARGET, "should not be logged");
    assert_eq!(LOG_COUNT.load(Ordering::SeqCst), 0);

    resolver_log_disable();
}
