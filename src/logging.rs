use crate::common::types::{ResolverLogLevel, ResolverLogRecord, ResolverStatus, ResolverStringView};

use core::ffi::{c_char, c_void};
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

pub type ResolverLogCallback = Option<extern "C" fn(record: *const ResolverLogRecord, user_data: *mut c_void)>;

const MODE_DISABLED: u8 = 0;
const MODE_STDERR: u8 = 1;
const MODE_CALLBACK: u8 = 2;

struct CallbackState {
    callback: ResolverLogCallback,
    user_data: usize,
}

impl CallbackState {
    const fn new() -> Self {
        Self {
            callback: None,
            user_data: 0,
        }
    }
}

pub struct WcfssLogger {
    mode: AtomicU8,
    level: AtomicU8,
    callback: Mutex<CallbackState>,
}

impl WcfssLogger {
    const fn new() -> Self {
        Self {
            mode: AtomicU8::new(MODE_DISABLED),
            level: AtomicU8::new(ResolverLogLevel::Off as u8),
            callback: Mutex::new(CallbackState::new()),
        }
    }

    fn level(&self) -> Option<Level> {
        level_from_u8(self.level.load(Ordering::Relaxed))
    }

    fn set_level(&self, level: ResolverLogLevel) {
        self.level.store(level as u8, Ordering::Relaxed);
        log::set_max_level(level_filter_from_u8(level as u8));
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::Relaxed);
    }

    fn set_callback(&self, callback: ResolverLogCallback, user_data: *mut c_void) {
        if let Ok(mut state) = self.callback.lock() {
            state.callback = callback;
            state.user_data = user_data as usize;
        }
    }
}

impl Log for WcfssLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let Some(level) = self.level() else {
            return false;
        };
        metadata.level() <= level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        match self.mode.load(Ordering::Relaxed) {
            MODE_STDERR => {
                eprintln!("[wcfss][{}] {}", record.level(), record.args());
            }
            MODE_CALLBACK => {
                let Ok(state) = self.callback.lock() else {
                    return;
                };
                let Some(callback) = state.callback else {
                    return;
                };
                let message = record.args().to_string();
                let target = record.target();
                let file = record.file().unwrap_or("");
                let line = record.line().unwrap_or(0);

                let msg_view = string_view_from_str(&message);
                let target_view = string_view_from_str(target);
                let file_view = string_view_from_str(file);

                let record = ResolverLogRecord {
                    level: resolver_level_from_log(record.level()),
                    target: target_view,
                    message: msg_view,
                    file: file_view,
                    line,
                };

                callback(&record as *const ResolverLogRecord, state.user_data as *mut c_void);
            }
            _ => {}
        }
    }

    fn flush(&self) {}
}

static LOGGER: WcfssLogger = WcfssLogger::new();
static LOGGER_STATE: OnceLock<LoggerInstall> = OnceLock::new();

#[derive(Copy, Clone)]
enum LoggerInstall {
    Installed,
    External,
}

fn init_logger() -> LoggerInstall {
    *LOGGER_STATE.get_or_init(|| match log::set_logger(&LOGGER) {
        Ok(()) => {
            log::set_max_level(LevelFilter::Off);
            LoggerInstall::Installed
        }
        Err(_) => LoggerInstall::External,
    })
}

fn level_filter_from_u8(level: u8) -> LevelFilter {
    match level {
        x if x == ResolverLogLevel::Error as u8 => LevelFilter::Error,
        x if x == ResolverLogLevel::Warn as u8 => LevelFilter::Warn,
        x if x == ResolverLogLevel::Info as u8 => LevelFilter::Info,
        x if x == ResolverLogLevel::Debug as u8 => LevelFilter::Debug,
        x if x == ResolverLogLevel::Trace as u8 => LevelFilter::Trace,
        _ => LevelFilter::Off,
    }
}

fn level_from_u8(level: u8) -> Option<Level> {
    match level {
        x if x == ResolverLogLevel::Error as u8 => Some(Level::Error),
        x if x == ResolverLogLevel::Warn as u8 => Some(Level::Warn),
        x if x == ResolverLogLevel::Info as u8 => Some(Level::Info),
        x if x == ResolverLogLevel::Debug as u8 => Some(Level::Debug),
        x if x == ResolverLogLevel::Trace as u8 => Some(Level::Trace),
        _ => None,
    }
}

fn resolver_level_from_log(level: Level) -> ResolverLogLevel {
    match level {
        Level::Error => ResolverLogLevel::Error,
        Level::Warn => ResolverLogLevel::Warn,
        Level::Info => ResolverLogLevel::Info,
        Level::Debug => ResolverLogLevel::Debug,
        Level::Trace => ResolverLogLevel::Trace,
    }
}

fn string_view_from_str(value: &str) -> ResolverStringView {
    ResolverStringView {
        ptr: value.as_ptr() as *const c_char,
        len: value.len(),
    }
}

pub fn log_set_stderr(level: ResolverLogLevel) -> ResolverStatus {
    if matches!(init_logger(), LoggerInstall::External) {
        return ResolverStatus::IoError;
    }
    LOGGER.set_mode(MODE_STDERR);
    LOGGER.set_level(level);
    ResolverStatus::Ok
}

pub fn log_set_callback(callback: ResolverLogCallback, user_data: *mut c_void, level: ResolverLogLevel) -> ResolverStatus {
    if callback.is_none() {
        return log_disable();
    }
    if matches!(init_logger(), LoggerInstall::External) {
        return ResolverStatus::IoError;
    }
    LOGGER.set_callback(callback, user_data);
    LOGGER.set_mode(MODE_CALLBACK);
    LOGGER.set_level(level);
    ResolverStatus::Ok
}

pub fn log_set_level(level: ResolverLogLevel) -> ResolverStatus {
    match init_logger() {
        LoggerInstall::Installed => {
            LOGGER.set_level(level);
            ResolverStatus::Ok
        }
        LoggerInstall::External => {
            log::set_max_level(level_filter_from_u8(level as u8));
            ResolverStatus::Ok
        }
    }
}

pub fn log_disable() -> ResolverStatus {
    match init_logger() {
        LoggerInstall::Installed => {
            LOGGER.set_mode(MODE_DISABLED);
            LOGGER.set_level(ResolverLogLevel::Off);
            ResolverStatus::Ok
        }
        LoggerInstall::External => {
            log::set_max_level(LevelFilter::Off);
            ResolverStatus::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_init_is_idempotent() {
        assert_eq!(log_disable(), ResolverStatus::Ok);
        assert_eq!(log_set_level(ResolverLogLevel::Warn), ResolverStatus::Ok);
        assert_eq!(log_set_level(ResolverLogLevel::Warn), ResolverStatus::Ok);
        assert_eq!(log_set_stderr(ResolverLogLevel::Error), ResolverStatus::Ok);
        assert_eq!(log_disable(), ResolverStatus::Ok);
    }
}
