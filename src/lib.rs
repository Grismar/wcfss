mod common;
mod ffi;
mod resolver;

#[cfg(target_os = "windows")]
mod windows_native;
#[cfg(target_os = "windows")]
pub(crate) use windows_native::PlatformResolver;

#[cfg(target_os = "linux")]
pub mod linux_emulation;
#[cfg(target_os = "linux")]
pub(crate) use linux_emulation::PlatformResolver;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
compile_error!("wcfss only supports Windows and Linux targets.");

pub use crate::common::types::*;
pub use crate::ffi::*;
