#![cfg(windows)]

mod native_resolver {
    include!("windows/native_resolver.rs");
}
mod logging {
    include!("windows/logging.rs");
}
