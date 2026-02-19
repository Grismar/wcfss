# Rust bindings (safe wrapper)

This directory contains a safe Rust wrapper over the wcfss C ABI.

Files:
- `lib.rs`: wrapper types and functions

## Linking

This module expects the C ABI to be available as a shared library named `wcfss`.
If you link statically, adjust the `#[link(name = \"wcfss\")]` attribute accordingly.

## Usage

```rust
use wcfss_bindings::{Resolver, Intent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = Resolver::new(None)?;
    let plan = resolver.plan("/tmp", "file.txt", Intent::StatExists)?;
    resolver.execute_from_plan(&plan)?;
    Ok(())
}
```

## Error Handling

All APIs return `Result<T, Error>`, where `Error::Status` wraps a `Status` code:

```rust
use wcfss_bindings::{Resolver, Intent, Error};

match Resolver::new(None) {
    Ok(r) => {
        let _ = r.execute_open_return_path("/tmp", "file.txt", Intent::Read);
    }
    Err(Error::Status(status)) => eprintln!("resolver failed: {:?}", status),
    Err(err) => eprintln!("resolver error: {:?}", err),
}
```

## Ownership Rules

`Resolver` and `Plan` free C-allocated buffers automatically via `Drop`.

## Logging

The core library is quiet by default. You can opt in to stderr logging:

```rust
use wcfss_bindings::{enable_stderr_logging, LogLevel};

enable_stderr_logging(LogLevel::Info)?;
```

Or adjust the level / disable:

```rust
use wcfss_bindings::{set_log_level, disable_logging, LogLevel};

set_log_level(LogLevel::Debug)?;
disable_logging()?;
```
