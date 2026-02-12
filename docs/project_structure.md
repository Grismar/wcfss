wcfss/
├── Cargo.toml
├── Cargo.lock
├── build.rs             # Build-time code generation (Unicode tables)
├── data/
│   └── unicode/
│       └── 15.1/
│           └── UnicodeData.txt
├── src/
│   ├── lib.rs              # Public C ABI
│   ├── common/             # Shared types and utilities
│   │   ├── mod.rs
│   │   ├── types.rs        # Status codes, config structs
│   │   ├── unicode.rs      # Unicode tables (if shared)
│   │   └── diagnostics.rs
│   ├── windows_native/     # Windows implementation
│   │   ├── mod.rs
│   │   ├── resolver.rs
│   │   └── win32.rs         # Win32 bindings/helpers
│   └── linux_emulation/    # Linux implementation
│       ├── mod.rs
│       ├── resolver.rs
│       ├── parser.rs
│       ├── dirindex.rs
│       └── cache.rs
├── tests/
│   ├── common/             # Shared test cases
│   ├── windows/            # Windows-specific tests
│   └── linux/              # Linux-specific tests
└── bindings/
    ├── fortran/
    ├── python/
    └── rust/
