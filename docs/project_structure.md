wcfss/
├── Cargo.toml
├── Cargo.lock
├── build.rs             # Build-time code generation (Unicode tables)
├── data/
│   └── unicode/
│       └── 15.1/
│           └── UnicodeData.txt
├── src/
│   ├── lib.rs              # Public C ABI + platform dispatch
│   ├── common/             # Shared types
│   │   ├── mod.rs
│   │   └── types.rs        # Status codes, config structs, FFI structs
│   ├── windows_native/     # Windows implementation
│   │   ├── mod.rs
│   │   ├── resolver.rs
│   │   └── win32.rs         # Win32 bindings/helpers
│   └── linux_emulation/    # Linux implementation
│       ├── mod.rs
│       ├── resolver.rs
│       ├── parser.rs
│       └── dirindex.rs
├── tests/
│   ├── windows/            # Windows-specific tests
│   ├── linux/              # Linux-specific tests
│   ├── windows.rs          # Test harness for Windows targets
│   └── linux.rs            # Test harness for Linux targets
└── docs/
    ├── spec.md
    ├── environment.md
    └── project_structure.md
