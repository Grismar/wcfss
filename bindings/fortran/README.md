# Fortran bindings (ISO_C_BINDING)

This directory contains a Fortran 2003 module that wraps the wcfss C ABI.

Files:
- `wcfss.f90`: Module with C interfaces and Fortran-friendly wrappers.

## Build / Link

You need to link against the wcfss shared library produced by the Rust build.
Example (Linux, Intel ifx):
```sh
ifx -c wcfss.f90
ifx -o my_app my_app.f90 wcfss.o -L/path/to/lib -lwcfss
```

On Windows (Intel oneAPI), link against the `wcfss.dll` import library
(`wcfss.lib`) and ensure `wcfss.dll` is on `PATH` at runtime.

On Linux, ensure the runtime linker can find the shared library
(e.g. set `LD_LIBRARY_PATH` or use an rpath).

## Usage

```fortran
use wcfss
type(c_ptr) :: h
type(ResolverResult) :: res
character(len=:), allocatable :: resolved
character(len=:), allocatable :: resolved_list(:)

h = wcfss_create()
call wcfss_execute_open_return_path(h, "/tmp", "file.txt", INTENT_READ, resolved)
open(unit=10, file=resolved, status="old", action="read")
call wcfss_find_matches(h, "/tmp", "FILE.TXT", resolved_list)
call wcfss_destroy(h)
```

## Error Handling

All wrapper calls return a `status` (integer). Compare against `RESOLVER_OK`.

```fortran
integer(c_int) :: status
status = wcfss_execute_mkdirs(h, "/tmp", "newdir", res)
if (status /= RESOLVER_OK) then
  print *, "mkdirs failed:", status
end if
```

## Ownership Rules

If a wrapper returns allocated buffers (e.g., plans or resolved paths), use:
- `wcfss_plan_destroy(plan)`
- `wcfss_diag_destroy(diag)`

These wrappers call `resolver_free_*` as required by the C ABI.

## Logging

Logging is quiet by default. You can enable stderr logging explicitly:

```fortran
use wcfss
integer(c_int) :: status
status = wcfss_log_set_stderr(RESOLVER_LOG_INFO)
```

You can adjust the level or disable logging later:

```fortran
status = wcfss_log_set_level(RESOLVER_LOG_DEBUG)
status = wcfss_log_disable()
```

## Notes on ifx Compatibility

The module is standard Fortran 2003 with `ISO_C_BINDING`, so no code changes
are required for ifx. The only implications are build/link details:
- Use the ifx toolchain for both compilation and linking.
- Make sure you link against the correct platform library name (`-lwcfss`
  on Linux, `wcfss.lib` on Windows).
