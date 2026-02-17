# Fortran bindings (ISO_C_BINDING)

This directory contains a Fortran 2003 module that wraps the wcfss C ABI.

Files:
- `wcfss.f90`: Module with C interfaces and Fortran-friendly wrappers.

## Build / Link

You need to link against the wcfss shared library produced by the Rust build.
Example (Linux, gfortran):
```sh
gfortran -c wcfss.f90
gfortran -o my_app my_app.f90 wcfss.o -L/path/to/lib -lwcfss
```

On Windows (MinGW), link against `wcfss.dll` import library as appropriate.

## Usage

```fortran
use wcfss
type(c_ptr) :: h
type(ResolverResult) :: res
character(len=:), allocatable :: resolved

h = wcfss_create()
call wcfss_execute_open_return_path(h, "/tmp", "file.txt", INTENT_READ, resolved)
open(unit=10, file=resolved, status="old", action="read")
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
