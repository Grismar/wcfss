# Python bindings (ctypes)

These bindings provide a Pythonic wrapper around the wcfss C ABI.

Files:
- `wcfss.py`: main wrapper
- `__init__.py`: convenience exports

## Requirements

The shared library must be discoverable. You can:
- Set `WCFSS_LIB=/path/to/libwcfss.so` (or `.dylib`, `.dll`)
- Or rely on system library search paths

## Install (editable, recommended for local dev)

This repo includes minimal packaging metadata so you can install directly from
the source tree and pull updates later:

```bash
pip install -e /path/to/wcfss/bindings/python
```

Then update the repo with `git pull` and your Python environment will see the
latest bindings without copying files.

Notes:
- Versioning: keep this in sync with the core crate when cutting releases.
- Branch switching: if you change branches and see stale behavior, run
  `pip uninstall -y wcfss` then `pip install -e /path/to/wcfss/bindings/python`.

## Usage

```python
from wcfss import Resolver, ResolverConfig, Intent

with Resolver(ResolverConfig()) as r:
    resolved = r.execute_open_return_path("/tmp", "file.txt", Intent.READ)
    with open(resolved, "rb") as f:
        data = f.read()
```

## Error Handling

Status codes are mapped to exceptions:
- `ResolverError` (base class)
- Specific subclasses like `CollisionError`, `EncodingError`, `StalePlanError`, etc.

```python
from wcfss import Resolver, ResolverConfig, Intent, ResolverError

try:
    with Resolver(ResolverConfig()) as r:
        r.execute_mkdirs("/tmp", "missing/dir")
except ResolverError as exc:
    print("Resolver failed:", exc)
```
