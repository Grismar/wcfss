"""
Python ctypes bindings for the wcfss C ABI.

Usage:
    from wcfss import Resolver, ResolverConfig, Intent

    with Resolver(ResolverConfig()) as r:
        plan = r.plan("/tmp", "file.txt", Intent.STAT_EXISTS)
        resolved = r.execute_open_return_path("/tmp", "file.txt", Intent.READ)
"""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, List


class Status(IntEnum):
    OK = 0
    NOT_FOUND = 1
    EXISTS = 2
    COLLISION = 3
    UNMAPPED_ROOT = 4
    UNSUPPORTED_ABSOLUTE_PATH = 5
    ESCAPES_ROOT = 6
    ENCODING_ERROR = 7
    TOO_MANY_SYMLINKS = 8
    NOT_A_DIRECTORY = 9
    PERMISSION_DENIED = 10
    BASE_DIR_INVALID = 11
    PATH_TOO_LONG = 12
    STALE_PLAN = 13
    IO_ERROR = 14
    INVALID_PATH = 15


class Intent(IntEnum):
    STAT_EXISTS = 0
    READ = 1
    WRITE_TRUNCATE = 2
    WRITE_APPEND = 3
    CREATE_NEW = 4
    MKDIRS = 5
    RENAME = 6


class LogLevel(IntEnum):
    OFF = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5


RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY = 1 << 0
RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS = 1 << 1

RESOLVER_PLAN_TARGET_EXISTS = 1 << 0
RESOLVER_PLAN_TARGET_IS_DIR = 1 << 1
RESOLVER_PLAN_WOULD_CREATE = 1 << 2
RESOLVER_PLAN_WOULD_TRUNCATE = 1 << 3


class ResolverError(Exception):
    """Base error for resolver failures."""

    def __init__(self, status: Status, message: str = "") -> None:
        super().__init__(f"{status.name}{': ' + message if message else ''}")
        self.status = status


class NotFoundError(ResolverError):
    pass


class CollisionError(ResolverError):
    pass


class EncodingError(ResolverError):
    pass


class UnsupportedAbsolutePathError(ResolverError):
    pass


class UnmappedRootError(ResolverError):
    pass


class EscapesRootError(ResolverError):
    pass


class BaseDirInvalidError(ResolverError):
    pass


class PathTooLongError(ResolverError):
    pass


class StalePlanError(ResolverError):
    pass


_STATUS_TO_ERROR = {
    Status.NOT_FOUND: NotFoundError,
    Status.COLLISION: CollisionError,
    Status.ENCODING_ERROR: EncodingError,
    Status.UNSUPPORTED_ABSOLUTE_PATH: UnsupportedAbsolutePathError,
    Status.UNMAPPED_ROOT: UnmappedRootError,
    Status.ESCAPES_ROOT: EscapesRootError,
    Status.BASE_DIR_INVALID: BaseDirInvalidError,
    Status.PATH_TOO_LONG: PathTooLongError,
    Status.STALE_PLAN: StalePlanError,
}


class ResolverStringView(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class ResolverBufferView(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class ResolverLogRecord(ctypes.Structure):
    _fields_ = [
        ("level", ctypes.c_int),
        ("target", ResolverStringView),
        ("message", ResolverStringView),
        ("file", ResolverStringView),
        ("line", ctypes.c_uint32),
    ]


class ResolverConfig(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("ttl_fast_ms", ctypes.c_uint64),
        ("reserved", ctypes.c_uint64 * 5),
    ]

    def __init__(self, flags: int = 0, ttl_fast_ms: int = 0) -> None:
        super().__init__()
        self.size = ctypes.sizeof(ResolverConfig)
        self.flags = flags
        self.ttl_fast_ms = ttl_fast_ms
        self.reserved = (ctypes.c_uint64 * 5)(*([0] * 5))


class ResolverRootMappingEntry(ctypes.Structure):
    _fields_ = [("key", ResolverStringView), ("value", ResolverStringView)]


class ResolverRootMapping(ctypes.Structure):
    _fields_ = [("entries", ctypes.POINTER(ResolverRootMappingEntry)), ("len", ctypes.c_size_t)]


class ResolverDirGeneration(ctypes.Structure):
    _fields_ = [("dev", ctypes.c_uint64), ("ino", ctypes.c_uint64), ("generation", ctypes.c_uint64)]


class ResolverDirStamp(ctypes.Structure):
    _fields_ = [
        ("dev", ctypes.c_uint64),
        ("ino", ctypes.c_uint64),
        ("mtime_sec", ctypes.c_int64),
        ("mtime_nsec", ctypes.c_int64),
        ("ctime_sec", ctypes.c_int64),
        ("ctime_nsec", ctypes.c_int64),
    ]


class ResolverPlanToken(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("op_generation", ctypes.c_uint64),
        ("unicode_version_generation", ctypes.c_uint64),
        ("root_mapping_generation", ctypes.c_uint64),
        ("absolute_path_support_generation", ctypes.c_uint64),
        ("encoding_policy_generation", ctypes.c_uint64),
        ("symlink_policy_generation", ctypes.c_uint64),
        ("dir_generations", ResolverBufferView),
        ("touched_dir_stamps", ResolverBufferView),
        ("reserved", ctypes.c_uint64 * 4),
    ]


class ResolverPlan(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("status", ctypes.c_int),
        ("would_error", ctypes.c_int),
        ("flags", ctypes.c_uint32),
        ("intent", ctypes.c_int),
        ("resolved_parent", ResolverStringView),
        ("resolved_leaf", ResolverStringView),
        ("plan_token", ResolverPlanToken),
        ("reserved", ctypes.c_uint64 * 6),
    ]


class ResolverResult(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("reserved", ctypes.c_uint64 * 6)]


class ResolverDiagEntry(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("severity", ctypes.c_uint32),
        ("context", ResolverStringView),
        ("detail", ResolverStringView),
    ]


class ResolverDiag(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("entries", ResolverBufferView), ("reserved", ctypes.c_uint64 * 7)]


class ResolverMetrics(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("dirindex_cache_hits", ctypes.c_uint64),
        ("dirindex_cache_misses", ctypes.c_uint64),
        ("dirindex_rebuilds", ctypes.c_uint64),
        ("stamp_validations", ctypes.c_uint64),
        ("collisions", ctypes.c_uint64),
        ("invalid_utf8_entries", ctypes.c_uint64),
        ("encoding_errors", ctypes.c_uint64),
        ("plans_rejected_stale", ctypes.c_uint64),
        ("reserved", ctypes.c_uint64 * 4),
    ]


class ResolverResolvedPath(ctypes.Structure):
    _fields_ = [("value", ResolverStringView)]


def _load_library(path: Optional[str] = None) -> ctypes.CDLL:
    if path:
        return ctypes.CDLL(path)
    env_path = os.environ.get("WCFSS_LIB")
    if env_path:
        return ctypes.CDLL(env_path)
    name = ctypes.util.find_library("wcfss")
    if name is None:
        # Fallback names
        for candidate in ("libwcfss.so", "libwcfss.dylib", "wcfss.dll"):
            try:
                return ctypes.CDLL(candidate)
            except OSError:
                continue
        raise OSError("Could not locate wcfss library. Set WCFSS_LIB to explicit path.")
    return ctypes.CDLL(name)


_LOG_LIB: Optional[ctypes.CDLL] = None
_LOG_BOUND = False
_LOG_CALLBACK = None


def _get_log_lib() -> ctypes.CDLL:
    global _LOG_LIB
    if _LOG_LIB is None:
        _LOG_LIB = _load_library()
    return _LOG_LIB


def _bind_logging(lib: ctypes.CDLL) -> None:
    global _LOG_BOUND
    if _LOG_BOUND:
        return
    lib.resolver_log_set_stderr.argtypes = [ctypes.c_int]
    lib.resolver_log_set_stderr.restype = ctypes.c_int
    lib.resolver_log_set_callback.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.resolver_log_set_callback.restype = ctypes.c_int
    lib.resolver_log_set_level.argtypes = [ctypes.c_int]
    lib.resolver_log_set_level.restype = ctypes.c_int
    lib.resolver_log_disable.argtypes = []
    lib.resolver_log_disable.restype = ctypes.c_int
    _LOG_BOUND = True


def _ensure_trace_level() -> None:
    if logging.getLevelName(5) != "TRACE":
        logging.addLevelName(5, "TRACE")


def _sv_to_str(view: ResolverStringView) -> str:
    if not view.ptr or not view.len:
        return ""
    return ctypes.string_at(view.ptr, view.len).decode("utf-8", errors="replace")


def _parse_log_level(level) -> LogLevel:
    if isinstance(level, LogLevel):
        return level
    if isinstance(level, str):
        key = level.strip().upper()
        mapping = {
            "OFF": LogLevel.OFF,
            "ERROR": LogLevel.ERROR,
            "WARN": LogLevel.WARN,
            "WARNING": LogLevel.WARN,
            "INFO": LogLevel.INFO,
            "DEBUG": LogLevel.DEBUG,
            "TRACE": LogLevel.TRACE,
        }
        if key in mapping:
            return mapping[key]
        raise ValueError(f"unknown log level: {level}")
    if isinstance(level, int):
        if level <= 0:
            return LogLevel.OFF
        if level >= logging.ERROR:
            return LogLevel.ERROR
        if level >= logging.WARNING:
            return LogLevel.WARN
        if level >= logging.INFO:
            return LogLevel.INFO
        if level >= logging.DEBUG:
            return LogLevel.DEBUG
        return LogLevel.TRACE
    raise TypeError("level must be str, int, or LogLevel")


def _python_level_for_log(level: LogLevel) -> int:
    if level == LogLevel.OFF:
        return logging.NOTSET
    if level == LogLevel.ERROR:
        return logging.ERROR
    if level == LogLevel.WARN:
        return logging.WARNING
    if level == LogLevel.INFO:
        return logging.INFO
    if level == LogLevel.DEBUG:
        return logging.DEBUG
    return 5


def init_logging(level: "str | int | LogLevel" = "INFO", logger_name: str = "wcfss") -> None:
    """Connect Rust logs to Python logging. Idempotent and thread-safe."""
    _ensure_trace_level()
    lib = _get_log_lib()
    _bind_logging(lib)

    parsed_level = _parse_log_level(level)
    callback_type = ctypes.CFUNCTYPE(None, ctypes.POINTER(ResolverLogRecord), ctypes.c_void_p)
    logger = logging.getLogger(logger_name)

    def _callback(record_ptr, _user_data):
        if not record_ptr:
            return
        rec = record_ptr.contents
        try:
            level_value = LogLevel(rec.level)
        except ValueError:
            level_value = LogLevel.INFO
        msg = _sv_to_str(rec.message)
        target = _sv_to_str(rec.target)
        file = _sv_to_str(rec.file)
        logger.log(
            _python_level_for_log(level_value),
            msg,
            extra={"wcfss_target": target, "wcfss_file": file, "wcfss_line": rec.line},
        )

    global _LOG_CALLBACK
    _LOG_CALLBACK = callback_type(_callback)
    status = Status(lib.resolver_log_set_callback(_LOG_CALLBACK, None, int(parsed_level)))
    _raise_for_status(status)


def enable_stderr_logging(level: "str | int | LogLevel" = "INFO") -> None:
    """Explicitly enable stderr logging from Rust. Idempotent."""
    lib = _get_log_lib()
    _bind_logging(lib)
    parsed_level = _parse_log_level(level)
    status = Status(lib.resolver_log_set_stderr(int(parsed_level)))
    _raise_for_status(status)


def set_log_level(level: "str | int | LogLevel") -> None:
    """Adjust the log level without changing the output target."""
    lib = _get_log_lib()
    _bind_logging(lib)
    parsed_level = _parse_log_level(level)
    status = Status(lib.resolver_log_set_level(int(parsed_level)))
    _raise_for_status(status)


def disable_logging() -> None:
    """Disable Rust logging output."""
    lib = _get_log_lib()
    _bind_logging(lib)
    status = Status(lib.resolver_log_disable())
    _raise_for_status(status)


def _as_view(value: str) -> ResolverStringView:
    data = value.encode("utf-8")
    buf = ctypes.create_string_buffer(data)
    view = ResolverStringView(ctypes.cast(buf, ctypes.c_void_p), len(data))
    view._buffer = buf  # keep alive
    return view


def _string_from_view(view: ResolverStringView, lib: ctypes.CDLL) -> str:
    if not view.ptr or view.len == 0:
        return ""
    raw = ctypes.string_at(view.ptr, view.len)
    lib.resolver_free_string(view)
    return raw.decode("utf-8", errors="replace")


def _raise_for_status(status: Status, diag: Optional[List["DiagEntry"]] = None) -> None:
    if status == Status.OK:
        return
    message = ""
    if diag:
        message = "; ".join(f"{d.code}:{d.detail}" for d in diag if d.detail)
    exc_cls = _STATUS_TO_ERROR.get(status, ResolverError)
    raise exc_cls(status, message)


@dataclass
class DiagEntry:
    code: int
    severity: int
    context: str
    detail: str


def _read_diag(diag: ResolverDiag, lib: ctypes.CDLL) -> List[DiagEntry]:
    entries: List[DiagEntry] = []
    if diag.entries.ptr and diag.entries.len:
        count = diag.entries.len
        array_type = ResolverDiagEntry * count
        array = ctypes.cast(diag.entries.ptr, ctypes.POINTER(array_type)).contents
        for entry in array:
            ctx = ""
            det = ""
            if entry.context.ptr and entry.context.len:
                ctx = ctypes.string_at(entry.context.ptr, entry.context.len).decode("utf-8", errors="replace")
            if entry.detail.ptr and entry.detail.len:
                det = ctypes.string_at(entry.detail.ptr, entry.detail.len).decode("utf-8", errors="replace")
            entries.append(DiagEntry(entry.code, entry.severity, ctx, det))
        lib.resolver_free_buffer(diag.entries)
        diag.entries.ptr = None
        diag.entries.len = 0
    return entries


class Plan:
    """Owned plan token; frees any allocated buffers on close."""

    def __init__(self, plan: ResolverPlan, lib: ctypes.CDLL) -> None:
        self._plan = plan
        self._lib = lib

    @property
    def raw(self) -> ResolverPlan:
        return self._plan

    def close(self) -> None:
        self._lib.resolver_free_buffer(self._plan.plan_token.dir_generations)
        self._lib.resolver_free_buffer(self._plan.plan_token.touched_dir_stamps)
        self._lib.resolver_free_string(self._plan.resolved_parent)
        self._lib.resolver_free_string(self._plan.resolved_leaf)
        self._plan.plan_token.dir_generations.ptr = None
        self._plan.plan_token.dir_generations.len = 0
        self._plan.plan_token.touched_dir_stamps.ptr = None
        self._plan.plan_token.touched_dir_stamps.len = 0
        self._plan.resolved_parent.ptr = None
        self._plan.resolved_parent.len = 0
        self._plan.resolved_leaf.ptr = None
        self._plan.resolved_leaf.len = 0

    def __enter__(self) -> "Plan":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class Resolver:
    """High-level resolver wrapper with context manager support."""

    def __init__(self, config: Optional[ResolverConfig] = None, lib_path: Optional[str] = None) -> None:
        self._lib = _load_library(lib_path)
        self._bind()
        cfg_ptr = ctypes.byref(config) if config is not None else None
        self._handle = self._lib.resolver_create(cfg_ptr)
        if not self._handle:
            raise ResolverError(Status.INVALID_PATH, "failed to create resolver")

    def _bind(self) -> None:
        lib = self._lib
        lib.resolver_create.restype = ctypes.c_void_p
        lib.resolver_create.argtypes = [ctypes.POINTER(ResolverConfig)]
        lib.resolver_destroy.argtypes = [ctypes.c_void_p]

        lib.resolver_set_root_mapping.argtypes = [ctypes.c_void_p, ctypes.POINTER(ResolverRootMapping), ctypes.POINTER(ResolverDiag)]
        lib.resolver_set_root_mapping.restype = ctypes.c_int

        lib.resolver_plan.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.c_int,
            ctypes.POINTER(ResolverPlan),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_plan.restype = ctypes.c_int

        lib.resolver_execute_mkdirs.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverResult),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_execute_mkdirs.restype = ctypes.c_int

        lib.resolver_execute_rename.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverResult),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_execute_rename.restype = ctypes.c_int

        lib.resolver_execute_unlink.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverResult),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_execute_unlink.restype = ctypes.c_int

        lib.resolver_execute_open_return_path.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.c_int,
            ctypes.POINTER(ResolverResolvedPath),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_execute_open_return_path.restype = ctypes.c_int

        lib.resolver_execute_open_return_fd.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverStringView),
            ctypes.POINTER(ResolverStringView),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_execute_open_return_fd.restype = ctypes.c_int

        lib.resolver_execute_from_plan.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ResolverPlan),
            ctypes.POINTER(ResolverResult),
            ctypes.POINTER(ResolverDiag),
        ]
        lib.resolver_execute_from_plan.restype = ctypes.c_int

        lib.resolver_get_metrics.argtypes = [ctypes.c_void_p, ctypes.POINTER(ResolverMetrics)]
        lib.resolver_get_metrics.restype = ctypes.c_int

        lib.resolver_free_string.argtypes = [ResolverStringView]
        lib.resolver_free_buffer.argtypes = [ResolverBufferView]

    def close(self) -> None:
        if self._handle:
            self._lib.resolver_destroy(self._handle)
            self._handle = None

    def __enter__(self) -> "Resolver":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _call_with_diag(self, func, *args) -> List[DiagEntry]:
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(func(*args, ctypes.byref(diag)))
        entries = _read_diag(diag, self._lib)
        _raise_for_status(status, entries)
        return entries

    def set_root_mapping(self, mapping: dict[str, str]) -> None:
        """Set drive/UNC mappings on Linux (when enabled)."""
        entries: List[ResolverRootMappingEntry] = []
        buffers = []
        for k, v in mapping.items():
            k_view = _as_view(k)
            v_view = _as_view(v)
            buffers.extend([k_view, v_view])
            entries.append(ResolverRootMappingEntry(k_view, v_view))
        if entries:
            array_type = ResolverRootMappingEntry * len(entries)
            array = array_type(*entries)
            mapping_struct = ResolverRootMapping(array, len(entries))
            diag = ResolverDiag()
            diag.size = ctypes.sizeof(ResolverDiag)
            status = Status(self._lib.resolver_set_root_mapping(self._handle, ctypes.byref(mapping_struct), ctypes.byref(diag)))
            diags = _read_diag(diag, self._lib)
            _raise_for_status(status, diags)
        else:
            mapping_struct = ResolverRootMapping(None, 0)
            status = Status(self._lib.resolver_set_root_mapping(self._handle, ctypes.byref(mapping_struct), None))
            _raise_for_status(status)

    def plan(self, base_dir: str, input_path: str, intent: Intent) -> Plan:
        """Create a plan for later execution (no side effects)."""
        plan = ResolverPlan()
        plan.size = ctypes.sizeof(ResolverPlan)
        plan.plan_token.size = ctypes.sizeof(ResolverPlanToken)
        base_view = _as_view(base_dir)
        input_view = _as_view(input_path)
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_plan(self._handle, ctypes.byref(base_view), ctypes.byref(input_view),
                                               int(intent), ctypes.byref(plan), ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)
        return Plan(plan, self._lib)

    def execute_from_plan(self, plan: Plan) -> None:
        """Execute a previously created plan."""
        result = ResolverResult()
        result.size = ctypes.sizeof(ResolverResult)
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_execute_from_plan(self._handle, ctypes.byref(plan.raw),
                                                            ctypes.byref(result), ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)

    def execute_open_return_path(self, base_dir: str, input_path: str, intent: Intent) -> str:
        """Resolve and open path, returning the resolved path."""
        base_view = _as_view(base_dir)
        input_view = _as_view(input_path)
        out = ResolverResolvedPath(ResolverStringView(None, 0))
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_execute_open_return_path(self._handle,
                                                                    ctypes.byref(base_view),
                                                                    ctypes.byref(input_view),
                                                                    int(intent),
                                                                    ctypes.byref(out),
                                                                    ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)
        return _string_from_view(out.value, self._lib)

    def execute_open_return_fd(self, base_dir: str, input_path: str, intent: Intent) -> int:
        """Resolve and open path, returning an OS file descriptor."""
        base_view = _as_view(base_dir)
        input_view = _as_view(input_path)
        fd = ctypes.c_int(-1)
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_execute_open_return_fd(self._handle,
                                                                  ctypes.byref(base_view),
                                                                  ctypes.byref(input_view),
                                                                  int(intent),
                                                                  ctypes.byref(fd),
                                                                  ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)
        return fd.value

    def execute_mkdirs(self, base_dir: str, input_path: str) -> None:
        """Create directories according to Windows-compatible semantics."""
        base_view = _as_view(base_dir)
        input_view = _as_view(input_path)
        result = ResolverResult()
        result.size = ctypes.sizeof(ResolverResult)
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_execute_mkdirs(self._handle, ctypes.byref(base_view),
                                                         ctypes.byref(input_view), ctypes.byref(result),
                                                         ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)

    def execute_unlink(self, base_dir: str, input_path: str) -> None:
        """Unlink a file according to Windows-compatible semantics."""
        base_view = _as_view(base_dir)
        input_view = _as_view(input_path)
        result = ResolverResult()
        result.size = ctypes.sizeof(ResolverResult)
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_execute_unlink(self._handle, ctypes.byref(base_view),
                                                         ctypes.byref(input_view), ctypes.byref(result),
                                                         ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)

    def execute_rename(self, base_dir: str, from_path: str, to_path: str) -> None:
        """Rename a file according to Windows-compatible semantics."""
        base_view = _as_view(base_dir)
        from_view = _as_view(from_path)
        to_view = _as_view(to_path)
        result = ResolverResult()
        result.size = ctypes.sizeof(ResolverResult)
        diag = ResolverDiag()
        diag.size = ctypes.sizeof(ResolverDiag)
        status = Status(self._lib.resolver_execute_rename(self._handle, ctypes.byref(base_view),
                                                         ctypes.byref(from_view), ctypes.byref(to_view),
                                                         ctypes.byref(result), ctypes.byref(diag)))
        diags = _read_diag(diag, self._lib)
        _raise_for_status(status, diags)

    def get_metrics(self) -> ResolverMetrics:
        """Fetch resolver metrics counters."""
        metrics = ResolverMetrics()
        metrics.size = ctypes.sizeof(ResolverMetrics)
        status = Status(self._lib.resolver_get_metrics(self._handle, ctypes.byref(metrics)))
        _raise_for_status(status)
        return metrics


# Example:
#
# from wcfss import Resolver, ResolverConfig, Intent
#
# with Resolver(ResolverConfig()) as r:
#     try:
#         resolved = r.execute_open_return_path("/tmp", "file.txt", Intent.READ)
#         with open(resolved, "rb") as f:
#             data = f.read()
#     except ResolverError as exc:
#         print("Resolver failed:", exc)
