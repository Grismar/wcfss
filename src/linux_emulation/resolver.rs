use crate::common::types::*;
use crate::resolver::Resolver;

pub struct LinuxResolver {
    _private: (),
}

impl LinuxResolver {
    pub fn new(_config: *const ResolverConfig) -> Self {
        // TODO(linux): parse config, initialize caches and Unicode tables.
        Self { _private: () }
    }
}

impl Resolver for LinuxResolver {
    fn set_root_mapping(
        &self,
        _mapping: *const ResolverRootMapping,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): update root mapping table and generations.
        ResolverStatus::UnsupportedAbsolutePath
    }

    fn plan(
        &self,
        _base_dir: *const ResolverStringView,
        _input_path: *const ResolverStringView,
        _intent: ResolverIntent,
        _out_plan: *mut ResolverPlan,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement plan/resolve with DirIndex cache.
        ResolverStatus::IoError
    }

    fn execute_mkdirs(
        &self,
        _base_dir: *const ResolverStringView,
        _input_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement mkdirs with collision handling.
        ResolverStatus::IoError
    }

    fn execute_rename(
        &self,
        _base_dir: *const ResolverStringView,
        _from_path: *const ResolverStringView,
        _to_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement rename/move with invalidation.
        ResolverStatus::IoError
    }

    fn execute_unlink(
        &self,
        _base_dir: *const ResolverStringView,
        _input_path: *const ResolverStringView,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement unlink with invalidation.
        ResolverStatus::IoError
    }

    fn execute_open_return_path(
        &self,
        _base_dir: *const ResolverStringView,
        _input_path: *const ResolverStringView,
        _intent: ResolverIntent,
        _out_resolved_path: *mut ResolverResolvedPath,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement open-return-path with case-insensitive resolve.
        ResolverStatus::IoError
    }

    fn execute_open_return_fd(
        &self,
        _base_dir: *const ResolverStringView,
        _input_path: *const ResolverStringView,
        _intent: ResolverIntent,
        _out_fd: *mut i32,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): implement open-return-fd.
        ResolverStatus::IoError
    }

    fn execute_from_plan(
        &self,
        _plan: *const ResolverPlan,
        _out_result: *mut ResolverResult,
        _out_diag: *mut ResolverDiag,
    ) -> ResolverStatus {
        // TODO(linux): validate plan token and execute.
        ResolverStatus::IoError
    }

    fn get_metrics(&self, _out_metrics: *mut ResolverMetrics) -> ResolverStatus {
        // TODO(linux): populate metrics counters.
        ResolverStatus::Ok
    }
}
