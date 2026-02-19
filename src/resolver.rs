use crate::common::types::*;

pub trait Resolver: Send + Sync {
    fn set_root_mapping(
        &self,
        mapping: *const ResolverRootMapping,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn plan(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_plan: *mut ResolverPlan,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn execute_mkdirs(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn execute_rename(
        &self,
        base_dir: *const ResolverStringView,
        from_path: *const ResolverStringView,
        to_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn execute_unlink(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn execute_open_return_path(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_resolved_path: *mut ResolverResolvedPath,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn execute_open_return_fd(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        intent: ResolverIntent,
        out_fd: *mut i32,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn execute_from_plan(
        &self,
        plan: *const ResolverPlan,
        out_result: *mut ResolverResult,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn find_matches(
        &self,
        base_dir: *const ResolverStringView,
        input_path: *const ResolverStringView,
        out_list: *mut ResolverStringList,
        out_diag: *mut ResolverDiag,
    ) -> ResolverStatus;

    fn get_metrics(&self, out_metrics: *mut ResolverMetrics) -> ResolverStatus;
}
