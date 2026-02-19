module wcfss
  use, intrinsic :: iso_c_binding
  implicit none
  private

  ! Public constants (mirror ResolverStatus / ResolverIntent / flags)
  integer(c_int), parameter, public :: RESOLVER_OK = 0
  integer(c_int), parameter, public :: RESOLVER_NOT_FOUND = 1
  integer(c_int), parameter, public :: RESOLVER_EXISTS = 2
  integer(c_int), parameter, public :: RESOLVER_COLLISION = 3
  integer(c_int), parameter, public :: RESOLVER_UNMAPPED_ROOT = 4
  integer(c_int), parameter, public :: RESOLVER_UNSUPPORTED_ABSOLUTE_PATH = 5
  integer(c_int), parameter, public :: RESOLVER_ESCAPES_ROOT = 6
  integer(c_int), parameter, public :: RESOLVER_ENCODING_ERROR = 7
  integer(c_int), parameter, public :: RESOLVER_TOO_MANY_SYMLINKS = 8
  integer(c_int), parameter, public :: RESOLVER_NOT_A_DIRECTORY = 9
  integer(c_int), parameter, public :: RESOLVER_PERMISSION_DENIED = 10
  integer(c_int), parameter, public :: RESOLVER_BASE_DIR_INVALID = 11
  integer(c_int), parameter, public :: RESOLVER_PATH_TOO_LONG = 12
  integer(c_int), parameter, public :: RESOLVER_STALE_PLAN = 13
  integer(c_int), parameter, public :: RESOLVER_IO_ERROR = 14
  integer(c_int), parameter, public :: RESOLVER_INVALID_PATH = 15

  integer(c_int), parameter, public :: RESOLVER_LOG_OFF = 0
  integer(c_int), parameter, public :: RESOLVER_LOG_ERROR = 1
  integer(c_int), parameter, public :: RESOLVER_LOG_WARN = 2
  integer(c_int), parameter, public :: RESOLVER_LOG_INFO = 3
  integer(c_int), parameter, public :: RESOLVER_LOG_DEBUG = 4
  integer(c_int), parameter, public :: RESOLVER_LOG_TRACE = 5

  integer(c_int), parameter, public :: INTENT_STAT_EXISTS = 0
  integer(c_int), parameter, public :: INTENT_READ = 1
  integer(c_int), parameter, public :: INTENT_WRITE_TRUNCATE = 2
  integer(c_int), parameter, public :: INTENT_WRITE_APPEND = 3
  integer(c_int), parameter, public :: INTENT_CREATE_NEW = 4
  integer(c_int), parameter, public :: INTENT_MKDIRS = 5
  integer(c_int), parameter, public :: INTENT_RENAME = 6

  integer(c_uint32_t), parameter, public :: RESOLVER_FLAG_FAIL_ON_ANY_INVALID_UTF8_ENTRY = &
      int(z'00000001', c_uint32_t)
  integer(c_uint32_t), parameter, public :: RESOLVER_FLAG_ENABLE_WINDOWS_ABSOLUTE_PATHS = &
      int(z'00000002', c_uint32_t)

  integer(c_uint32_t), parameter, public :: RESOLVER_PLAN_TARGET_EXISTS = int(z'00000001', c_uint32_t)
  integer(c_uint32_t), parameter, public :: RESOLVER_PLAN_TARGET_IS_DIR = int(z'00000002', c_uint32_t)
  integer(c_uint32_t), parameter, public :: RESOLVER_PLAN_WOULD_CREATE = int(z'00000004', c_uint32_t)
  integer(c_uint32_t), parameter, public :: RESOLVER_PLAN_WOULD_TRUNCATE = int(z'00000008', c_uint32_t)

  ! C ABI types
  type, bind(C), public :: ResolverConfig
     integer(c_uint32_t) :: size
     integer(c_uint32_t) :: flags
     integer(c_uint64_t) :: ttl_fast_ms
     integer(c_uint64_t) :: reserved(5)
  end type ResolverConfig

  type, bind(C), public :: ResolverStringView
     type(c_ptr) :: ptr
     integer(c_size_t) :: len
  end type ResolverStringView

  type, bind(C), public :: ResolverBufferView
     type(c_ptr) :: ptr
     integer(c_size_t) :: len
  end type ResolverBufferView

  type, bind(C), public :: ResolverRootMappingEntry
     type(ResolverStringView) :: key
     type(ResolverStringView) :: value
  end type ResolverRootMappingEntry

  type, bind(C), public :: ResolverRootMapping
     type(c_ptr) :: entries
     integer(c_size_t) :: len
  end type ResolverRootMapping

  type, bind(C), public :: ResolverDirGeneration
     integer(c_uint64_t) :: dev
     integer(c_uint64_t) :: ino
     integer(c_uint64_t) :: generation
  end type ResolverDirGeneration

  type, bind(C), public :: ResolverDirStamp
     integer(c_uint64_t) :: dev
     integer(c_uint64_t) :: ino
     integer(c_int64_t) :: mtime_sec
     integer(c_int64_t) :: mtime_nsec
     integer(c_int64_t) :: ctime_sec
     integer(c_int64_t) :: ctime_nsec
  end type ResolverDirStamp

  type, bind(C), public :: ResolverPlanToken
     integer(c_uint32_t) :: size
     integer(c_uint64_t) :: op_generation
     integer(c_uint64_t) :: unicode_version_generation
     integer(c_uint64_t) :: root_mapping_generation
     integer(c_uint64_t) :: absolute_path_support_generation
     integer(c_uint64_t) :: encoding_policy_generation
     integer(c_uint64_t) :: symlink_policy_generation
     type(ResolverBufferView) :: dir_generations
     type(ResolverBufferView) :: touched_dir_stamps
     integer(c_uint64_t) :: reserved(4)
  end type ResolverPlanToken

  type, bind(C), public :: ResolverPlan
     integer(c_uint32_t) :: size
     integer(c_int) :: status
     integer(c_int) :: would_error
     integer(c_uint32_t) :: flags
     integer(c_int) :: intent
     type(ResolverStringView) :: resolved_parent
     type(ResolverStringView) :: resolved_leaf
     type(ResolverPlanToken) :: plan_token
     integer(c_uint64_t) :: reserved(6)
  end type ResolverPlan

  type, bind(C), public :: ResolverResult
     integer(c_uint32_t) :: size
     integer(c_uint64_t) :: reserved(6)
  end type ResolverResult

  type, bind(C), public :: ResolverDiagEntry
     integer(c_uint32_t) :: code
     integer(c_uint32_t) :: severity
     type(ResolverStringView) :: context
     type(ResolverStringView) :: detail
  end type ResolverDiagEntry

  type, bind(C), public :: ResolverDiag
     integer(c_uint32_t) :: size
     type(ResolverBufferView) :: entries
     integer(c_uint64_t) :: reserved(7)
  end type ResolverDiag

  type, bind(C), public :: ResolverMetrics
     integer(c_uint32_t) :: size
     integer(c_uint64_t) :: dirindex_cache_hits
     integer(c_uint64_t) :: dirindex_cache_misses
     integer(c_uint64_t) :: dirindex_rebuilds
     integer(c_uint64_t) :: stamp_validations
     integer(c_uint64_t) :: collisions
     integer(c_uint64_t) :: invalid_utf8_entries
     integer(c_uint64_t) :: encoding_errors
     integer(c_uint64_t) :: plans_rejected_stale
     integer(c_uint64_t) :: reserved(4)
  end type ResolverMetrics

  type, bind(C), public :: ResolverResolvedPath
     type(ResolverStringView) :: value
  end type ResolverResolvedPath

  type, bind(C), public :: ResolverStringList
     integer(c_uint32_t) :: size
     type(ResolverBufferView) :: entries
     integer(c_size_t) :: count
     integer(c_uint64_t) :: reserved(4)
  end type ResolverStringList

  ! Public Fortran API
  public :: wcfss_create
  public :: wcfss_destroy
  public :: wcfss_plan
  public :: wcfss_execute_from_plan
  public :: wcfss_execute_open_return_path
  public :: wcfss_execute_open_return_fd
  public :: wcfss_execute_mkdirs
  public :: wcfss_execute_unlink
  public :: wcfss_execute_rename
  public :: wcfss_get_metrics
  public :: wcfss_set_root_mapping
  public :: wcfss_plan_destroy
  public :: wcfss_diag_destroy
  public :: wcfss_find_matches
  public :: wcfss_string_list_destroy
  public :: wcfss_log_set_stderr
  public :: wcfss_log_set_level
  public :: wcfss_log_disable

  interface
     function resolver_create(config) bind(C, name="resolver_create")
       import :: c_ptr
       type(c_ptr) :: resolver_create
       type(c_ptr), value :: config
     end function resolver_create

     subroutine resolver_destroy(handle) bind(C, name="resolver_destroy")
       import :: c_ptr
       type(c_ptr), value :: handle
     end subroutine resolver_destroy

     function resolver_set_root_mapping(handle, mapping, out_diag) bind(C, name="resolver_set_root_mapping")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_set_root_mapping
       type(c_ptr), value :: handle
       type(c_ptr), value :: mapping
       type(c_ptr), value :: out_diag
     end function resolver_set_root_mapping

     function resolver_plan(handle, base_dir, input_path, intent, out_plan, out_diag) &
         bind(C, name="resolver_plan")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_plan
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: input_path
       integer(c_int), value :: intent
       type(c_ptr), value :: out_plan
       type(c_ptr), value :: out_diag
     end function resolver_plan

     function resolver_execute_mkdirs(handle, base_dir, input_path, out_result, out_diag) &
         bind(C, name="resolver_execute_mkdirs")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_execute_mkdirs
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: input_path
       type(c_ptr), value :: out_result
       type(c_ptr), value :: out_diag
     end function resolver_execute_mkdirs

     function resolver_execute_rename(handle, base_dir, from_path, to_path, out_result, out_diag) &
         bind(C, name="resolver_execute_rename")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_execute_rename
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: from_path
       type(c_ptr), value :: to_path
       type(c_ptr), value :: out_result
       type(c_ptr), value :: out_diag
     end function resolver_execute_rename

     function resolver_execute_unlink(handle, base_dir, input_path, out_result, out_diag) &
         bind(C, name="resolver_execute_unlink")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_execute_unlink
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: input_path
       type(c_ptr), value :: out_result
       type(c_ptr), value :: out_diag
     end function resolver_execute_unlink

     function resolver_find_matches(handle, base_dir, input_path, out_list, out_diag) &
         bind(C, name="resolver_find_matches")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_find_matches
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: input_path
       type(c_ptr), value :: out_list
       type(c_ptr), value :: out_diag
     end function resolver_find_matches

     subroutine resolver_free_string_list(value) bind(C, name="resolver_free_string_list")
       import :: ResolverStringList
       type(ResolverStringList), value :: value
     end subroutine resolver_free_string_list

     function resolver_log_set_stderr(level) bind(C, name="resolver_log_set_stderr")
       import :: c_int
       integer(c_int) :: resolver_log_set_stderr
       integer(c_int), value :: level
     end function resolver_log_set_stderr

     function resolver_log_set_level(level) bind(C, name="resolver_log_set_level")
       import :: c_int
       integer(c_int) :: resolver_log_set_level
       integer(c_int), value :: level
     end function resolver_log_set_level

     function resolver_log_disable() bind(C, name="resolver_log_disable")
       import :: c_int
       integer(c_int) :: resolver_log_disable
     end function resolver_log_disable

     function resolver_execute_open_return_path(handle, base_dir, input_path, intent, out_resolved, out_diag) &
         bind(C, name="resolver_execute_open_return_path")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_execute_open_return_path
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: input_path
       integer(c_int), value :: intent
       type(c_ptr), value :: out_resolved
       type(c_ptr), value :: out_diag
     end function resolver_execute_open_return_path

     function resolver_execute_open_return_fd(handle, base_dir, input_path, intent, out_fd, out_diag) &
         bind(C, name="resolver_execute_open_return_fd")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_execute_open_return_fd
       type(c_ptr), value :: handle
       type(c_ptr), value :: base_dir
       type(c_ptr), value :: input_path
       integer(c_int), value :: intent
       type(c_ptr), value :: out_fd
       type(c_ptr), value :: out_diag
     end function resolver_execute_open_return_fd

     function resolver_execute_from_plan(handle, plan, out_result, out_diag) &
         bind(C, name="resolver_execute_from_plan")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_execute_from_plan
       type(c_ptr), value :: handle
       type(c_ptr), value :: plan
       type(c_ptr), value :: out_result
       type(c_ptr), value :: out_diag
     end function resolver_execute_from_plan

     function resolver_get_metrics(handle, out_metrics) bind(C, name="resolver_get_metrics")
       import :: c_ptr, c_int
       integer(c_int) :: resolver_get_metrics
       type(c_ptr), value :: handle
       type(c_ptr), value :: out_metrics
     end function resolver_get_metrics

     subroutine resolver_free_string(value) bind(C, name="resolver_free_string")
       import :: ResolverStringView
       type(ResolverStringView), value :: value
     end subroutine resolver_free_string

     subroutine resolver_free_buffer(value) bind(C, name="resolver_free_buffer")
       import :: ResolverBufferView
       type(ResolverBufferView), value :: value
     end subroutine resolver_free_buffer
  end interface

contains
  subroutine make_view(str, view, buffer)
    ! Uses len_trim; trailing spaces in Fortran strings are not preserved.
    character(len=*), intent(in) :: str
    type(ResolverStringView), intent(out) :: view
    character(kind=c_char), allocatable, target, intent(out) :: buffer(:)
    integer :: i, n
    n = len_trim(str)
    if (n <= 0) then
      view%ptr = c_null_ptr
      view%len = 0_c_size_t
      return
    end if
    allocate(buffer(n))
    do i = 1, n
      buffer(i) = str(i:i)
    end do
    view%ptr = c_loc(buffer(1))
    view%len = int(n, c_size_t)
  end subroutine make_view

  subroutine fill_view_fixed(str, view, buffer)
    character(len=*), intent(in) :: str
    type(ResolverStringView), intent(out) :: view
    character(kind=c_char), target, intent(inout) :: buffer(:)
    integer :: i, n
    n = len_trim(str)
    if (n <= 0) then
      view%ptr = c_null_ptr
      view%len = 0_c_size_t
      return
    end if
    do i = 1, n
      buffer(i) = str(i:i)
    end do
    view%ptr = c_loc(buffer(1))
    view%len = int(n, c_size_t)
  end subroutine fill_view_fixed

  subroutine view_to_string(view, out_str)
    type(ResolverStringView), intent(in) :: view
    character(len=:), allocatable, intent(out) :: out_str
    character(kind=c_char), pointer :: p(:)
    integer :: i, n
    n = int(view%len)
    if (n <= 0 .or. .not. c_associated(view%ptr)) then
      out_str = ""
      return
    end if
    call c_f_pointer(view%ptr, p, [n])
    allocate(character(len=n) :: out_str)
    do i = 1, n
      out_str(i:i) = p(i)
    end do
  end subroutine view_to_string

  subroutine string_list_to_array(list, out_arr)
    type(ResolverStringList), intent(in) :: list
    character(len=:), allocatable, intent(out) :: out_arr(:)
    type(ResolverStringView), pointer :: views(:)
    integer :: i, count, max_len
    character(len=:), allocatable :: tmp
    count = int(list%count)
    if (count <= 0 .or. .not. c_associated(list%entries%ptr)) then
      allocate(character(len=0) :: out_arr(0))
      return
    end if
    call c_f_pointer(list%entries%ptr, views, [count])
    max_len = 0
    do i = 1, count
      if (int(views(i)%len) > max_len) max_len = int(views(i)%len)
    end do
    if (max_len <= 0) then
      allocate(character(len=0) :: out_arr(count))
      return
    end if
    allocate(character(len=max_len) :: out_arr(count))
    do i = 1, count
      call view_to_string(views(i), tmp)
      out_arr(i) = tmp
    end do
  end subroutine string_list_to_array

  function wcfss_create(config) result(handle)
    type(ResolverConfig), intent(in), optional :: config
    type(c_ptr) :: handle
    type(ResolverConfig), target :: cfg
    if (present(config)) then
      cfg = config
      cfg%size = int(c_sizeof(cfg), c_uint32_t)
      handle = resolver_create(c_loc(cfg))
    else
      handle = resolver_create(c_null_ptr)
    end if
  end function wcfss_create

  subroutine wcfss_destroy(handle)
    type(c_ptr), intent(in) :: handle
    call resolver_destroy(handle)
  end subroutine wcfss_destroy

  function wcfss_plan(handle, base_dir, input_path, intent, plan, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: input_path
    integer(c_int), intent(in) :: intent
    type(ResolverPlan), intent(inout), target :: plan
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverStringView), target :: base_view, input_view
    character(kind=c_char), allocatable, target :: base_buf(:), input_buf(:)
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr

    plan%size = int(c_sizeof(plan), c_uint32_t)
    plan%plan_token%size = int(c_sizeof(plan%plan_token), c_uint32_t)

    call make_view(base_dir, base_view, base_buf)
    call make_view(input_path, input_view, input_buf)

    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if

    status = resolver_plan(handle, c_loc(base_view), c_loc(input_view), intent, c_loc(plan), diag_ptr)
  end function wcfss_plan

  subroutine wcfss_plan_destroy(plan)
    type(ResolverPlan), intent(inout) :: plan
    call resolver_free_buffer(plan%plan_token%dir_generations)
    call resolver_free_buffer(plan%plan_token%touched_dir_stamps)
    call resolver_free_string(plan%resolved_parent)
    call resolver_free_string(plan%resolved_leaf)
    plan%plan_token%dir_generations%ptr = c_null_ptr
    plan%plan_token%dir_generations%len = 0_c_size_t
    plan%plan_token%touched_dir_stamps%ptr = c_null_ptr
    plan%plan_token%touched_dir_stamps%len = 0_c_size_t
    plan%resolved_parent%ptr = c_null_ptr
    plan%resolved_parent%len = 0_c_size_t
    plan%resolved_leaf%ptr = c_null_ptr
    plan%resolved_leaf%len = 0_c_size_t
  end subroutine wcfss_plan_destroy

  subroutine wcfss_diag_destroy(diag)
    type(ResolverDiag), intent(inout) :: diag
    call resolver_free_buffer(diag%entries)
    diag%entries%ptr = c_null_ptr
    diag%entries%len = 0_c_size_t
  end subroutine wcfss_diag_destroy

  function wcfss_find_matches(handle, base_dir, input_path, matches, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: input_path
    character(len=:), allocatable, intent(out) :: matches(:)
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverStringView), target :: base_view, input_view
    character(kind=c_char), allocatable, target :: base_buf(:), input_buf(:)
    type(ResolverStringList), target :: list
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr

    list%size = int(c_sizeof(list), c_uint32_t)
    list%entries%ptr = c_null_ptr
    list%entries%len = 0_c_size_t
    list%count = 0_c_size_t
    list%reserved = 0_c_uint64_t

    call make_view(base_dir, base_view, base_buf)
    call make_view(input_path, input_view, input_buf)

    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if

    status = resolver_find_matches(handle, c_loc(base_view), c_loc(input_view), c_loc(list), diag_ptr)
    if (status == RESOLVER_OK) then
      call string_list_to_array(list, matches)
    else
      allocate(character(len=0) :: matches(0))
    end if
    call resolver_free_string_list(list)
  end function wcfss_find_matches

  subroutine wcfss_string_list_destroy(list)
    type(ResolverStringList), intent(in) :: list
    call resolver_free_string_list(list)
  end subroutine wcfss_string_list_destroy

  function wcfss_log_set_stderr(level) result(status)
    integer(c_int), intent(in) :: level
    integer(c_int) :: status
    status = resolver_log_set_stderr(level)
  end function wcfss_log_set_stderr

  function wcfss_log_set_level(level) result(status)
    integer(c_int), intent(in) :: level
    integer(c_int) :: status
    status = resolver_log_set_level(level)
  end function wcfss_log_set_level

  function wcfss_log_disable() result(status)
    integer(c_int) :: status
    status = resolver_log_disable()
  end function wcfss_log_disable

  function wcfss_execute_from_plan(handle, plan, result_out, diag) result(status)
    type(c_ptr), intent(in) :: handle
    type(ResolverPlan), intent(in), target :: plan
    type(ResolverResult), intent(inout) :: result_out
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr
    result_out%size = int(c_sizeof(result_out), c_uint32_t)
    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if
    status = resolver_execute_from_plan(handle, c_loc(plan), c_loc(result_out), diag_ptr)
  end function wcfss_execute_from_plan

  function wcfss_execute_open_return_path(handle, base_dir, input_path, intent, resolved, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: input_path
    integer(c_int), intent(in) :: intent
    character(len=:), allocatable, intent(out) :: resolved
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverResolvedPath), target :: out_path
    type(ResolverStringView), target :: base_view, input_view
    character(kind=c_char), allocatable, target :: base_buf(:), input_buf(:)
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr

    call make_view(base_dir, base_view, base_buf)
    call make_view(input_path, input_view, input_buf)
    out_path%value%ptr = c_null_ptr
    out_path%value%len = 0_c_size_t

    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if

    status = resolver_execute_open_return_path(handle, c_loc(base_view), c_loc(input_view), intent, &
                                               c_loc(out_path), diag_ptr)
    if (status == RESOLVER_OK) then
      call view_to_string(out_path%value, resolved)
    else
      resolved = ""
    end if
    call resolver_free_string(out_path%value)
  end function wcfss_execute_open_return_path

  function wcfss_execute_open_return_fd(handle, base_dir, input_path, intent, fd_out, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: input_path
    integer(c_int), intent(in) :: intent
    integer(c_int), intent(out) :: fd_out
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverStringView), target :: base_view, input_view
    character(kind=c_char), allocatable, target :: base_buf(:), input_buf(:)
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr

    call make_view(base_dir, base_view, base_buf)
    call make_view(input_path, input_view, input_buf)
    fd_out = -1

    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if

    status = resolver_execute_open_return_fd(handle, c_loc(base_view), c_loc(input_view), intent, &
                                             c_loc(fd_out), diag_ptr)
  end function wcfss_execute_open_return_fd

  function wcfss_execute_mkdirs(handle, base_dir, input_path, result_out, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: input_path
    type(ResolverResult), intent(inout) :: result_out
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverStringView), target :: base_view, input_view
    character(kind=c_char), allocatable, target :: base_buf(:), input_buf(:)
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr
    result_out%size = int(c_sizeof(result_out), c_uint32_t)
    call make_view(base_dir, base_view, base_buf)
    call make_view(input_path, input_view, input_buf)
    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if
    status = resolver_execute_mkdirs(handle, c_loc(base_view), c_loc(input_view), c_loc(result_out), diag_ptr)
  end function wcfss_execute_mkdirs

  function wcfss_execute_unlink(handle, base_dir, input_path, result_out, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: input_path
    type(ResolverResult), intent(inout) :: result_out
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverStringView), target :: base_view, input_view
    character(kind=c_char), allocatable, target :: base_buf(:), input_buf(:)
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr
    result_out%size = int(c_sizeof(result_out), c_uint32_t)
    call make_view(base_dir, base_view, base_buf)
    call make_view(input_path, input_view, input_buf)
    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if
    status = resolver_execute_unlink(handle, c_loc(base_view), c_loc(input_view), c_loc(result_out), diag_ptr)
  end function wcfss_execute_unlink

  function wcfss_execute_rename(handle, base_dir, from_path, to_path, result_out, diag) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), intent(in) :: base_dir
    character(len=*), intent(in) :: from_path
    character(len=*), intent(in) :: to_path
    type(ResolverResult), intent(inout) :: result_out
    type(ResolverDiag), intent(inout), optional :: diag
    integer(c_int) :: status
    type(ResolverStringView), target :: base_view, from_view, to_view
    character(kind=c_char), allocatable, target :: base_buf(:), from_buf(:), to_buf(:)
    type(ResolverDiag), target :: local_diag
    type(c_ptr) :: diag_ptr
    result_out%size = int(c_sizeof(result_out), c_uint32_t)
    call make_view(base_dir, base_view, base_buf)
    call make_view(from_path, from_view, from_buf)
    call make_view(to_path, to_view, to_buf)
    if (present(diag)) then
      diag%size = int(c_sizeof(diag), c_uint32_t)
      diag_ptr = c_loc(diag)
    else
      local_diag%size = 0_c_uint32_t
      diag_ptr = c_null_ptr
    end if
    status = resolver_execute_rename(handle, c_loc(base_view), c_loc(from_view), c_loc(to_view), &
                                     c_loc(result_out), diag_ptr)
  end function wcfss_execute_rename

  function wcfss_get_metrics(handle, metrics) result(status)
    type(c_ptr), intent(in) :: handle
    type(ResolverMetrics), intent(inout) :: metrics
    integer(c_int) :: status
    metrics%size = int(c_sizeof(metrics), c_uint32_t)
    status = resolver_get_metrics(handle, c_loc(metrics))
  end function wcfss_get_metrics

  function wcfss_set_root_mapping(handle, keys, values) result(status)
    type(c_ptr), intent(in) :: handle
    character(len=*), dimension(:), intent(in) :: keys
    character(len=*), dimension(:), intent(in) :: values
    integer(c_int) :: status
    integer :: i, n, maxk, maxv
    type(ResolverRootMapping), target :: mapping
    type(ResolverRootMappingEntry), allocatable, target :: entries(:)
    character(kind=c_char), allocatable, target :: key_bufs(:,:), val_bufs(:,:)
    type(ResolverStringView) :: key_view, val_view

    n = size(keys)
    if (n /= size(values)) then
      status = RESOLVER_INVALID_PATH
      return
    end if
    if (n == 0) then
      mapping%entries = c_null_ptr
      mapping%len = 0_c_size_t
      status = resolver_set_root_mapping(handle, c_loc(mapping), c_null_ptr)
      return
    end if

    maxk = 0
    maxv = 0
    do i = 1, n
      maxk = max(maxk, len_trim(keys(i)))
      maxv = max(maxv, len_trim(values(i)))
    end do
    if (maxk == 0 .or. maxv == 0) then
      status = RESOLVER_INVALID_PATH
      return
    end if

    allocate(entries(n))
    allocate(key_bufs(maxk, n))
    allocate(val_bufs(maxv, n))

    do i = 1, n
      call fill_view_fixed(keys(i), key_view, key_bufs(:, i))
      call fill_view_fixed(values(i), val_view, val_bufs(:, i))
      entries(i)%key = key_view
      entries(i)%value = val_view
    end do

    mapping%entries = c_loc(entries(1))
    mapping%len = int(n, c_size_t)
    status = resolver_set_root_mapping(handle, c_loc(mapping), c_null_ptr)
  end function wcfss_set_root_mapping

  ! Error handling example:
  !
  !  integer(c_int) :: status
  !  status = wcfss_execute_mkdirs(h, "/tmp", "missing/dir", res)
  !  if (status /= RESOLVER_OK) then
  !    print *, "mkdirs failed with status=", status
  !  end if
  !
  ! Example usage (open with resolved path):
  !
  !  use wcfss
  !  type(c_ptr) :: h
  !  type(ResolverResult) :: res
  !  character(len=:), allocatable :: resolved
  !  h = wcfss_create()
  !  call wcfss_execute_open_return_path(h, "/tmp", "file.txt", INTENT_READ, resolved)
  !  open(unit=10, file=resolved, status="old", action="read")
  !  call wcfss_destroy(h)

end module wcfss
