const std = @import("std");

const linux = std.os.linux;
const posix = std.posix;

const E = linux.E;
const UnexpectedError = posix.UnexpectedError;

pub const MountFlags = packed struct(u32) {
    read_only: bool = false,
    no_suid: bool = false,
    no_dev: bool = false,
    no_exec: bool = false,
    synchronous: bool = false,
    remount: bool = false,
    allow_mandatory_locks: bool = false,
    synchronous_dir_changes: bool = false,
    _2: u2 = 0,
    no_atime: bool = false,
    no_dir_atime: bool = false,
    bind: bool = false,
    move: bool = false,
    recursive: bool = false,
    silent: bool = false,
    posix_acl: bool = false,
    unbindable: bool = false,
    private: bool = false,
    slave: bool = false,
    shared: bool = false,
    relative_atime: bool = false,
    kern_mount: bool = false,
    update_inode_version: bool = false,
    strict_atime: bool = false,
    lazy_time: bool = false,
    _1: u1 = 0,
    no_remote_lock: bool = false,
    no_sec: bool = false,
    born: bool = false,
    active: bool = false,
    no_user: bool = false,
};

pub const MountError = error{
    InvalidArgument,
    AccessDenied,
    FilesystemBusy,
    FilesystemLoopDetected,
    TooManyDummyDevices,
    PathNameTooLong,
    UnsupportedFilesystem,
    FileNotFound,
    KernelAllocFailed,
    NotBlockDevice,
    NotDir,
    InvalidDeviceMajor,
    NotPermitted,
    ReadOnlyFilesystem,
    Unexpected,
};

/// Wrapper for the `mount(2)` syscall, but with a more Zig-like API.
pub fn mount(source: [*:0]const u8, target: [*:0]const u8, fs_type: ?[*:0]const u8, flags: MountFlags, extra_data: ?[*:0]const u8) MountError!void {
    return switch (E.init(linux.syscall5(
        .mount,
        @intFromPtr(source),
        @intFromPtr(target),
        @intFromPtr(fs_type),
        @as(u32, @bitCast(flags)),
        @intFromPtr(extra_data),
    ))) {
        .SUCCESS => {},
        .INVAL => error.InvalidArgument,
        .ACCES => error.AccessDenied,
        .BUSY => error.FilesystemBusy,
        .FAULT => return error.Unexpected,
        .LOOP => error.FilesystemLoopDetected,
        .MFILE => error.TooManyDummyDevices,
        .NXIO => error.UnsupportedFilesystem,
        .NAMETOOLONG => error.PathNameTooLong,
        .NOENT => error.FileNotFound,
        .NOMEM => error.KernelAllocFailed,
        .NOTBLK => error.NotBlockDevice,
        .NOTDIR => error.NotDir,
        .PERM => error.NotPermitted,
        .ROFS => error.ReadOnlyFilesystem,
        else => return error.Unexpected,
    };
}

pub const UnshareFlags = packed struct(u32) {
    _7: u7 = 0,
    new_time_ns: bool = false,
    vm: bool = false,
    fs: bool = false,
    files: bool = false,
    signal_handlers: bool = false,
    pidfd: bool = false,
    ptrace: bool = false,
    vfork: bool = false,
    same_parent: bool = false, 
    same_thread_group: bool = false,
    new_mount_ns: bool = false,
    shared_sysvsem: bool = false,
    set_tls_info: bool = false,
    parent_set_tid: bool = false,
    child_clear_tid: bool = false,
    detached: bool = false,
    untraced: bool = false,
    child_set_tid: bool = false,
    new_cgroup_ns: bool = false,
    new_uts_ns: bool = false,
    new_ipc_ns: bool = false,
    new_user_ns: bool = false,
    new_pid_ns: bool = false,
    new_net_ns: bool = false,
    io_context: bool = false,
};

pub const UnshareError = error{
    InvalidArgument,
    KernelAllocFailed,
    NamespaceLimitExceeded,
    NotPermitted,
    Unexpected
};

pub fn unshare(flags: UnshareFlags) UnshareError!void {
    return switch (E.init(linux.syscall1(.unshare, @as(u32, @bitCast(flags))))) {
        .SUCCESS => {},
        .INVAL => error.InvalidArgument,
        .NOMEM => error.KernelAllocFailed,
        .NOSPC => error.NamespaceLimitExceeded,
        .PERM => error.NotPermitted,
        else => error.Unexpected,
    };
}

pub const CloneFlags = packed struct(u32) {
    sig_mask: u8 = 0,
    vm: bool = false,
    fs: bool = false,
    files: bool = false,
    signal_handlers: bool = false,
    pidfd: bool = false,
    ptrace: bool = false,
    vfork: bool = false,
    same_parent: bool = false, 
    same_thread_group: bool = false,
    new_mount_ns: bool = false,
    shared_sysvsem: bool = false,
    set_tls_info: bool = false,
    parent_set_tid: bool = false,
    child_clear_tid: bool = false,
    detached: bool = false,
    untraced: bool = false,
    child_set_tid: bool = false,
    new_cgroup_ns: bool = false,
    new_uts_ns: bool = false,
    new_ipc_ns: bool = false,
    new_user_ns: bool = false,
    new_pid_ns: bool = false,
    new_net_ns: bool = false,
    io_context: bool = false,
};

pub const Clone2Error = error{
    TooManyProcesses,
    InvalidArgument,
    KernelAllocFailed,
    NamespaceLimitExceeded,
    NotPermitted,
    Interrupted,
    Unexpected,
};

pub fn clone2(flags: CloneFlags, stack_ptr: ?[*]u8) Clone2Error!linux.pid_t {
    const syscall_result = linux.syscall2(.clone, @as(u32, @bitCast(flags)), @intFromPtr(stack_ptr));
    return switch (E.init(syscall_result)) {
        .SUCCESS => @intCast(syscall_result),
        .AGAIN => error.TooManyProcesses,
        .INVAL => error.InvalidArgument,
        .NOMEM => error.KernelAllocFailed,
        .NOSPC, .USERS => error.NamespaceLimitExceeded,
        .PERM => error.NotPermitted,
        .RESTART => error.Interrupted,
        else => error.Unexpected,
    };
}

pub const PrlimitError = error{
    InvalidArgument,
    NotPermitted,
    NoSuchProcess,
};

/// Returns the old resource limit.
pub fn prlimit(pid: linux.pid_t, resource: linux.rlimit_resource, new_limit: ?linux.rlimit) PrlimitError!linux.rlimit {
    const new_limit_ptr: ?*linux.rlimit = if (new_limit) |*nl| nl else null;
    var old_limit: linux.rlimit = undefined;
    prlimit(0, .{});
    return switch (E.init(linux.syscall4(.prlimit64, pid, @intFromEnum(resource), @intFromPtr(new_limit_ptr), @intFromPtr(&old_limit)))) {
        .SUCCESS => old_limit,
        .FAULT => unreachable,
        .INVAL => error.InvalidArgument,
        .PERM => error.NotPermitted,
        .SRCH => error.NoSuchProcess,
        else => unreachable,
    };
}

pub const PivotRootError = error{
    FilesystemBusy,
    InvalidArgument,
    NotDir,
    NotPermitted,
};

pub fn pivotRoot(new_root: [*:0]const u8, put_old: [*:0]const u8) PivotRootError!void {
    return switch (E.init(linux.syscall2(.pivot_root, @intFromPtr(new_root), @intFromPtr(put_old)))) {
        .SUCCESS => {},
        .BUSY => error.FilesystemBusy,
        .INVAL => error.InvalidArgument,
        .NOTDIR => error.NotDir,
        .PERM => error.NotPermitted,
        else => unreachable,
    };
}

pub const UmountError = error{
    FilesystemExpired,
    FilesystemBusy,
    InvalidArgument,
    PathNameTooLong,
    FileNotFound,
    KernelAllocFailed,
    NotPermitted,
};

pub const UmountFlags = packed struct(u32) {
    force: bool = false,
    detach: bool = false,
    expire: bool = false,
    no_follow_symlinks: bool = false,
    _28: u28 = 0,
};

/// Uses `umount2` internally.
pub fn umount(dir: [*:0]const u8, flags: UmountFlags) UmountError!void {
    return switch (E.init(linux.syscall2(.umount2, @intFromPtr(dir), @as(u32, @bitCast(flags))))) {
        .SUCCESS => {},
        .AGAIN => error.FilesystemExpired,
        .BUSY => error.FilesystemBusy,
        .INVAL => error.InvalidArgument,
        .NAMETOOLONG => error.PathNameTooLong,
        .NOENT => error.FileNotFound,
        .NOMEM => error.KernelAllocFailed,
        .PERM => error.NotPermitted,
        else => unreachable,
    };
}

pub const GetGroupsError = error{TooManyGroups} || UnexpectedError;

/// Returns the number of groups written. If `buf == null`, return the number of
/// supplemental groups instead.
pub fn getgroups(buf: ?[]u8) GetGroupsError!usize {
    if (buf) |b| {
        const rv = linux.syscall2(.getgroups, b.len, b.ptr);
        return switch (E.init(rv)) {
            .SUCCESS => rv,
            .INVAL => error.TooManyGroups,
            else => |errno| posix.unexpectedErrno(errno)
        };
    } else {
        const rv = linux.syscall2(.getgroups, 0, 0);
        return switch (E.init(rv)) {
            .SUCCESS => rv,
            else => |errno| posix.unexpectedErrno(errno)
        };
    }
}

pub const SetGroupsError = error{
    TooManyGroups,
    OutOfMemory,
    NotPermitted,
} || UnexpectedError;

pub fn setgroups(groups: []const linux.gid_t) SetGroupsError!void {
    return switch (E.init(linux.syscall2(.setgroups, groups.len, @intFromPtr(groups.ptr)))) {
        .SUCCESS => {},
        .INVAL => error.TooManyGroups,
        .NOMEM => error.OutOfMemory,
        .PERM => error.NotPermitted,
        else => |errno| std.posix.unexpectedErrno(errno)
    };
}
