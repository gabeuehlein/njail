host_uid: posix.uid_t,
host_gid: posix.gid_t,
host_pid: posix.pid_t,
init_state: InitStage,

/// `gpa` is used for temporary allocations; no allocations will persist and need to be freed outside
/// of this function.
pub fn init(gpa: Allocator, options: Options) !Jail {
    const host_uid = posix.getuid();
    const host_gid = std.os.linux.getgid();
    const host_pid_space = try posix.mmap(null, 4, posix.PROT.WRITE | posix.PROT.READ, .{ .TYPE = .SHARED, .ANONYMOUS = true }, -1, 0);
    errdefer posix.munmap(host_pid_space);
    const child_read, const parent_write = try posix.pipe2(.{ .CLOEXEC = true }); 
    defer posix.close(child_read);
    const parent_read, const child_write = try posix.pipe2(.{ .CLOEXEC = true }); 
    defer posix.close(child_write);
    const child_pid = try sys.clone2(.{ 
        .new_user_ns = true,
        .new_pid_ns = true,
        .new_mount_ns = true,
        .new_cgroup_ns = !options.share_cgroup_ns,
        .new_net_ns = !options.share_net_ns,
        .new_uts_ns = !options.share_uts_ns,
        .new_ipc_ns = !options.share_ipc_ns,
        .sig_mask = posix.SIG.CHLD,
    }, null);

    if (child_pid != 0) {
        std.mem.writeInt(i32, host_pid_space[0..4], child_pid, .little);
        try helpChild(gpa, &options, child_pid, parent_read, parent_write);
        std.posix.abort();
    }

    if (!options.share_time_ns)
        _ = try sys.unshare(.{ .new_time_ns = true });

    var space = [1]u8{1};
    if ((try posix.read(child_read, &space)) != 1 and space[0] != 0)
        return error.SetupFailed;
    space[0] = 0;
    if ((try posix.write(child_write, &space)) != 1)
        return error.SetupFailed;

    try posix.setgid(options.initial_gid);
    try posix.setuid(options.initial_gid);

    const host_pid = std.mem.readInt(i32, host_pid_space[0..4], .little);
    // parent won't use this memory anymore
    posix.munmap(host_pid_space);

    return .{
        .host_uid = host_uid,
        .host_gid = host_gid,
        .host_pid = host_pid,
        .init_state = .initial,
    };
}

fn helpChild(gpa: Allocator, options: *const Options, child_pid: posix.pid_t, read_fd: posix.fd_t, write_fd: posix.fd_t) !void {
    errdefer posix.kill(child_pid, posix.SIG.KILL) catch {};
    var read_file: std.fs.File = .{ .handle = read_fd };
    var write_file: std.fs.File = .{ .handle = write_fd };
    const reader = read_file.reader();
    const writer = write_file.writer();

    {
        // TODO we could probably also check for other files in PATH in case new[ug]idmap are installed in 
        // nonstandard and/or unusual locations.
        const empty_envp: [0:null]?[*:0]u8 = .{};
        const allocPrintZ = std.fmt.allocPrintZ;
        var child_argv: std.ArrayListUnmanaged(?[*:0]const u8) = try .initCapacity(gpa, 3 + 3 * @max(options.uid_maps.len, options.gid_maps.len));
        defer child_argv.deinit(gpa);
        var arena_allocator: std.heap.ArenaAllocator = .init(gpa);
        defer arena_allocator.deinit();
        const arena = arena_allocator.allocator();
        {
            defer {
                child_argv.clearRetainingCapacity();
                _ = arena_allocator.reset(.retain_capacity);
            }
            child_argv.appendAssumeCapacity("/usr/bin/newuidmap");
            child_argv.appendAssumeCapacity(try allocPrintZ(arena, "{d}", .{child_pid}));
            for (options.uid_maps) |uid_map| {
                const items = child_argv.addManyAsArrayAssumeCapacity(3);
                items[0] = try allocPrintZ(arena, "{d}", .{uid_map.island_start});
                items[1] = try allocPrintZ(arena, "{d}", .{uid_map.parent_start});
                items[2] = try allocPrintZ(arena, "{d}", .{uid_map.map_len});
            }
            child_argv.appendAssumeCapacity(null);

            const newuidmap_pid = try posix.fork();
            if (newuidmap_pid == 0) 
                posix.execveZ("/usr/bin/newuidmap", @ptrCast(child_argv.items), &empty_envp) catch posix.exit(1);
            const wait_result = posix.waitpid(newuidmap_pid, 0);
            switch (posix.W.EXITSTATUS(wait_result.status)) {
                0 => {},
                else => return error.UidmapFailed
            }
        }
        {
            try child_argv.ensureTotalCapacity(gpa, options.gid_maps.len);
            child_argv.appendAssumeCapacity("/usr/bin/newgidmap");
            child_argv.appendAssumeCapacity(try allocPrintZ(arena, "{d}", .{child_pid}));
            for (options.gid_maps) |gid_map| {
                const items = child_argv.addManyAsArrayAssumeCapacity(3);
                items[0] = try allocPrintZ(arena, "{d}", .{gid_map.island_start});
                items[1] = try allocPrintZ(arena, "{d}", .{gid_map.parent_start});
                items[2] = try allocPrintZ(arena, "{d}", .{gid_map.map_len});
            }
            child_argv.appendAssumeCapacity(null);
            
            const newgidmap_pid = try posix.fork();
            if (newgidmap_pid == 0)
                posix.execveZ("/usr/bin/newgidmap", @ptrCast(child_argv.items), &empty_envp) catch posix.exit(1);
            const wait_result = posix.waitpid(newgidmap_pid, 0);
            switch (posix.W.EXITSTATUS(wait_result.status)) {
                0 => {},
                else => return error.GidmapFailed
            }
        }
    }

    try  writer.writeByte(0);
    if ((try reader.readByte()) != 0)
        return error.ChildFailed;

    read_file.close();
    write_file.close();

    const full_sigmask = linux.sigfillset();
    posix.sigprocmask(posix.SIG.BLOCK, &full_sigmask, null);

    const wait_result = posix.wait4wait4(child_pid, 0, null);
    
    posix.exit(posix.W.EXITSTATUS(wait_result.status)); // PID 1 in the jail exited, nothing more for us to do
}

/// Begins the process for setting up the new root filesystem for the jail. After calling this,
/// there will be exactly two directories in the filesystem root: `/new` and `/old`. `/new` will
/// be empty and `/old` will refer to the old root file system. 
pub fn startFilesystemSetup(jail: *Jail) !void {
    assert(jail.init_state == .initial);
    defer jail.init_state = .fs_setup;
    try sys.mount("/", "/", "none", .{ .bind = true, .recursive = true, .private = true }, null);
    try sys.mount("tmpfs", "/tmp", "tmpfs", .{}, null);
    try std.fs.makeDirAbsoluteZ("/tmp/new");
    try std.fs.makeDirAbsoluteZ("/tmp/old");
    try sys.mount("/tmp/new", "/tmp/new", "none", .{ .bind = true, .recursive = true }, null);
    try posix.chdir("/tmp"); 
    try sys.pivotRoot(".", "old");
}

/// If `dst == null`, binds `src` to the same path in the new filesystem.
pub fn bindMount(jail: *Jail, src: []const u8, dst: ?[]const u8, options: BindMountOptions) !void {
    assert(jail.init_state == .fs_setup);
    if (!std.fs.path.isAbsolute(src))
        return error.SourceNotAbsolute;
    if (dst != null and !std.fs.path.isAbsolute(dst.?))
        return error.DestinationNotAbsolute;
    const src_prefixed = try toPosixPathWithPrefix("/old", src);
    const dst_prefixed = try toPosixPathWithPrefix("/new", dst orelse src);
    const src_stat: posix.Stat = blk: {
        const fd = try posix.openZ(&src_prefixed, .{ .PATH = true }, 0);
        defer posix.close(fd);
        break :blk try posix.fstat(fd);
    };
    const dst_slice = dst_prefixed[0.."/new".len + (dst orelse src).len :0];
    if (posix.S.ISDIR(src_stat.mode)) {
        try fs.mkdirs(std.mem.sliceTo(&dst_prefixed, 0), 0o755);
    } else {
        const dirname = std.fs.path.dirname(dst_slice).?;
        try fs.mkdirs(dirname, 0o755);
        (try std.fs.createFileAbsoluteZ(dst_slice, .{})).close();
    }
    try sys.mount(&src_prefixed, &dst_prefixed, "none", .{
        .bind = true,
        .read_only = options.read_only,
        .recursive = options.recursive,
    }, null);
}

pub fn symLink(jail: *Jail, path: []const u8, target: []const u8) !void {
    assert(jail.init_state == .fs_setup);
    if (!std.fs.path.isAbsolute(path))
        return error.NotAbsolute;
    const target_z = try posix.toPosixPath(target);
    const path_prefixed = try toPosixPathWithPrefix("/new", path);
    parent: {
        const dirname = std.fs.path.dirname(path_prefixed[0.."/new".len + path.len]) orelse break :parent;
        try fs.mkdirs(dirname, 0o755);
    }
    try std.fs.cwd().symLinkZ(&target_z, &path_prefixed, .{});
}

pub fn finalizeFilesystem(jail: *Jail) !void {
    assert(jail.init_state == .fs_setup);
    defer jail.init_state = .done;
    try posix.chdir("/new");
    try sys.pivotRoot(".", ".");
    try sys.umount("/", .{ .detach = true });
}

pub const BindMountOptions = packed struct {
    recursive: bool = false,
    read_only: bool = true,
};

pub fn mountProc(j: *Jail, dir: []const u8, access: ProcPidAccess, overseer_gid: posix.gid_t) !void {
    assert(j.init_state == .fs_setup);
    const new_dir = try toPosixPathWithPrefix("/new", dir);
    try fs.mkdirs(std.mem.sliceTo(&new_dir, 0), 0o555);
    var options_buffer: [256]u8 = undefined;
    const options = std.fmt.bufPrintZ(&options_buffer, "hidepid={d},gid={d}", .{@intFromEnum(access), overseer_gid}) catch unreachable;
    try sys.mount("proc", &new_dir, "proc", .{}, options);
}

/// Used to convert a slice to a null terminated slice on the stack with the prefix `prefix`.
/// Does not append a `/` to `prefix` if `file_path[0] != '/'`
fn toPosixPathWithPrefix(comptime prefix: []const u8, file_path: []const u8) error{NameTooLong}![posix.PATH_MAX - 1:0]u8 {
    comptime assert(std.mem.indexOfScalar(u8, prefix, 0) == null);
    if (std.debug.runtime_safety) assert(std.mem.indexOfScalar(u8, file_path, 0) == null);
    var path_with_null: [posix.PATH_MAX - 1:0]u8 = undefined;
    // >= rather than > to make room for the null byte
    if (file_path.len + prefix.len >= posix.PATH_MAX) return error.NameTooLong;
    @memcpy(path_with_null[0..prefix.len], prefix);
    @memcpy(path_with_null[prefix.len..][0..file_path.len], file_path);
    path_with_null[file_path.len + prefix.len] = 0;
    return path_with_null;
}

const ProcPidAccess = enum {
    /// Everyone can inspect /proc/pid for an arbitrary pid.
    everyone,
    /// Processes may only read their own /proc/pid directory.
    read_own,
    /// Processes can only see their own /proc/pid directory; other processes'
    /// /proc/pid directories become invisible.
    hidden,
};

const std = @import("std");
const fs = @import("fs.zig");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const sys = @import("sys.zig");


const Jail = @This();

pub const Options = struct {
    share_net_ns: bool = false,
    share_uts_ns: bool = false,
    share_ipc_ns: bool = false,
    share_cgroup_ns: bool = false, 
    share_time_ns: bool = false,
    uid_maps: []const UidMap,
    gid_maps: []const GidMap,
    initial_uid: posix.uid_t,
    initial_gid: posix.gid_t,
};

pub const UidMap = struct {
    island_start: linux.uid_t,
    parent_start: linux.uid_t,
    map_len: u32 = 1,

    pub inline fn one(from: linux.uid_t, to: linux.uid_t) UidMap {
        return .{ .island_start = to, .parent_start = from };
    }

    pub fn currentToRoot() UidMap {
        return .{
            .island_start = 0,
            .parent_start = linux.getuid(),
            .map_len = 1,
        };
    }

    pub fn currentToCurrent() UidMap {
        const uid = linux.getuid();
        return .{
            .island_start = uid,
            .parent_start = uid,
            .map_len = 1,
        };
    }
};

pub const GidMap = struct {
    island_start: linux.gid_t,
    parent_start: linux.gid_t,
    map_len: u32 = 1,

    pub inline fn one(from: linux.gid_t, to: linux.gid_t) GidMap {
        return .{ .island_start = to, .parent_start = from };
    }

    pub fn currentToRoot() GidMap {
        return .{
            .island_start = 0,
            .parent_start = linux.getgid(),
            .map_len = 1,
        };
    }

    pub fn currentToCurrent() GidMap {
        const gid = linux.getgid();
        return .{
            .island_start = gid,
            .parent_start = gid,
            .map_len = 1,
        };
    }
};

pub const InitStage = enum {
    /// Namepsaces have been unshared, UID/GID mappings have been made,
    /// and the initial UID and GID have been set.
    initial,
    /// The filesystem still have to be created.
    fs_setup,
    /// All elementary initialization of the sandbox has been done.
    done,
};
