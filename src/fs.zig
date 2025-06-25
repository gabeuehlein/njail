pub const max_multicall_binary_args = 14;

pub const SetupMulticallOptions = struct {
    extra_args: []const [:0]const u8,
    relativize: bool = true,
    delimiter: u8 = '\n',
    ignore_eexist: bool = true,
    prefix: []const u8 = "/",
};

/// Sets up a multicall binary (e.g. `/bin/busybox`) using arguments provided that are assumed to 
/// produce a delimited list of the root-relative programs it offers via a symbolic link.
pub fn setupMulticallBinary(j: *Jail, target: [:0]const u8, options: SetupMulticallOptions) !void {
    // TODO this should probably be cleaned up.
    if (options.extra_args.len >= max_multicall_binary_args)
        return error.TooManyArgs;
    if (!std.fs.path.isAbsolute(target))
        return error.NotAbsolute;
    var argv: [max_multicall_binary_args + 2:null]?[*:0]const u8 = @splat(null);
    for (argv[1..][0..options.extra_args.len], options.extra_args) |*ptr, extra_arg|
        ptr.* = extra_arg.ptr;
    const stdout_read, const stdout_fd = try posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    defer posix.close(stdout_fd);
    defer posix.close(stdout_read);
    const child_pid = try posix.fork();
    if (child_pid == 0) {
        const empty_envp: [0:null]?[*:0]const u8 = .{};
        try posix.dup2(stdout_fd, posix.STDOUT_FILENO);
        const new_target_space = try toPosixPathWithPrefix("/new", target);
        const new_target = sliceTo(&new_target_space, 0);
        argv[0] = new_target.ptr;
        std.posix.execveZ(new_target, &argv, &empty_envp) catch posix.exit(1);
    }

    const wait_result = posix.waitpid(child_pid, 0);
    if (posix.W.EXITSTATUS(wait_result.status) != 0)
        return error.ChildFailed;

    var path_buf: [posix.PATH_MAX]u8 = undefined;
    var scratch: [posix.PATH_MAX]u8 = undefined;
    var scratch1: [posix.PATH_MAX]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var f: std.fs.File = .{ .handle = stdout_read };
    const reader = f.reader();
    const extra_sep: []const u8 = if (options.prefix.len != 0 and options.prefix[options.prefix.len - 1] != '/')
        "/"
    else
        "";

    while (reader.readUntilDelimiterOrEof(&path_buf, '\n') catch |e| switch (e) {
        error.WouldBlock => return,
        else => return e,
    }) |line| {
        defer if (options.relativize) fba.reset();
        const absolute = try std.fmt.bufPrint(&scratch1, "{s}{s}{s}", .{options.prefix, extra_sep, line});
        const link_path = if (options.relativize)
            try std.fs.path.relative(fba.allocator(), std.fs.path.dirname(absolute) orelse line, target)
        else
            try std.fmt.bufPrint(&scratch, "{s}{s}{s}", .{options.prefix, extra_sep, target});
        j.symLink(absolute, link_path) catch |e| {
            if (options.ignore_eexist)
                if (e == error.PathAlreadyExists)
                    continue;
            return e;
        };
    }
}

/// Does not return an error when creating directories that already exist.
pub fn mkdirs(path: []const u8, mode: posix.mode_t) !void {
    var components = try std.fs.path.componentIterator(path);
    const fd = if (std.fs.path.isAbsolute(path))
        try posix.openZ("/", .{ .DIRECTORY = true }, 0)
    else
        posix.AT.FDCWD;
    try mkdirsInner(fd, mode, &components);
}

fn mkdirsInner(dirfd: posix.fd_t, mode: posix.mode_t, components: *std.fs.path.ComponentIterator(.posix, u8)) !void {
    defer {
        if (dirfd != posix.AT.FDCWD) {
            @branchHint(.likely);
            posix.close(dirfd); 
        }
    }
    const component = components.next() orelse return;
    var exists_already = false;
    errdefer {
        if (!exists_already)
            posix.unlinkat(dirfd, component.name, posix.AT.REMOVEDIR) catch {};
    }
    posix.mkdirat(dirfd, component.name, mode) catch |e| switch (e) {
        error.PathAlreadyExists => exists_already = true,
        else => return e,
    };
    const new_fd = try posix.openat(dirfd, component.name, .{ .DIRECTORY = true }, 0);
    return mkdirsInner(new_fd, mode, components);
}

/// Used to convert a slice to a null terminated slice on the stack with the prefix `prefix`.
/// Does not append a `/` to `prefix` if `file_path[0] != '/'`
fn toPosixPathWithPrefix(comptime prefix: []const u8, file_path: []const u8) error{NameTooLong}![posix.PATH_MAX - 1:0]u8 {
    comptime std.debug.assert(std.mem.indexOfScalar(u8, prefix, 0) == null);
    if (std.debug.runtime_safety) std.debug.assert(std.mem.indexOfScalar(u8, file_path, 0) == null);
    var path_with_null: [posix.PATH_MAX - 1:0]u8 = undefined;
    // >= rather than > to make room for the null byte
    if (file_path.len + prefix.len >= posix.PATH_MAX) return error.NameTooLong;
    @memcpy(path_with_null[0..prefix.len], prefix);
    @memcpy(path_with_null[prefix.len..][0..file_path.len], file_path);
    path_with_null[file_path.len + prefix.len] = 0;
    return path_with_null;
}

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const sliceTo = std.mem.sliceTo;
const Jail = @import("Jail.zig");
