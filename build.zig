const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("njail", .{
        .root_source_file = b.path("src/njail.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = lib_mod;
}
