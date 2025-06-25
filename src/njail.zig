//! `njail` is a Zig library that provides a sandboxing mechanism based on Linux namespaces.
//! On most modern Linux Systems, `njail` can work as an unprivileged user, allowing
//! processes to establish a filesystem that suits its needs while providing isolation
//! from the host system.


const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const sys = @import("sys.zig");

pub const Jail = @import("Jail.zig");
pub const fs = @import("fs.zig");
