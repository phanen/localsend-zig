const std = @import("std");
const discovery = @import("./discovery.zig");

pub const Cons = struct {
    pub const PORT: u16 = 53317; // default multicast/tcp port
    pub const PROTOCOL = "http";
    pub const MULTICAST_IP = "224.0.0.167";
    pub const CLEANUP_INTERVAL_SECONDS = 30;
    pub const STALE_THRESHOLD_SECONDS = 120;
    pub const SAVE_DIR = "received_files";
};

// Set up custom log handler and log level
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logFn,
};

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime @intFromEnum(level) > @intFromEnum(std.options.log_level)) {
        return;
    }

    const prefix1 = comptime level.asText();
    const prefix2 = comptime if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    // Print the message to stderr, silently ignoring any errors
    std.debug.print(prefix1 ++ prefix2 ++ format ++ "\n", args);
}

const log = std.log.scoped(.main);

var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
const allocator = std.heap.page_allocator;

pub fn main() !void {
    log.info("Sender Mode", .{});
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len <= 1) {
        log.info("No file provided", .{});
        return;
    }
    const paths = args[1..];
    for (paths) |p| log.info("File to be sent: {s}", .{p});
    var manager = try discovery.Manager.init(allocator, paths);
    defer manager.deinit();
    try manager.run();
}
