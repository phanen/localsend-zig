const std = @import("std");
const model = @import("./model.zig");
const discovery = @import("./discovery.zig");
const network = @import("./network.zig");
const Server = @import("./server.zig").Server;
const api = @import("./api.zig");

pub const Cons = struct {
    pub const PORT: u16 = 53317; // default multicast port
    pub const PROTOCOL = "http";
    pub const MULTICAST_IP = "224.0.0.167";
    pub const CLEANUP_INTERVAL_SECONDS = 30;
    pub const STALE_THRESHOLD_SECONDS = 120;
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
const allocator = gpa.allocator();
var buf: [1024]u8 = undefined;

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

fn recv(info: model.MultiCastDto) !void {
    // Create device info for server
    const device_info = model.InfoDto{
        .alias = info.alias,
        .version = info.version.?,
        .deviceModel = info.deviceModel,
        .deviceType = info.deviceType,
        .fingerprint = info.fingerprint,
        .download = false,
    };

    // Start HTTP server in a separate thread
    const ServerThread = struct {
        fn run(srv: *Server) void {
            srv.listen() catch |err| {
                log.err("Server error: {}", .{err});
            };
        }
    };

    var srv = try Server.init(
        allocator,
        Cons.PORT,
        device_info,
        "received_files",
        false, // HTTP only for now
    );
    defer srv.deinit();

    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{&srv});
    thread.detach();
}
