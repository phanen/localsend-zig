const std = @import("std");
const models = @import("./models.zig");

var alias_buf: [16]u8 = undefined;
var fingerprint: [64]u8 = undefined;
pub fn makeAnnouncement(info: *?models.MultiCastDto) !void {
    if (info.* != null) {
        return; // already initialized
    }
    const alias = try std.fmt.bufPrint(&alias_buf, "{s}_{d}", .{
        std.posix.getenv("USER") orelse "ramdom",
        std.time.timestamp() & 0xffff,
    });
    std.crypto.random.bytes(fingerprint[0 .. fingerprint.len / 2]);
    const hex = std.fmt.bytesToHex(fingerprint[0 .. fingerprint.len / 2], .upper);
    std.mem.copyForwards(u8, &fingerprint, &hex);
    info.* = .{
        .alias = alias,
        .version = "2.1",
        .deviceModel = "linux",
        .deviceType = "headless",
        .fingerprint = &fingerprint,
        .port = 53317,
        .protocol = "http",
        .download = false,
        .announce = true,
        .announcement = true,
    };
}
