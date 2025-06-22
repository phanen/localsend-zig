const std = @import("std");
const models = @import("./models.zig");

var alias_buf: [16]u8 = undefined;
var fp_buf: [64]u8 = undefined;
pub fn getMulticastInfo() !models.MultiCastType {
    const alias = try std.fmt.bufPrint(&alias_buf, "{s}_{d}", .{
        std.posix.getenv("USER") orelse "ramdom",
        std.time.timestamp() & 0xffff,
    });

    std.crypto.random.bytes(fp_buf[0 .. fp_buf.len / 2]);
    const hex = std.fmt.bytesToHex(fp_buf[0 .. fp_buf.len / 2], .lower);
    std.mem.copyForwards(u8, &fp_buf, &hex);
    return .{
        .alias = alias,
        .version = "2.0",
        .deviceModel = "linux",
        .deviceType = "headless",
        .fingerprint = &fp_buf,
        .port = 53317,
        .protocol = "http",
        .download = true,
        .announce = true,
    };
}
