const std = @import("std");
const models = @import("./models.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

var alias_buf: [16]u8 = undefined;
var fingerprint: [64]u8 = undefined;
pub fn makeAnnouncement() !models.MultiCastDto {
    const alias = try std.fmt.bufPrint(&alias_buf, "{s}_{d}", .{
        std.posix.getenv("USER") orelse "ramdom",
        std.time.timestamp() & 0xffff,
    });
    std.crypto.random.bytes(fingerprint[0 .. fingerprint.len / 2]);
    const hex = std.fmt.bytesToHex(fingerprint[0 .. fingerprint.len / 2], .upper);
    std.mem.copyForwards(u8, &fingerprint, &hex);
    return .{
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

pub fn hexSha256(in: []const u8, out: *[Sha256.digest_length * 2]u8) void {
    Sha256.hash(in, out[0..Sha256.digest_length], .{});
    const hex = std.fmt.bytesToHex(out[0..Sha256.digest_length], .upper);
    std.mem.copyForwards(u8, out, &hex);
}
