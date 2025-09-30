const std = @import("std");
const model = @import("./model.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn sha256File(allocator: std.mem.Allocator, file_path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var hasher = Sha256.init(.{});
    var buffer: [256]u8 = undefined;

    while (true) {
        const bytes_read = try file.readAll(&buffer);
        if (bytes_read == 0) break;
        hasher.update(buffer[0..bytes_read]);
    }

    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);

    const hex = std.fmt.bytesToHex(&digest, .lower);
    return try allocator.dupe(u8, &hex);
}

const MimeMap = std.StaticStringMap([]const u8).initComptime(.{
    .{ ".jpg", "image/jpeg" },
    .{ ".jpeg", "image/jpeg" },
    .{ ".png", "image/png" },
    .{ ".gif", "image/gif" },
    .{ ".mp4", "video/mp4" },
    .{ ".avi", "video/x-msvideo" },
    .{ ".mp3", "audio/mpeg" },
    .{ ".wav", "audio/wav" },
    .{ ".pdf", "application/pdf" },
    .{ ".txt", "text/plain" },
    .{ ".html", "text/html" },
    .{ ".zip", "application/zip" },
    .{ ".tar", "application/x-tar" },
});

pub fn getMimeType(filename: []const u8) []const u8 {
    const ext = std.fs.path.extension(filename);
    return MimeMap.get(ext) orelse "application/octet-stream";
}

pub fn generateId(allocator: std.mem.Allocator) ![]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const hex = std.fmt.bytesToHex(&bytes, .lower);
    return try allocator.dupe(u8, &hex);
}
