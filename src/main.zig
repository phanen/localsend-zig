const std = @import("std");
const http = std.http;

const Client = struct { address: std.net.Address, socket: std.posix.socket_t };
pub fn main() !void {
    const addr = try std.net.Address.parseIp4("127.0.0.1", 3000);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);
    try std.posix.bind(sock, &addr.any, addr.getOsSockLen());

    var buffer: [1024]u8 = undefined;
    while (true) {
        const received_bytes = try std.posix.recvfrom(sock, buffer[0..], 0, null, null);
        std.debug.print("Received {d} bytes: {s}\n", .{ received_bytes, buffer[0..received_bytes] });
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
