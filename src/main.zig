const std = @import("std");
const UDPClient = @import("./udp.zig").UDPClient;
const posix = std.posix;
const os = std.os;
const net = std.net;
const fs = std.fs;

pub fn main() !void {
    // const gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var client = try UDPClient.init("127.0.0.1", 3000);
    defer client.close();
    try client.listen();
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
