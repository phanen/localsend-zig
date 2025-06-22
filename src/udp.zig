const std = @import("std");
const posix = std.posix;
const os = std.os;
const net = std.net;
const fs = std.fs;

pub const UDPClient = struct {
    const Self = @This();
    addr: net.Address,
    sock: posix.socket_t,
    buf: [1024]u8,
    pub fn init(ip: []const u8, port: u16) !Self {
        const addr = try net.Address.parseIp4(ip, port);
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        return Self{ .addr = addr, .sock = sock, .buf = undefined };
    }
    pub fn close(self: Self) void {
        posix.close(self.sock);
    }
    pub fn listen(self: Self) !void {
        try posix.bind(self.sock, &self.addr.any, self.addr.getOsSockLen());
        var buf = self.buf;
        while (true) {
            const bytes = try posix.recvfrom(self.sock, buf[0..], 0, null, null);
            std.debug.print("<- {any}: [{d}] {s}\n", .{ self.addr, bytes, buf[0..bytes] });
            try self.sendFile("src/main.zig");
        }
    }
    pub fn sendFile(self: Self, filename: []const u8) !void {
        var buf: [1024]u8 = undefined;
        const content = try fs.cwd().readFile(filename, buf[0..]);
        const bytes = try posix.sendto(self.sock, content, 0, &self.addr.any, self.addr.getOsSockLen());
        std.debug.print("-> {any}: [{d}]\n", .{ self.addr.in, bytes });
    }
    // pub fn receive(self: Self) !void {
    //     const bytes = try posix.recvfrom(self.socket, self.buffer[0..], 0, null, null);
    //     std.debug.print("<- {d} bytes: {s}\n", .{ bytes, self.buffer[0..bytes] });
    // }
    //
};
