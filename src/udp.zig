const std = @import("std");
const posix = std.posix;
const os = std.os;
const net = std.net;
const fs = std.fs;
const netinet = @cImport({
    @cInclude("netinet/in.h");
});

const Self = @This();
addr: net.Address,
sock: posix.socket_t,
buf: [1024]u8,

pub fn init(ip: []const u8, port: u16) !Self {
    const addr = try net.Address.parseIp4(ip, port);
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    return .{ .addr = addr, .sock = sock, .buf = undefined };
}
pub fn close(self: Self) void {
    posix.close(self.sock);
}

pub fn listen(self: Self) !void {
    try posix.bind(self.sock, &self.addr.any, self.addr.getOsSockLen());
    const request = netinet.ip_mreq{
        .imr_multiaddr = netinet.struct_in_addr{ .s_addr = self.addr.in.sa.addr },
        .imr_interface = netinet.struct_in_addr{ .s_addr = std.mem.nativeToBig(u32, netinet.INADDR_ANY) },
    };
    std.debug.print("DEBUGPRINT[319]: udp.zig:32: request={any}\n", .{request});
    try posix.setsockopt(self.sock,
        // posix.SOL.SOCKET,
        posix.IPPROTO.IP, os.linux.IP.ADD_MEMBERSHIP,
        // std.mem.asBytes(&request),
        &std.mem.toBytes(request));

    // const flags = try posix.fcntl(self.sock, posix.F.GETFL, 0);
    // std.debug.print("DEBUGPRINT[323]: udp.zig:38: flags={any}\n", .{flags});
    // try posix.fcntl(self.sock, posix.F.SETFL, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK);
    var buf = self.buf;
    while (true) {
        var sockaddr: posix.sockaddr = undefined;
        // var addrlen = @sizeOf(sockaddr);
        var addrlen: u32 = @sizeOf(posix.sockaddr);
        const bytes = try posix.recvfrom(self.sock, buf[0..], 0, &sockaddr, &addrlen);
        const addr = net.Address.parseIp4(&sockaddr.data, 0);
        std.debug.print("<- {any}: [{d}] {s}\n", .{ addr, bytes, buf[0..bytes] });
        // try self.sendFile("src/main.zig");
    }
}

pub fn sendFile(self: Self, filename: []const u8) !void {
    var buf: [1024]u8 = undefined;
    const content = try fs.cwd().readFile(filename, buf[0..]);
    const bytes = try posix.sendto(self.sock, content, 0, &self.addr.any, self.addr.getOsSockLen());
    std.debug.print("-> {any}: [{d}]", .{ self.addr.in, bytes });
}

// pub fn receive(self: Self) !void {
//     const bytes = try posix.recvfrom(self.socket, self.buffer[0..], 0, null, null);
//     std.debug.print("<- {d} bytes: {s}\n", .{ bytes, self.buffer[0..bytes] });
// }
