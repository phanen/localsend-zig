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

    try posix.bind(sock, &addr.any, addr.getOsSockLen());
    const request = netinet.ip_mreq{
        .imr_multiaddr = netinet.struct_in_addr{ .s_addr = addr.in.sa.addr },
        .imr_interface = netinet.struct_in_addr{ .s_addr = std.mem.nativeToBig(u32, netinet.INADDR_ANY) },
    };
    try posix.setsockopt(sock,
        // posix.SOL.SOCKET,
        posix.IPPROTO.IP, os.linux.IP.ADD_MEMBERSHIP,
        // std.mem.asBytes(&request),
        &std.mem.toBytes(request));

    // const flags = try posix.fcntl(self.sock, posix.F.GETFL, 0);
    // try posix.fcntl(self.sock, posix.F.SETFL, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK);
    return .{ .addr = addr, .sock = sock, .buf = undefined };
}
pub fn close(self: Self) void {
    posix.close(self.sock);
}

// assume we are receiving a multicast packet...
pub fn recv(self: Self, buf: []u8, src_addr: *posix.sockaddr) !usize {
    var addrlen: u32 = @sizeOf(posix.sockaddr);
    const bytes = try posix.recvfrom(self.sock, buf[0..], 0, src_addr, &addrlen);
    // std.debug.print("DEBUGPRINT[349]: udp.zig:42: src_addr={any}\n", .{src_addr});
    // const addrp: *posix.sockaddr.in = @ptrCast(@alignCast(src_addr));
    // const stdout = std.io.getStdErr().writer();
    // try std.fmt.format(stdout, "<- {}.{}.{}.{}:{}: [{d}] {s}\n", .{
    //     @as(*const [4]u8, @ptrCast(&addrp.addr))[0],
    //     @as(*const [4]u8, @ptrCast(&addrp.addr))[1],
    //     @as(*const [4]u8, @ptrCast(&addrp.addr))[2],
    //     @as(*const [4]u8, @ptrCast(&addrp.addr))[3],
    //     std.mem.bigToNative(u16, addrp.port),
    //     bytes,
    //     buf[0..bytes],
    // });
    return bytes;
    // try self.sendFile("src/main.zig");
}

pub fn send(_: Self, buf: []const u8, dest_addr: *const posix.sockaddr) !usize {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);
    const bytes = try posix.sendto(sock, buf, 0, dest_addr, @sizeOf(posix.sockaddr));
    return bytes;
}

pub fn sendFile(self: Self, filename: []const u8) !void {
    var buf: [1024]u8 = undefined;
    const content = try fs.cwd().readFile(filename, buf[0..]);
    const bytes = try posix.sendto(self.sock, content, 0, &self.addr.any, self.addr.getOsSockLen());
    std.debug.print("-> {any}: [{d}]", .{ self.addr.in, bytes });
}
