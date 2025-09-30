const std = @import("std");
const model = @import("./model.zig");
const posix = std.posix;
const net = std.net;
const netinet = @cImport({
    @cInclude("netinet/in.h");
});

// Helper function to safely copy sockaddr to proper type
fn safeCopy(comptime T: type, src: *const posix.sockaddr) T {
    var result: T = undefined;
    @memcpy(@as([*]u8, @ptrCast(&result))[0..@sizeOf(T)], @as([*]const u8, @ptrCast(src))[0..@sizeOf(T)]);
    return result;
}

fn formatIPv4(buf: []u8, ip_bytes: *const [4]u8, port: ?u16) ![]const u8 {
    return if (port) |p|
        try std.fmt.bufPrint(buf, "{}.{}.{}.{}:{}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], p })
    else
        try std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] });
}

fn formatIPv6(buf: []u8, ip_bytes: *const [16]u8, port: ?u16) ![]const u8 {
    const segments = .{
        (@as(u16, ip_bytes[0]) << 8) | ip_bytes[1],
        (@as(u16, ip_bytes[2]) << 8) | ip_bytes[3],
        (@as(u16, ip_bytes[4]) << 8) | ip_bytes[5],
        (@as(u16, ip_bytes[6]) << 8) | ip_bytes[7],
        (@as(u16, ip_bytes[8]) << 8) | ip_bytes[9],
        (@as(u16, ip_bytes[10]) << 8) | ip_bytes[11],
        (@as(u16, ip_bytes[12]) << 8) | ip_bytes[13],
        (@as(u16, ip_bytes[14]) << 8) | ip_bytes[15],
    };
    return if (port) |p|
        try std.fmt.bufPrint(buf, "[{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}]:{}", .{ segments[0], segments[1], segments[2], segments[3], segments[4], segments[5], segments[6], segments[7], p })
    else
        try std.fmt.bufPrint(buf, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", segments);
}

fn formatSockaddrGeneric(
    buf: []u8,
    addr: *const posix.sockaddr,
    include_port: bool,
    comptime SockType: type,
    comptime IpBytesType: type,
    formatFn: fn ([]u8, IpBytesType, ?u16) anyerror![]const u8,
) ![]const u8 {
    const temp_addr = safeCopy(SockType, addr);
    const ip_bytes = @as(IpBytesType, @ptrCast(&temp_addr.addr));
    const port = if (include_port) std.mem.bigToNative(u16, temp_addr.port) else null;
    return try formatFn(buf, ip_bytes, port);
}

/// Extract IP and optionally port from sockaddr to buffer (no allocation)
/// If include_port is true, format as "IP:PORT", otherwise just "IP"
pub fn formatSockaddr(buf: []u8, addr: *const posix.sockaddr, include_port: bool) ![]const u8 {
    return switch (addr.family) {
        posix.AF.INET => try formatSockaddrGeneric(buf, addr, include_port, posix.sockaddr.in, *const [4]u8, formatIPv4),
        posix.AF.INET6 => try formatSockaddrGeneric(buf, addr, include_port, posix.sockaddr.in6, *const [16]u8, formatIPv6),
        else => if (include_port)
            try std.fmt.bufPrint(buf, "unknown(family:{}):?", .{addr.family})
        else
            try std.fmt.bufPrint(buf, "unknown(family:{})", .{addr.family}),
    };
}

/// Convenience wrapper for when you need an allocating version
pub fn formatSockaddrAlloc(allocator: std.mem.Allocator, addr: *const posix.sockaddr, include_port: bool) ![]const u8 {
    var buf: [64]u8 = undefined;
    const result = try formatSockaddr(&buf, addr, include_port);
    return try allocator.dupe(u8, result);
}

/// Send a UDP packet to a specific address
pub fn udpSend(buf: []const u8, dest_addr: *const posix.sockaddr) !usize {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);

    const bytes = try posix.sendto(sock, buf, 0, dest_addr, @sizeOf(posix.sockaddr));

    // Use buffer instead of allocator to avoid heap allocation
    var addr_buf: [64]u8 = undefined;
    const addr_str = formatSockaddr(&addr_buf, dest_addr, true) catch "unknown"; // Include port for logging
    std.log.info("Sent {d} bytes to {s}", .{ bytes, addr_str });
    return bytes;
}

pub const Multicast = struct {
    const Self = @This();
    addr: net.Address,
    sock: posix.socket_t,

    var recv_buf: [1024]u8 = undefined;
    var addr_buf: [64]u8 = undefined;

    const log = std.log.scoped(.multicast);
    pub fn init(ip: []const u8, port: u16) !Self {
        const addr = try net.Address.parseIp(ip, port);
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        // Allow address reuse
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        // Bind to the multicast address
        try posix.bind(sock, &addr.any, addr.getOsSockLen());

        // Join the multicast group
        const request = netinet.ip_mreq{
            .imr_multiaddr = netinet.struct_in_addr{ .s_addr = addr.in.sa.addr },
            .imr_interface = netinet.struct_in_addr{ .s_addr = std.mem.nativeToBig(u32, netinet.INADDR_ANY) },
        };
        // TODO: use posix.ADD_MEMBERSHIP
        try posix.setsockopt(sock, posix.IPPROTO.IP, std.os.linux.IP.ADD_MEMBERSHIP, &std.mem.toBytes(request));

        log.info("UDP socket initialized on {s}:{d}", .{ ip, port });
        return .{ .addr = addr, .sock = sock };
    }

    pub fn close(self: *Self) void {
        posix.close(self.sock);
        log.info("UDP socket closed", .{});
    }

    /// Receive a multicast packet
    pub fn recv(self: *Self, src_addr: *posix.sockaddr) ![]const u8 {
        var addrlen: u32 = @sizeOf(posix.sockaddr);
        const bytes = try posix.recvfrom(self.sock, &recv_buf, 0, src_addr, &addrlen);
        const addr_str = formatSockaddr(&addr_buf, src_addr, true) catch "unknown"; // Include port for logging
        log.info("Received {d} bytes from {s}", .{ bytes, addr_str });
        return recv_buf[0..bytes];
    }

    /// Send a packet to the multicast group
    pub fn send(self: *Self, buf: []const u8) !usize {
        // Create a new UDP socket for sending
        const send_sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(send_sock);

        // avoid loopback https://stackoverflow.com/questions/33121208/loopback-in-multicast
        const loop = .{0};
        try posix.setsockopt(send_sock, posix.IPPROTO.IP, std.os.linux.IP.MULTICAST_LOOP, &loop);
        // Send the buffer to the multicast group address
        const bytes = try posix.sendto(send_sock, buf, 0, &self.addr.any, self.addr.getOsSockLen());
        log.info("Sent {d} bytes to multicast group", .{bytes});
        return bytes;
    }
};
