const std = @import("std");
const model = @import("./model.zig");
const posix = std.posix;
const net = std.net;
const netinet = @cImport({
    @cInclude("netinet/in.h");
});

/// Send a UDP packet to a specific address
pub fn udpSend(buf: []const u8, dest_addr: *const posix.sockaddr) !usize {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);
    const addr = net.Address.initPosix(@alignCast(dest_addr));
    const bytes = try posix.sendto(sock, buf, 0, dest_addr, addr.getOsSockLen());
    std.log.scoped(.udp).info("Sent {d} bytes to {f}", .{ bytes, addr });
    return bytes;
}

pub const Multicast = struct {
    const Self = @This();
    addr: net.Address,
    sock: posix.socket_t,

    var recv_buf: [1024]u8 = undefined;

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
        const addr = net.Address.initPosix(@alignCast(src_addr));
        log.info("Received {d} bytes from {f}", .{ bytes, addr });
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
