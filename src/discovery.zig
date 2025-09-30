const std = @import("std");
const posix = std.posix;
const model = @import("./model.zig");
const network = @import("./network.zig");
const Cons = @import("./main.zig").Cons;
const Client = @import("./client.zig").Client;

/// Represents a LocalSend peer with enhanced functionality
pub const Peer = struct {
    info: model.MultiCastDto,
    addr: posix.sockaddr,
    last_seen: i64, // Unix timestamp
    status: Status = .online,

    const Self = @This();

    pub const Status = enum { online, offline };

    pub fn init(info: model.MultiCastDto, addr: posix.sockaddr) !Self {
        var addr0 = addr;
        const port = info.port orelse Cons.PORT;
        switch (addr.family) {
            posix.AF.INET => setPort(posix.sockaddr.in, &addr0, port),
            posix.AF.INET6 => setPort(posix.sockaddr.in6, &addr0, port),
            else => return error.UnsupportedAddressFamily,
        }
        return .{
            .info = info,
            .addr = addr0,
            .last_seen = std.time.timestamp(),
        };
    }

    pub fn deinit(_: *Self) void {}

    fn setPort(comptime T: type, addr: *posix.sockaddr, port: u16) void {
        const p: *T = @ptrCast(@alignCast(addr));
        p.port = std.mem.nativeToBig(u16, port);
    }

    pub fn getIP(self: *const Self, alloc: std.mem.Allocator) ![]const u8 {
        return network.formatSockaddrAlloc(alloc, &self.addr, false); // IP only, no port
    }

    pub fn getIPWithPort(self: *const Self, buf: []u8) ![]const u8 {
        return network.formatSockaddr(buf, &self.addr, true);
    }

    /// Update the last seen timestamp and mark as online
    pub fn updateActivity(self: *Self, info: model.MultiCastDto) void {
        self.last_seen = std.time.timestamp();
        self.status = .online;
        self.info = info;
    }

    /// Check if peer is considered stale (not seen for threshold seconds)
    pub fn isStale(self: *const Self, threshold_seconds: i64) bool {
        return (std.time.timestamp() - self.last_seen) > threshold_seconds;
    }

    /// Get a human-readable status string
    pub fn getStatusString(self: *const Self) []const u8 {
        return switch (self.status) {
            .online => "online",
            .offline => "offline",
        };
    }

    /// Compare peers by fingerprint for equality
    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.info.fingerprint, other.info.fingerprint);
    }

    /// Get device icon based on device type
    pub fn getDeviceIcon(self: *const Self) []const u8 {
        const dtype = self.info.deviceType orelse "desktop";
        if (std.mem.eql(u8, dtype, "mobile")) return "📱";
        if (std.mem.eql(u8, dtype, "desktop")) return "🖥️";
        if (std.mem.eql(u8, dtype, "web")) return "🌐";
        if (std.mem.eql(u8, dtype, "headless")) return "⚡";
        if (std.mem.eql(u8, dtype, "server")) return "📦";
        return "🖥️"; // default to desktop icon
    }

    /// TODO: we can only use {f}?
    pub fn format(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var ip_buf: [64]u8 = undefined;
        const ip_str = self.getIPWithPort(&ip_buf) catch "unknown";
        const time_diff = std.time.timestamp() - self.last_seen;
        try w.print("{s} {s}\n", .{ self.getDeviceIcon(), self.info.alias });
        try w.print("   IP: {s} | Status: {s}\n", .{ ip_str, self.getStatusString() });
        try w.print("   Device: {s} {s} | Version: {s}\n", .{ self.info.deviceType orelse "unknown", self.info.deviceModel orelse "unknown", self.info.version orelse "unknown" });
        try w.print("   Last seen: {}s ago | Fingerprint: {s}", .{ time_diff, self.info.fingerprint[0..8] });
    }
};

pub const Registry = struct {
    peers: std.StringHashMap(Peer),
    allocator: std.mem.Allocator,

    const Self = @This();
    const log = std.log.scoped(.registry);

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(Peer).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.peers.iterator();
        while (it.next()) |kv| kv.value_ptr.deinit();
        self.peers.deinit();
    }

    /// Register or update a peer
    pub fn registerPeer(self: *Self, info: model.MultiCastDto, addr: posix.sockaddr) !*Peer {
        const gop = try self.peers.getOrPut(info.fingerprint);
        if (gop.found_existing) {
            var peer = gop.value_ptr;
            peer.updateActivity(info);
            log.info("Updated peer: {s} {s}", .{ peer.getDeviceIcon(), peer.info.alias });
        } else {
            gop.value_ptr.* = try Peer.init(info, addr);
            log.info("📱 New peer discovered: {s} ({s})", .{ info.alias, info.deviceType orelse "unknown" });
        }
        return gop.value_ptr;
    }

    /// Remove a specific peer
    pub fn removePeer(self: *Self, fingerprint: []const u8) bool {
        if (self.peers.fetchRemove(fingerprint)) |kv| {
            log.info("Removed peer: {s}", .{kv.value.info.alias});
            return true;
        }
        return false;
    }

    /// Clean up stale peers (not seen for a while)
    pub fn cleanupStalePeers(self: *Self) !void {
        var it = self.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isStale(Cons.STALE_THRESHOLD_SECONDS)) {
                entry.value_ptr.status = .offline;
                _ = self.removePeer(entry.value_ptr.info.fingerprint);
            }
        }
    }

    /// Get a peer by fingerprint
    pub fn getPeer(self: *Self, fingerprint: []const u8) ?*Peer {
        return self.peers.getPtr(fingerprint);
    }

    pub fn format(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const stats = self.getStats();
        try w.print("=== Peer Registry Stats ===\n", .{});
        try w.print("Total peers: {}, Online: {}\n", .{ stats.total, stats.online });

        if (stats.total == 0) {
            try w.print("No peers discovered yet\n", .{});
            return;
        }

        try w.print("=== Active Peers ===\n", .{});
        var it = self.iterator();
        while (it.next()) |entry| {
            const peer = entry.value_ptr;
            try peer.format(w);
            try w.print("\n", .{});
        }
        try w.print("========================\n", .{});
    }

    /// Get count of peers by status
    pub fn getStats(self: *const Self) struct { online: u32, total: u32 } {
        var online: u32 = 0;

        var it = self.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .online) {
                online += 1;
            }
        }

        return .{ .online = online, .total = @intCast(self.peers.count()) };
    }

    pub fn iterator(self: *const Self) std.StringHashMapUnmanaged(Peer).Iterator {
        return self.peers.iterator();
    }
};

/// Robust peer registry with automatic cleanup and management
pub const Manager = struct {
    allocator: std.mem.Allocator,
    last_cleanup_time: i64,
    client: Client,
    registry: Registry,
    send_paths: []const []const u8,

    const Self = @This();
    const log = std.log.scoped(.manager);

    pub fn init(allocator: std.mem.Allocator, paths: []const []const u8) !Self {
        return .{
            .allocator = allocator,
            .last_cleanup_time = std.time.timestamp(),
            .client = try .init(allocator),
            .registry = .init(allocator),
            .send_paths = paths,
        };
    }

    pub fn deinit(self: *Self) void {
        self.client.deinit();
        self.registry.deinit();
    }

    pub fn run(self: *Self) !void {
        // _ = try std.Thread.spawn(.{}, listenThread.run, .{self});
        try self.listenMultiCast();
        // while (true) std.Thread.sleep(5 * std.time.ns_per_s);
    }

    const tlog = std.log.scoped(.discovery);
    fn listenMultiCast(self: *Self) !void {
        var multicast = try network.Multicast.init(Cons.MULTICAST_IP, Cons.PORT);
        const me_str = try std.json.Stringify.valueAlloc(self.allocator, self.client.info, .{});
        defer self.allocator.free(me_str);
        while (true) {
            var addr: posix.sockaddr = undefined;
            tlog.info("Waiting for peers...", .{});
            const buf = try multicast.recv(&addr);
            const parsed = try std.json.parseFromSlice(model.MultiCastDto, self.allocator, buf, .{});
            defer parsed.deinit();
            const peer_info = parsed.value;

            try self.cleanupStalePeers();
            // _ = try multicast.send(me_str);
            const peer_announce = peer_info.announce orelse peer_info.announcement orelse false;
            if (peer_announce) {
                try self.handleAnnounce(peer_info, addr);
                continue;
            }
            const peer = self.registry.getPeer(peer_info.fingerprint) orelse {
                tlog.info("Unknown peer, skipping", .{});
                continue;
            };
            const ip = try peer.getIP(self.allocator);
            defer self.allocator.free(ip);
            const port = peer.info.port orelse Cons.PORT;
            tlog.info("Sending file to {s}:{d}", .{ ip, port });
            try self.client.sendFiles(ip, port, self.send_paths, false);
            // const stdin: std.fs.File = .stdin();
            // var stdio_buffer: [1024]u8 = undefined;
            // var file_reader: std.fs.File.Reader = stdin.reader(&stdio_buffer);
            // try std.zig.readSourceFileToEndAlloc(self.allocator, &file_reader);
            return;
        }
    }

    fn handleAnnounce(self: *Manager, peer_info: model.MultiCastDto, addr: posix.sockaddr) !void {
        // TODO: racing?
        const peer = try self.registry.registerPeer(peer_info, addr);
        const me_str = try std.json.Stringify.valueAlloc(self.allocator, self.client.info, .{});
        tlog.info("{f}", .{self.registry});
        _ = try network.udpSend(me_str, &peer.addr);
    }

    /// Periodic cleanup wrapper that checks if it's time to run cleanup
    fn cleanupStalePeers(self: *Manager) !void {
        const now = std.time.timestamp();
        if (now - self.last_cleanup_time > Cons.CLEANUP_INTERVAL_SECONDS) {
            try self.registry.cleanupStalePeers();
            self.last_cleanup_time = now;
        }
    }
};
