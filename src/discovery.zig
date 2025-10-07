const std = @import("std");
const posix = std.posix;
const net = std.net;
const model = @import("./model.zig");
const network = @import("./network.zig");
const Cons = @import("./main.zig").Cons;
const Client = @import("./client.zig").Client;
const Server = @import("./server.zig").Server;

/// Represents a LocalSend peer with enhanced functionality
pub const Peer = struct {
    info: model.MultiCastDto,
    addr: net.Address,
    last_seen: i64, // Unix timestamp
    status: Status = .online,

    const Self = @This();

    pub const Status = enum { online, offline };

    pub fn init(info: model.MultiCastDto, from_addr: *const net.Address) !Self {
        const port = info.port orelse Cons.PORT;
        var addr = net.Address.initPosix(@alignCast(&from_addr.any));
        addr.setPort(port);
        return .{
            .info = info,
            .addr = addr,
            .last_seen = std.time.timestamp(),
        };
    }

    pub fn deinit(_: *Self) void {}

    pub fn getPort(self: *const Self) u16 {
        return self.addr.getPort();
    }

    pub fn getIPWithPort(self: *const Self, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{f}", .{self.addr});
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

    /// TODO: std.fmt.alt to use multiple format fn https://github.com/ziglang/zig/blob/150169f1e0cf08d4b76fed81fc205a63177b6e01/lib/std/Uri.zig#L66
    pub fn format(self: *const Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [64]u8 = undefined;
        const ip = self.getIPWithPort(&buf) catch "unknown";
        const time_diff = std.time.timestamp() - self.last_seen;
        try w.print("{s} {s}\n", .{ self.getDeviceIcon(), self.info.alias });
        try w.print("   IP: {s} | Status: {s}\n", .{ ip, self.getStatusString() });
        try w.print("   Device: {s} {s} | Version: {s}\n", .{
            self.info.deviceType orelse "unknown",
            self.info.deviceModel orelse "unknown",
            self.info.version orelse "unknown",
        });
        try w.print("   Last seen: {}s ago | Fingerprint: {s}", .{ time_diff, self.info.fingerprint[0..8] });
    }
};

pub const Registry = struct {
    peers: std.StringHashMap(Peer),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    const Self = @This();
    const log = std.log.scoped(.registry);

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(Peer).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.peers.iterator();
        while (it.next()) |kv| kv.value_ptr.deinit();
        self.peers.deinit();
    }

    /// Register or update a peer
    pub fn registerPeer(self: *Self, info: model.MultiCastDto, addr: *const net.Address) !*const Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
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
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.peers.fetchRemove(fingerprint)) |kv| {
            log.info("Removed peer: {s}", .{kv.value.info.alias});
            return true;
        }
        return false;
    }

    /// Clean up stale peers (not seen for a while)
    pub fn cleanupStalePeers(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isStale(Cons.STALE_THRESHOLD_SECONDS)) {
                entry.value_ptr.status = .offline;
                _ = self.removePeer(entry.value_ptr.info.fingerprint);
            }
        }
    }

    /// Get a peer by fingerprint
    pub fn getPeer(self: *Self, fingerprint: []const u8) ?*const Peer {
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
    // server: Server,
    registry: Registry,
    send_paths: []const []const u8,
    multicast: network.Multicast,
    info: model.MultiCastDto,

    const Self = @This();
    const log = std.log.scoped(.manager);

    pub fn init(allocator: std.mem.Allocator, paths: []const []const u8) !Self {
        const info = try model.MultiCastDto.init(allocator);
        return .{
            .allocator = allocator,
            .last_cleanup_time = std.time.timestamp(),
            .client = try .init(allocator, info),
            // .server = try .init(allocator, info, Cons.SAVE_DIR),
            .registry = .init(allocator),
            .send_paths = paths,
            .multicast = try .init(try net.Address.parseIp(Cons.MULTICAST_IP, Cons.PORT)),
            .info = info,
        };
    }

    pub fn deinit(self: *Self) void {
        self.multicast.close();
        self.client.deinit();
        // self.server.deinit();
        self.registry.deinit();
        self.info.deinit(self.allocator);
    }

    pub fn run(self: *Self) !void {
        // const thread = try std.Thread.spawn(.{}, listenMultiCast, .{self});
        _ = try std.Thread.spawn(.{}, listenMultiCast, .{self});
        // const thread = try std.Thread.spawn(.{}, listenTcp, .{&self.server});
        // thread.detach();
        // try self.listenMultiCast();
        // announce once
        // thread.join();
        while (true) {
            try self.sendAnnounce();
            std.Thread.sleep(5 * std.time.ns_per_s);
        }
    }

    const tlog = std.log.scoped(.discovery);
    fn listenTcp(srv: *Server) !void {
        srv.listen() catch |err| {
            log.err("Server error: {}", .{err});
        };
    }
    fn listenMultiCast(self: *Self) !void {
        while (true) {
            tlog.info("Waiting for peers...", .{});
            const buf, const addr = try self.multicast.recv();
            const parsed = try std.json.parseFromSlice(model.MultiCastDto, self.allocator, buf, .{});
            defer parsed.deinit();
            const peer_info = parsed.value;

            try self.cleanupStalePeers();
            const peer_announce = peer_info.announce orelse peer_info.announcement orelse false;
            if (peer_announce) {
                try self.handleAnnounce(peer_info, &addr);
                continue;
            }
            const peer = self.registry.getPeer(peer_info.fingerprint) orelse {
                tlog.info("Unknown peer, skipping", .{});
                continue;
            };
            try self.client.sendFiles(&peer.addr, self.send_paths);
            // const stdin: std.fs.File = .stdin();
            // var stdio_buffer: [1024]u8 = undefined;
            // var file_reader: std.fs.File.Reader = stdin.reader(&stdio_buffer);
            // try std.zig.readSourceFileToEndAlloc(self.allocator, &file_reader);
            return;
        }
    }

    // TODO: no alloc
    fn sendAnnounce(self: *const Self) !void {
        const me = try std.json.Stringify.valueAlloc(self.allocator, self.info, .{});
        defer self.allocator.free(me);
        _ = try self.multicast.send(me);
    }

    fn handleAnnounce(self: *Self, peer_info: model.MultiCastDto, addr: *const net.Address) !void {
        const peer = try self.registry.registerPeer(peer_info, addr);
        const me = try std.json.Stringify.valueAlloc(self.allocator, self.info, .{});
        defer self.allocator.free(me);
        tlog.info("{f}", .{self.registry});
        try self.client.register(&peer.addr, me);
        _ = try network.udpSend(&peer.addr, me); // fallback
    }

    /// Periodic cleanup wrapper that checks if it's time to run cleanup
    fn cleanupStalePeers(self: *Self) !void {
        const now = std.time.timestamp();
        if (now - self.last_cleanup_time > Cons.CLEANUP_INTERVAL_SECONDS) {
            try self.registry.cleanupStalePeers();
            self.last_cleanup_time = now;
        }
    }
};
