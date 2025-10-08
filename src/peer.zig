const std = @import("std");
const model = @import("./model.zig");
const net = std.net;
const Cons = @import("./main.zig").Cons;

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
