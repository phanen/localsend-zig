const std = @import("std");
const posix = std.posix;
const net = std.net;
const model = @import("./model.zig");
const network = @import("./network.zig");
const Cons = @import("./main.zig").Cons;
const Client = @import("./client.zig").Client;
const Server = @import("./server.zig").Server;
const Registry = @import("./peer.zig").Registry;

/// Robust peer registry with automatic cleanup and management
allocator: std.mem.Allocator,
last_cleanup_time: i64,
client: Client,
server: Server,
registry: Registry,
send_paths: []const []const u8,
multicast: network.Multicast,

var info: model.MultiCastDto = undefined;

const Self = @This();
const log = std.log.scoped(.manager);

pub fn init(allocator: std.mem.Allocator, paths: []const []const u8) !Self {
    info = try model.MultiCastDto.init(allocator);
    return .{
        .allocator = allocator,
        .last_cleanup_time = std.time.timestamp(),
        .client = try .init(allocator, &info),
        .server = try .init(allocator, &info),
        .registry = .init(allocator),
        .send_paths = paths,
        .multicast = try .init(try net.Address.parseIp(Cons.MULTICAST_IP, Cons.PORT)),
    };
}

pub fn deinit(self: *Self) void {
    self.multicast.close();
    self.client.deinit();
    self.server.deinit();
    self.registry.deinit();
    info.deinit(self.allocator);
}

pub fn run(self: *Self) !void {
    // const thread = try std.Thread.spawn(.{}, listenMultiCast, .{self});
    _ = try std.Thread.spawn(.{}, listenMultiCast, .{self});
    // _ = try std.Thread.spawn(.{}, listenTcp, .{&self.server});
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
    const me = try std.json.Stringify.valueAlloc(self.allocator, info, .{});
    defer self.allocator.free(me);
    _ = try self.multicast.send(me);
}

fn handleAnnounce(self: *Self, peer_info: model.MultiCastDto, addr: *const net.Address) !void {
    const peer = try self.registry.registerPeer(peer_info, addr);
    const me = try std.json.Stringify.valueAlloc(self.allocator, info, .{});
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
