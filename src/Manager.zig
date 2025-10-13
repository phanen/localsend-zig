const std = @import("std");
const posix = std.posix;
const net = std.net;
const model = @import("./model.zig");
const network = @import("./network.zig");
const Cons = @import("./main.zig").Cons;
const Client = @import("./client.zig").Client;
const Server = @import("./server.zig").Server;
const Registry = @import("./peer.zig").Registry;
const httpz = @import("httpz");
const api = @import("./api.zig");
const xev = @import("xev");

allocator: std.mem.Allocator,
client: Client,
server: Server,
registry: Registry,
send_paths: []const []const u8,
multicast: network.Multicast,

loop: xev.Loop,
announce_timer: xev.Timer,
addr: net.Address,

var info: model.MultiCastDto = undefined;

const Self = @This();
const log = std.log.scoped(.manager);

pub fn init(allocator: std.mem.Allocator, paths: []const []const u8) !Self {
    info = try model.MultiCastDto.init(allocator);
    const addr = try net.Address.parseIp(Cons.MULTICAST_IP, Cons.PORT);
    return .{
        .allocator = allocator,
        .client = try .init(allocator, &info),
        .server = try .init(allocator, &info),
        .registry = .init(allocator),
        .send_paths = paths,
        .multicast = try .init(addr),
        .loop = try .init(.{}),
        .announce_timer = try .init(),
        .addr = addr,
    };
}

pub fn deinit(self: *Self) void {
    self.multicast.close();
    self.client.deinit();
    self.server.deinit();
    self.registry.deinit();
    info.deinit(self.allocator);
    self.announce_timer.deinit();
    self.loop.deinit();
}

fn timerCallback(
    self_: ?*Self,
    loop: *xev.Loop,
    c: *xev.Completion,
    result: xev.Timer.RunError!void,
) xev.CallbackAction {
    _ = result catch unreachable;
    const self = self_.?;
    self.sendAnnounce() catch unreachable;
    self.announce_timer.run(loop, c, 5000, Self, self, &timerCallback);
    return .disarm;
}

pub fn run(self: *Self) !void {
    var c: xev.Completion = undefined;
    self.announce_timer.run(&self.loop, &c, 500, Self, self, &timerCallback);
    try self.listenMutliCastXev();
    // _ = try std.Thread.spawn(.{}, listenMultiCast, .{self});
    _ = try std.Thread.spawn(.{}, listenHttpz, .{self});
    try self.loop.run(.until_done);
    // _ = try std.Thread.spawn(.{}, listenRaw, .{self});
    // try self.listenHttpz();
}

fn listenRaw(self: *Self) !void {
    self.server.listen() catch |err| log.err("Server error: {}", .{err});
}

fn listenMutliCastXev(self: *Self) !void {
    log.info("Waiting for peers...", .{});
    var c: xev.Completion = undefined;
    var udp_state: xev.UDP.State = undefined;
    var recv_buf: [65536]u8 = undefined;
    var udp = try xev.UDP.init(self.addr);
    try udp.bind(self.addr);
    try network.joinMulticastGroup(udp.fd, &self.addr);
    udp.read(&self.loop, &c, &udp_state, .{ .slice = &recv_buf }, Self, self, udpReadCallback);
}

fn udpReadCallback(
    self_: ?*Self,
    _: *xev.Loop,
    _: *xev.Completion,
    _: *xev.UDP.State,
    addr: std.net.Address,
    _: xev.UDP,
    b: xev.ReadBuffer,
    r: xev.ReadError!usize,
) xev.CallbackAction {
    const self = self_.?;
    const n = r catch |err| {
        switch (err) {
            error.EOF => {},
            else => std.log.warn("err={}", .{err}),
        }

        return .disarm;
    };

    // if (!std.mem.eql(u8, b.slice[0..n], EXPECTED)) @panic("Unexpected data.");
    const buf = b.slice[0..n];
    const parsed = std.json.parseFromSlice(model.MultiCastDto, self.allocator, buf, .{}) catch unreachable;
    defer parsed.deinit();
    const peer_info = parsed.value;
    const peer_announce = peer_info.announce orelse peer_info.announcement orelse false;
    if (peer_announce) self.handleAnnounce(peer_info, &addr) catch unreachable;
    const peer = self.registry.getPeer(peer_info.fingerprint) orelse {
        log.info("Unknown peer, skipping", .{});
        return .rearm;
    };
    self.client.sendFiles(&peer.addr, self.send_paths) catch unreachable;
    return .disarm;
}

fn listenMultiCast(self: *Self) !void {
    while (true) {
        log.info("Waiting for peers...", .{});
        const buf, const addr = try self.multicast.recv();
        const parsed = try std.json.parseFromSlice(model.MultiCastDto, self.allocator, buf, .{});
        defer parsed.deinit();
        const peer_info = parsed.value;
        const peer_announce = peer_info.announce orelse peer_info.announcement orelse false;
        if (peer_announce) try self.handleAnnounce(peer_info, &addr);
        const peer = self.registry.getPeer(peer_info.fingerprint) orelse {
            log.info("Unknown peer, skipping", .{});
            continue;
        };
        try self.client.sendFiles(&peer.addr, self.send_paths);
        // const stdin: std.fs.File = .stdin();
        // var stdio_buffer: [1024]u8 = undefined;
        // var file_reader: std.fs.File.Reader = stdin.reader(&stdio_buffer);
        // try std.zig.readSourceFileToEndAlloc(self.allocator, &file_reader);
    }
}

// TODO: no alloc
// FIXME: announce still don't work
fn sendAnnounce(self: *const Self) !void {
    const me = try std.json.Stringify.valueAlloc(self.allocator, info, .{});
    defer self.allocator.free(me);
    _ = try self.multicast.send(me);
}

fn handleAnnounce(self: *Self, peer_info: model.MultiCastDto, addr: *const net.Address) !void {
    log.info("handle announcement", .{});
    const peer = try self.registry.registerPeer(peer_info, addr);
    const me = try std.json.Stringify.valueAlloc(self.allocator, info, .{});
    defer self.allocator.free(me);
    try self.client.register(&peer.addr, me);
    _ = try network.udpSend(&peer.addr, me); // fallback
}

const l = std.log.scoped(.httpz);

// must pub this, otherwise std.meta.hasFn don't detect it
// https://github.com/karlseguin/http.zig/blob/86e86b2e6e34706bd13c740e86eabae401eba61d/src/httpz.zig#L506
pub fn dispatch(self: *Self, action: httpz.Action(*Self), req: *httpz.Request, res: *httpz.Response) !void {
    // not sure why log don't work
    l.info("{} {s}", .{ req.method, req.url.raw });
    try action(self, req, res);
}

fn listenHttpz(self: *Self) !void {
    var server = try httpz.Server(*Self).init(self.allocator, .{ .address = "0.0.0.0", .port = Cons.PORT }, self);
    defer server.deinit();
    defer server.stop();
    var router = try server.router(.{});
    router.get("/", handleRoot, .{});
    router.post(api.ApiRoute.register.path(), handleRegister, .{});
    router.get(api.ApiRoute.info.path(), handleInfo, .{});
    l.info("server listening http://{?s}:{?d}/", .{ server.config.address, server.config.port });
    try server.listen();
}

fn handleRoot(_: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    const ua = req.header("user-agent") orelse return;
    const fmt =
        \\<!DOCTYPE html>
        \\ <div>{s}</div>
        \\ <ul>
        \\ <li><a href="{s}">{s}</a>
        \\ <li><a href="{s}">{s}</a>
    ;
    res.body = try std.fmt.allocPrint(res.arena, fmt, .{
        ua,
        api.ApiRoute.info.path(),
        api.ApiRoute.info.path(),
        api.ApiRoute.register.path(),
        api.ApiRoute.register.path(),
    });
}

fn handleRegister(self: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    const peer_info = try req.json(model.MultiCastDto) orelse return;
    _ = try self.registry.registerPeer(peer_info, &req.address);
    try res.json(model.RegisterResponseDto.fromMultiCastDto(&info), .{});
}

fn handleInfo(_: *Self, req: *httpz.Request, res: *httpz.Response) !void {
    _ = (try req.query()).get("fingerprint") orelse return;
    try res.json(model.InfoDto.fromMultiCastDto(&info), .{});
}
