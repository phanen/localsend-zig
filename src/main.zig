const std = @import("std");
const UDP = @import("./udp.zig");
const models = @import("./models.zig");
const utils = @import("./utils.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
const allocator = gpa.allocator();
var buf: [1024]u8 = undefined;

const Peer = struct {
    info: models.MultiCastDto = undefined,
    addr: std.posix.sockaddr = undefined,
    const Self = @This();
    pub fn init(info: models.MultiCastDto, addr: std.posix.sockaddr) Self {
        var addr0 = addr;
        var p: *std.posix.sockaddr.in = @alignCast(@ptrCast(&addr0));
        p.port = std.mem.nativeToBig(u16, info.port orelse 53317);
        return .{ .info = info, .addr = addr0 };
    }
    pub fn getIP(self: *const Self, allo: std.mem.Allocator) ![]const u8 {
        const p = @as(*std.posix.sockaddr.in, @constCast(@alignCast(@ptrCast(&self.addr))));
        const bytes = @as(*const [4]u8, @ptrCast(&p.addr));
        return try std.fmt.allocPrint(allo, "{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
    }
};

pub fn main() !void {
    const myself: models.MultiCastDto = try utils.makeAnnouncement();
    var peers: std.StringHashMapUnmanaged(Peer) = .empty;
    defer peers.deinit(allocator);
    const udp = try UDP.init("224.0.0.167", 53317);
    defer udp.close();
    while (true) {
        var addr: std.posix.sockaddr = undefined;
        const recv_bytes = try udp.recv(buf[0..], &addr);
        const info = blk: {
            const parsed = try std.json.parseFromSlice(models.MultiCastDto, allocator, buf[0..recv_bytes], .{});
            defer parsed.deinit();
            break :blk parsed.value;
        };
        const announce = info.announce orelse info.announcement orelse false;
        const gop = try peers.getOrPut(allocator, info.fingerprint);
        if (announce) {
            const peer = Peer.init(info, addr);
            gop.value_ptr.* = peer;
            const str = try std.json.stringifyAlloc(allocator, myself, .{});
            defer allocator.free(str);
            _ = try udp.send(str, &peer.addr);
            continue;
        }
        if (!gop.found_existing) {
            continue;
        }
        const peer = gop.value_ptr.*;
        if (announce) {
            continue;
        }

        const ip = try peer.getIP(allocator);
        defer allocator.free(ip);
        // const protocol = peer.info.protocol orelse "http";
        const protocol = "http";
        const port = peer.info.port orelse 53317;
        const url = try std.fmt.bufPrint(buf[recv_bytes..], "{s}://{s}:{d}/api/localsend/v2/prepare-upload", .{ protocol, ip, port });
        var files = std.StringHashMap(models.FilesDto).init(allocator);
        const path = try std.fs.realpathAlloc(allocator, "./src/main.zig");
        defer allocator.free(path);
        const hash = buf[0 .. Sha256.digest_length * 2];
        utils.hexSha256(path, hash);

        std.debug.print("DEBUGPRINT[435]: main.zig:71: hash={s}\n", .{hash});
        try files.put(hash, models.FilesDto{
            .id = hash, // ?????????????
            // .fileName = path, // TODO: error path traversal detected
            .fileName = "main.zig",
            .size = 1234,
            .fileType = "application/octet-stream",
            .sha256 = hash,
            .preview = null,
            .metadata = null,
        });
        const str = try std.json.stringifyAlloc(allocator, models.PrepareUploadRequestDto{ .info = myself, .files = files }, .{});
        defer allocator.free(str);
        _ = try udp.send(str, &peer.addr);

        var client = std.http.Client{ .allocator = allocator };
        const headers = &[_]std.http.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        var resp_body = std.ArrayList(u8).init(allocator);
        defer resp_body.deinit();
        const resp = try client.fetch(.{
            .method = .POST,
            .location = .{ .url = url },
            .extra_headers = headers, //put these here instead of .headers
            .payload = str,
            .response_storage = .{ .dynamic = &resp_body },
        });
        switch (resp.status) {
            .ok => {
                const r = try std.json.parseFromSlice(models.PrepareUploadResponseDto, allocator, resp_body.items, .{});
                std.debug.print("DEBUGPRINT[430]: main.zig:97: resp_body.items={s}\n", .{resp_body.items});
                defer r.deinit();
                const session_id = r.value.sessionId;
                var it = r.value.files.iterator();
                std.debug.print("DEBUGPRINT[431]: main.zig:106: session_id={s}\n", .{session_id});
                const ip0 = try peer.getIP(allocator);
                defer allocator.free(ip0);
                while (it.next()) |kv| {
                    const file_id = kv.key_ptr.*;
                    const token = kv.value_ptr.*;
                    // const filename = files.get(kv.key_ptr.*).?.fileName;
                    // std.debug.print("DEBUGPRINT[437]: main.zig:108: filename={s}\n", .{filename});
                    const url0 = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}/api/localsend/v2/upload?sessionId={s}&fileId={s}&token={s}", .{
                        protocol,
                        ip,
                        port,
                        session_id,
                        file_id,
                        token,
                    });

                    // TODO: error path traversal detected
                    const file = try std.fs.openFileAbsolute(path, .{});
                    defer file.close();
                    const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
                    std.debug.print("DEBUGPRINT[439]: main.zig:125: content={s}\n", .{content});
                    defer allocator.free(content);
                    const resp0 = try client.fetch(.{
                        .method = .POST,
                        .location = .{ .url = url0 },
                        .extra_headers = headers,
                        .payload = content,
                        .response_storage = .{ .dynamic = &resp_body },
                    });

                    std.debug.print("DEBUGPRINT[440]: main.zig:128: resp0={any}\n", .{resp0});

                    std.debug.print("DEBUGPRINT[438]: main.zig:127: resp0={s}\n", .{resp_body.items});
                }
                return;
            },
            else => {
                std.debug.print("DEBUGPRINT[375]: main.zig:82: resp={any}\n", .{resp});
                @panic("unexpected response status");
            },
        }
    }
}
