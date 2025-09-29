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
        var p: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr0));
        p.port = std.mem.nativeToBig(u16, info.port orelse 53317);
        return .{ .info = info, .addr = addr0 };
    }
    pub fn getIP(self: *const Self, allo: std.mem.Allocator) ![]const u8 {
        const p = @as(*std.posix.sockaddr.in, @ptrCast(@alignCast(@constCast(&self.addr))));
        const bytes = @as(*const [4]u8, @ptrCast(&p.addr));
        return try std.fmt.allocPrint(allo, "{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
    }
};

fn sendHttpRequest(
    client: *std.http.Client,
    url: []const u8,
    method: std.http.Method,
    headers: []const std.http.Header,
    payload: []const u8,
    body: *std.Io.Writer.Allocating,
) !struct {
    resp: std.http.Client.FetchResult,
    resp_body: []const u8,
} {
    std.debug.print("DEBUGPRINT[http]: Sending {s} request to {s} (payload size: {d})\n", .{ @tagName(method), url, payload.len });
    try body.ensureUnusedCapacity(64);
    const resp = try client.fetch(.{
        .method = method,
        .location = .{ .url = url },
        .extra_headers = headers,
        .payload = payload,
        .response_writer = &body.writer,
    });
    const resp_body = body.toArrayList().items;
    std.debug.print("DEBUGPRINT[http]: Response status={any}, body={s}\n", .{ resp.status, resp_body });
    return .{ .resp = resp, .resp_body = resp_body };
}

pub fn main() !void {
    std.debug.print("DEBUGPRINT[main]: Program started\n", .{});
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <file-to-send>\n", .{args[0]});
        std.debug.print("No file specified. Exiting.\n", .{});
        return;
    }
    const file_path = args[1];
    std.debug.print("DEBUGPRINT[main]: file_path={s}\n", .{file_path});

    const myself: models.MultiCastDto = utils.makeAnnouncement();
    std.debug.print("DEBUGPRINT[main]: Announcement created\n", .{});
    var peers: std.StringHashMapUnmanaged(Peer) = .empty;
    defer peers.deinit(allocator);
    const udp = try UDP.init("224.0.0.167", 53317);
    defer udp.close();
    std.debug.print("DEBUGPRINT[main]: UDP initialized\n", .{});

    while (true) {
        std.debug.print("DEBUGPRINT[main]: Waiting for UDP packet...\n", .{});
        var addr: std.posix.sockaddr = undefined;
        const recv_bytes = try udp.recv(buf[0..], &addr);
        std.debug.print("DEBUGPRINT[main]: Received {d} bytes from UDP\n", .{recv_bytes});
        const info = blk: {
            const parsed = try std.json.parseFromSlice(models.MultiCastDto, allocator, buf[0..recv_bytes], .{});
            defer parsed.deinit();
            std.debug.print("DEBUGPRINT[main]: Parsed MultiCastDto\n", .{});
            break :blk parsed.value;
        };
        const announce = info.announce orelse info.announcement orelse false;
        std.debug.print("DEBUGPRINT[main]: announce={any}\n", .{announce});
        const gop = try peers.getOrPut(allocator, info.fingerprint);
        if (announce) {
            std.debug.print("DEBUGPRINT[main]: Handling announce\n", .{});
            const peer = Peer.init(info, addr);
            gop.value_ptr.* = peer;
            const str = try std.json.Stringify.valueAlloc(allocator, myself, .{});
            defer allocator.free(str);
            _ = try udp.send(str, &peer.addr);
            continue;
        }
        if (!gop.found_existing) {
            std.debug.print("DEBUGPRINT[main]: Peer not found in map, skipping\n", .{});
            continue;
        }
        const peer = gop.value_ptr.*;
        if (announce) {
            std.debug.print("DEBUGPRINT[main]: Announce is true, skipping\n", .{});
            continue;
        }

        const ip = try peer.getIP(allocator);
        defer allocator.free(ip);
        std.debug.print("DEBUGPRINT[main]: Peer IP: {s}\n", .{ip});
        // const protocol = peer.info.protocol orelse "http";
        const protocol = "http";
        const port = peer.info.port orelse 53317;
        const url = try std.fmt.bufPrint(buf[recv_bytes..], "{s}://{s}:{d}/api/localsend/v2/prepare-upload", .{ protocol, ip, port });
        std.debug.print("DEBUGPRINT[main]: Prepare-upload URL: {s}\n", .{url});
        var files = std.StringHashMap(models.FilesDto).init(allocator);

        const path = try std.fs.realpathAlloc(allocator, file_path);
        defer allocator.free(path);
        std.debug.print("DEBUGPRINT[main]: Real path: {s}\n", .{path});
        const stat = try std.fs.cwd().statFile(file_path);
        std.debug.print("DEBUGPRINT[main]: File size: {d}\n", .{stat.size});
        const file_name = std.fs.path.basename(file_path);
        std.debug.print("DEBUGPRINT[main]: File name: {s}\n", .{file_name});

        const hash = buf[0 .. Sha256.digest_length * 2];
        utils.hexSha256(path, hash);
        std.debug.print("DEBUGPRINT[main]: File hash: {s}\n", .{hash});
        try files.put(hash, models.FilesDto{
            .id = hash,
            .fileName = file_name,
            .size = stat.size,
            .fileType = "application/octet-stream",
            .sha256 = hash,
            .preview = null,
            .metadata = null,
        });
        const str = try std.json.Stringify.valueAlloc(allocator, models.PrepareUploadRequestDto{ .info = myself, .files = files }, .{});
        defer allocator.free(str);
        std.debug.print("DEBUGPRINT[main]: Sending prepare-upload UDP\n", .{});
        _ = try udp.send(str, &peer.addr);

        var client = std.http.Client{ .allocator = allocator };
        const headers = &[_]std.http.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        var body: std.Io.Writer.Allocating = .init(allocator);
        defer body.deinit();
        try body.ensureUnusedCapacity(64);
        std.debug.print("DEBUGPRINT[main]: Sending HTTP prepare-upload\n", .{});
        const result = try sendHttpRequest(&client, url, .POST, headers, str, &body);
        switch (result.resp.status) {
            .ok => {
                std.debug.print("DEBUGPRINT[main]: HTTP prepare-upload OK\n", .{});
                const r = try std.json.parseFromSlice(models.PrepareUploadResponseDto, allocator, result.resp_body, .{});
                defer r.deinit();
                const session_id = r.value.sessionId;
                std.debug.print("DEBUGPRINT[main]: session_id={s}\n", .{session_id});
                var it = r.value.files.iterator();
                const ip0 = try peer.getIP(allocator);
                defer allocator.free(ip0);

                while (it.next()) |kv| {
                    const file_id = kv.key_ptr.*;
                    const token = kv.value_ptr.*;
                    std.debug.print("DEBUGPRINT[main]: file_id={s}, token={s}\n", .{ file_id, token });
                    const url0 = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}/api/localsend/v2/upload?sessionId={s}&fileId={s}&token={s}", .{
                        protocol,
                        ip,
                        port,
                        session_id,
                        file_id,
                        token,
                    });
                    std.debug.print("DEBUGPRINT[main]: Upload URL: {s}\n", .{url0});

                    std.debug.print("DEBUGPRINT[main]: Opening file for upload: {s}\n", .{path});
                    const file = try std.fs.openFileAbsolute(path, .{});
                    defer file.close();
                    const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
                    std.debug.print("DEBUGPRINT[main]: Read file content, size={d}\n", .{content.len});
                    defer allocator.free(content);
                    std.debug.print("DEBUGPRINT[main]: Sending HTTP upload\n", .{});
                    const upload_result = try sendHttpRequest(&client, url0, .POST, headers, content, &body);
                    std.debug.print("DEBUGPRINT[main]: HTTP upload status={any}, body={s}\n", .{ upload_result.resp.status, upload_result.resp_body });
                }
                std.debug.print("DEBUGPRINT[main]: Upload finished, exiting\n", .{});
                return;
            },
            else => {
                std.debug.print("DEBUGPRINT[main]: HTTP prepare-upload error, status={any}, body={s}\n", .{ result.resp.status, result.resp_body });
                @panic("unexpected response status");
            },
        }
    }
}
