const std = @import("std");
const UDP = @import("./udp.zig");
const models = @import("./models.zig");
const utils = @import("./utils.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

// Set up custom log handler and log level
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logFn,
};

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime @intFromEnum(level) > @intFromEnum(std.options.log_level)) {
        return;
    }

    const prefix1 = comptime level.asText();
    const prefix2 = comptime if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    // Print the message to stderr, silently ignoring any errors
    std.debug.print(prefix1 ++ prefix2 ++ format ++ "\n", args);
}

const log = std.log.scoped(.main);

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
    log.info("HTTP {s} {s} (payload size: {d})", .{ @tagName(method), url, payload.len });
    try body.ensureUnusedCapacity(64);
    const resp = try client.fetch(.{
        .method = method,
        .location = .{ .url = url },
        .extra_headers = headers,
        .payload = payload,
        .response_writer = &body.writer,
    });
    const resp_body = body.toArrayList().items;
    log.info("HTTP response status={any}, body={s}", .{ resp.status, resp_body });
    return .{ .resp = resp, .resp_body = resp_body };
}

pub fn main() !void {
    log.info("Program started", .{});
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        log.warn("Usage: {s} <file-to-send>", .{args[0]});
        log.warn("No file specified. Exiting.", .{});
        return;
    }
    const file_path = args[1];
    log.info("file_path={s}", .{file_path});

    const myself: models.MultiCastDto = utils.makeAnnouncement();
    log.info("Announcement created", .{});
    var peers: std.StringHashMapUnmanaged(Peer) = .empty;
    defer peers.deinit(allocator);
    const udp = try UDP.init("224.0.0.167", 53317);
    defer udp.close();
    log.info("UDP initialized", .{});

    while (true) {
        log.info("Waiting for UDP packet...", .{});
        var addr: std.posix.sockaddr = undefined;
        const recv_bytes = try udp.recv(buf[0..], &addr);
        log.info("Received {d} bytes from UDP", .{recv_bytes});
        const info = blk: {
            const parsed = try std.json.parseFromSlice(models.MultiCastDto, allocator, buf[0..recv_bytes], .{});
            defer parsed.deinit();
            log.info("Parsed MultiCastDto", .{});
            break :blk parsed.value;
        };
        const announce = info.announce orelse info.announcement orelse false;
        log.info("announce={any}", .{announce});
        const gop = try peers.getOrPut(allocator, info.fingerprint);
        if (announce) {
            log.info("Handling announce", .{});
            const peer = Peer.init(info, addr);
            gop.value_ptr.* = peer;
            const str = try std.json.Stringify.valueAlloc(allocator, myself, .{});
            defer allocator.free(str);
            _ = try udp.send(str, &peer.addr);
            continue;
        }
        if (!gop.found_existing) {
            log.info("Peer not found in map, skipping", .{});
            continue;
        }
        const peer = gop.value_ptr.*;
        if (announce) {
            log.info("Announce is true, skipping", .{});
            continue;
        }

        const ip = try peer.getIP(allocator);
        defer allocator.free(ip);
        log.info("Peer IP: {s}", .{ip});
        // const protocol = peer.info.protocol orelse "http";
        const protocol = "http";
        const port = peer.info.port orelse 53317;
        const url = try std.fmt.bufPrint(buf[recv_bytes..], "{s}://{s}:{d}/api/localsend/v2/prepare-upload", .{ protocol, ip, port });
        log.info("Prepare-upload URL: {s}", .{url});
        var files = std.StringHashMap(models.FilesDto).init(allocator);

        const path = try std.fs.realpathAlloc(allocator, file_path);
        defer allocator.free(path);
        log.info("Real path: {s}", .{path});
        const stat = try std.fs.cwd().statFile(file_path);
        log.info("File size: {d}", .{stat.size});
        const file_name = std.fs.path.basename(file_path);
        log.info("File name: {s}", .{file_name});

        const hash = buf[0 .. Sha256.digest_length * 2];
        utils.hexSha256(path, hash);
        log.info("File hash: {s}", .{hash});
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
        log.info("Sending prepare-upload UDP", .{});
        _ = try udp.send(str, &peer.addr);

        var client = std.http.Client{ .allocator = allocator };
        const headers = &[_]std.http.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };
        var body: std.Io.Writer.Allocating = .init(allocator);
        defer body.deinit();
        try body.ensureUnusedCapacity(64);
        log.info("Sending HTTP prepare-upload", .{});
        const result = try sendHttpRequest(&client, url, .POST, headers, str, &body);
        switch (result.resp.status) {
            .ok => {
                log.info("HTTP prepare-upload OK", .{});
                const r = try std.json.parseFromSlice(models.PrepareUploadResponseDto, allocator, result.resp_body, .{});
                defer r.deinit();
                const session_id = r.value.sessionId;
                log.info("session_id={s}", .{session_id});
                var it = r.value.files.iterator();
                const ip0 = try peer.getIP(allocator);
                defer allocator.free(ip0);

                while (it.next()) |kv| {
                    const file_id = kv.key_ptr.*;
                    const token = kv.value_ptr.*;
                    log.info("file_id={s}, token={s}", .{ file_id, token });
                    const url0 = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}/api/localsend/v2/upload?sessionId={s}&fileId={s}&token={s}", .{
                        protocol,
                        ip,
                        port,
                        session_id,
                        file_id,
                        token,
                    });
                    log.info("Upload URL: {s}", .{url0});

                    log.info("Opening file for upload: {s}", .{path});
                    const file = try std.fs.openFileAbsolute(path, .{});
                    defer file.close();
                    const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
                    log.info("Read file content, size={d}", .{content.len});
                    defer allocator.free(content);
                    log.info("Sending HTTP upload", .{});
                    const upload_result = try sendHttpRequest(&client, url0, .POST, headers, content, &body);
                    log.info("HTTP upload status={any}, body={s}", .{ upload_result.resp.status, upload_result.resp_body });
                }
                log.info("Upload finished, exiting", .{});
                return;
            },
            else => {
                log.err("HTTP prepare-upload error, status={any}, body={s}", .{ result.resp.status, result.resp_body });
                @panic("unexpected response status");
            },
        }
    }
}
