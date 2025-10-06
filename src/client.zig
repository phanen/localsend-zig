const std = @import("std");
const http = std.http;
const model = @import("./model.zig");
const api = @import("./api.zig");

const log = std.log.scoped(.client);

/// HTTP client for sending files to peers
pub const Client = struct {
    allocator: std.mem.Allocator,
    http_client: http.Client,
    info: model.MultiCastDto,

    var alias_buf: [64]u8 = undefined;
    var fingerprint: [64]u8 = undefined;

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return .{
            .allocator = allocator,
            .http_client = .{ .allocator = allocator },
            .info = try .init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.http_client.deinit();
        self.info.deinit(self.allocator);
    }

    pub fn sendFiles(
        self: *Self,
        addr: *const std.net.Address,
        paths: []const []const u8,
        https: bool,
    ) !void {
        log.info("Sending file to {f}", .{addr});
        const url = try api.ApiRoute.prepare_upload.url(self.allocator, addr, https);
        defer self.allocator.free(url);
        log.info("Prepare upload URL: {s}", .{url});

        var prep = try model.PrepareUploadRequestDto.init(self.allocator, self.info, paths);
        defer prep.deinit(self.allocator);

        const payload = try std.json.Stringify.valueAlloc(self.allocator, prep, .{});
        defer self.allocator.free(payload);

        const resp = try self.sendHttpRequest(.POST, url, payload);
        defer resp.deinit();
        switch (resp.status) {
            .ok => log.info("Prepare upload successful.", .{}),
            // .forbidden => {
            //     log.info("File request declined by recipient", .{});
            //     return;
            // },
            else => {
                log.err("Prepare upload failed: {}", .{resp.status});
                // return error.PrepareUploadFailed;
                return;
            },
        }
        const parsed = try std.json.parseFromSlice(model.PrepareUploadResponseDto, self.allocator, resp.body, .{});
        defer parsed.deinit();

        const session_id = parsed.value.sessionId;
        log.info("Upload session created: {s}", .{session_id});

        // upload each file
        var it = parsed.value.files.iterator();
        while (it.next()) |entry| {
            const file_id = entry.key_ptr.*;
            const token = entry.value_ptr.*;
            const file_info = prep.files.get(file_id) orelse continue;
            const path = file_info.path.?;
            try self.uploadFile(addr, https, session_id, file_id, token, path);
        }

        log.info("All files uploaded successfully", .{});
    }

    fn uploadFile(
        self: *Self,
        addr: *const std.net.Address,
        use_https: bool,
        session_id: []const u8,
        file_id: []const u8,
        token: []const u8,
        path: []const u8,
    ) !void {
        log.info("Uploading {s} ({s})", .{ path, file_id });
        const url = try api.ApiRoute.upload.urlWithQuery(
            self.allocator,
            addr,
            use_https,
            &.{
                .{ "sessionId", session_id },
                .{ "fileId", file_id },
                .{ "token", token },
            },
        );
        defer self.allocator.free(url);
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, std.math.maxInt(usize));
        defer self.allocator.free(content);
        const resp = try self.sendHttpRequest(.POST, url, content);
        defer resp.deinit();

        if (resp.status != .ok) {
            log.err("Upload failed for {s}: {}", .{ path, resp.status });
            return error.UploadFailed;
        }

        log.info("File uploaded: {s} ({d} bytes)", .{ path, content.len });
    }

    fn sendHttpRequest(
        self: *Self,
        method: http.Method,
        url: []const u8,
        payload: []const u8,
    ) !HttpResponse {
        var buffer: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buffer.deinit();
        try buffer.ensureUnusedCapacity(64);
        log.info("HTTP {s} {s} ({d} bytes)", .{ @tagName(method), url, payload.len });
        const resp = try self.http_client.fetch(.{
            .method = method,
            .location = .{ .url = url },
            .extra_headers = &[_]http.Header{.{ .name = "content-type", .value = "application/json" }},
            .payload = payload,
            .response_writer = &buffer.writer,
        });
        const resp_body = try buffer.toOwnedSlice();
        log.info("HTTP response status={}, body={s}", .{ resp.status, resp_body });
        return HttpResponse.init(self.allocator, resp.status, resp_body);
    }
};

/// HTTP response with owned body memory
const HttpResponse = struct {
    allocator: std.mem.Allocator,
    status: http.Status,
    body: []const u8,

    const Self = @This();
    pub fn init(allocator: std.mem.Allocator, status: http.Status, body: []const u8) Self {
        return .{ .allocator = allocator, .status = status, .body = body };
    }

    pub fn deinit(self: *const Self) void {
        self.allocator.free(self.body);
    }
};
