const std = @import("std");
const model = @import("./model.zig");
const utils = @import("./utils.zig");
const api = @import("./api.zig");

const log = std.log.scoped(.server);

/// Session for managing file uploads
const UploadSession = struct {
    id: []const u8,
    sender_info: model.MultiCastDto,
    files: std.StringHashMap(FileToken),
    created_at: i64,

    const FileToken = struct {
        file_info: model.FilesDto,
        token: []const u8,
    };

    pub fn deinit(self: *UploadSession, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        var it = self.files.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.token);
        }
        self.files.deinit();
    }
};

/// Session for managing file downloads (reverse mode)
const DownloadSession = struct {
    id: []const u8,
    files: std.StringHashMap(model.FilesDto),
    created_at: i64,
    pin: ?[]const u8,

    pub fn deinit(self: *DownloadSession, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        if (self.pin) |p| allocator.free(p);
        self.files.deinit();
    }
};

/// LocalSend HTTP/HTTPS server for receiving files
pub const Server = struct {
    allocator: std.mem.Allocator,
    address: std.net.Address,
    device_info: model.InfoDto,
    upload_sessions: std.StringHashMap(UploadSession),
    download_sessions: std.StringHashMap(DownloadSession),
    save_dir: []const u8,
    https_enabled: bool,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        device_info: model.InfoDto,
        save_dir: []const u8,
        https_enabled: bool,
    ) !Self {
        const address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);

        // Ensure save directory exists
        std.fs.cwd().makePath(save_dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        return .{
            .allocator = allocator,
            .address = address,
            .device_info = device_info,
            .upload_sessions = std.StringHashMap(UploadSession).init(allocator),
            .download_sessions = std.StringHashMap(DownloadSession).init(allocator),
            .save_dir = save_dir,
            .https_enabled = https_enabled,
        };
    }

    pub fn deinit(self: *Self) void {
        var upload_it = self.upload_sessions.valueIterator();
        while (upload_it.next()) |session| {
            session.deinit(self.allocator);
        }
        self.upload_sessions.deinit();

        var download_it = self.download_sessions.valueIterator();
        while (download_it.next()) |session| {
            session.deinit(self.allocator);
        }
        self.download_sessions.deinit();
    }

    /// Start listening for connections
    pub fn listen(self: *Self) !void {
        var net_server = try self.address.listen(.{
            .reuse_address = true,
            .kernel_backlog = 128,
        });
        defer net_server.deinit();

        log.info("Server listening on {any} (HTTPS: {})", .{ self.address, self.https_enabled });

        while (true) {
            const connection = net_server.accept() catch |err| {
                log.err("Error accepting connection: {}", .{err});
                continue;
            };

            self.handleConnection(connection) catch |err| {
                log.err("Error handling connection: {}", .{err});
            };
        }
    }

    fn handleConnection(self: *Self, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        var read_buffer: [8192]u8 = undefined;
        var write_buffer: [8192]u8 = undefined;

        var reader = connection.stream.reader(&read_buffer);
        var writer = connection.stream.writer(&write_buffer);

        var server = std.http.Server.init(reader.interface(), &writer.interface);

        // Handle single request per connection (HTTP/1.0 style)
        // This is simpler and works reliably with the current API
        var request = server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => {
                log.err("Error receiving HTTP head: {}", .{err});
                return err;
            },
        };

        self.handleRequest(&request) catch |err| {
            log.err("Error handling request: {}", .{err});
            // Try to send error response
            self.sendResponse(&request, .internal_server_error, "text/plain", "Internal Server Error") catch {};
        };
    }

    fn handleRequest(self: *Self, request: *std.http.Server.Request) !void {
        const target = request.head.target;
        const method = request.head.method;

        log.info("{s} {s}", .{ @tagName(method), target });

        const route = api.ApiRoute.match(target) orelse {
            return self.sendResponse(request, .not_found, "text/plain", "Not Found");
        };

        switch (route) {
            .info => try self.handleInfo(request),
            .register => try self.handleRegister(request),
            .prepare_upload => try self.handlePrepareUpload(request),
            .upload => try self.handleUpload(request),
            .cancel => try self.handleCancel(request),
            .prepare_download => try self.handlePrepareDownload(request),
            .download => try self.handleDownload(request),
        }
    }

    fn handleInfo(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .GET) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        const json = try std.json.Stringify.valueAlloc(self.allocator, self.device_info, .{});
        defer self.allocator.free(json);

        try self.sendResponse(req, .ok, "application/json", json);
    }

    fn handleRegister(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .POST) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        // Get content length from headers
        const content_length = req.head.content_length orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing Content-Length");
        };

        // Read exact amount of body data
        var body_buf: [8192]u8 = undefined;
        if (content_length > body_buf.len) {
            return self.sendResponse(req, .bad_request, "text/plain", "Request too large");
        }

        const reader = req.readerExpectNone(&body_buf);
        const body_data = body_buf[0..content_length];
        try reader.readSliceAll(body_data);

        const parsed = std.json.parseFromSlice(
            model.MultiCastDto,
            self.allocator,
            body_data,
            .{ .ignore_unknown_fields = true },
        ) catch {
            return self.sendResponse(req, .bad_request, "text/plain", "Invalid JSON");
        };
        defer parsed.deinit();

        log.info("Device registered: {s} ({s})", .{ parsed.value.alias, parsed.value.deviceType orelse "unknown" });

        const json = try std.json.Stringify.valueAlloc(self.allocator, self.device_info, .{});
        defer self.allocator.free(json);

        try self.sendResponse(req, .ok, "application/json", json);
    }

    fn handlePrepareUpload(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .POST) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        // Get content length
        const content_length = req.head.content_length orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing Content-Length");
        };

        // Read body with proper buffer size
        const body = try self.allocator.alloc(u8, content_length);
        defer self.allocator.free(body);

        var body_buf: [8192]u8 = undefined;
        const reader = req.readerExpectNone(&body_buf);
        try reader.readSliceAll(body);

        // Parse JSON manually due to StringHashMap complexity in Zig 0.15
        const parsed_value = try std.json.parseFromSlice(std.json.Value, self.allocator, body, .{});
        defer parsed_value.deinit();

        const root = parsed_value.value.object;
        const info_obj = root.get("info").?.object;
        const files_obj = root.get("files").?.object;

        // Extract sender info
        const sender_info = model.MultiCastDto{
            .alias = info_obj.get("alias").?.string,
            .version = if (info_obj.get("version")) |v| v.string else null,
            .deviceModel = if (info_obj.get("deviceModel")) |v| v.string else null,
            .deviceType = if (info_obj.get("deviceType")) |v| v.string else null,
            .fingerprint = info_obj.get("fingerprint").?.string,
            .port = if (info_obj.get("port")) |v| @intCast(v.integer) else null,
            .protocol = if (info_obj.get("protocol")) |v| v.string else null,
            .download = if (info_obj.get("download")) |v| v.bool else null,
            .announce = if (info_obj.get("announce")) |v| v.bool else null,
            .announcement = if (info_obj.get("announcement")) |v| v.bool else null,
        };

        log.info("Prepare upload from {s}: {} file(s)", .{ sender_info.alias, files_obj.count() });

        // Generate session ID
        const session_id = try utils.generateId(self.allocator);
        errdefer self.allocator.free(session_id);

        // Create file tokens
        var file_tokens = std.StringHashMap(UploadSession.FileToken).init(self.allocator);
        errdefer {
            var it = file_tokens.valueIterator();
            while (it.next()) |ft| self.allocator.free(ft.token);
            file_tokens.deinit();
        }

        var files_it = files_obj.iterator();
        while (files_it.next()) |entry| {
            const file_obj = entry.value_ptr.object;
            const file_info = model.FilesDto{
                .id = entry.key_ptr.*,
                .fileName = file_obj.get("fileName").?.string,
                .size = @intCast(file_obj.get("size").?.integer),
                .fileType = file_obj.get("fileType").?.string,
                .sha256 = if (file_obj.get("sha256")) |v| v.string else null,
                .preview = if (file_obj.get("preview")) |v| v.string else null,
                .metadata = null,
            };

            const token = try utils.generateId(self.allocator);
            try file_tokens.put(entry.key_ptr.*, .{
                .file_info = file_info,
                .token = token,
            });
        }

        // Store session
        const session = UploadSession{
            .id = session_id,
            .sender_info = sender_info,
            .files = file_tokens,
            .created_at = std.time.timestamp(),
        };
        try self.upload_sessions.put(session_id, session);

        // Build response
        var response_buf: std.ArrayList(u8) = .empty;
        defer response_buf.deinit(self.allocator);
        const writer = response_buf.writer(self.allocator);

        try writer.writeAll("{\"sessionId\":\"");
        try writer.writeAll(session_id);
        try writer.writeAll("\",\"files\":{");

        var first = true;
        var session_files_it = file_tokens.iterator();
        while (session_files_it.next()) |entry| {
            if (!first) try writer.writeByte(',');
            try writer.writeByte('"');
            try writer.writeAll(entry.key_ptr.*);
            try writer.writeAll("\":\"");
            try writer.writeAll(entry.value_ptr.token);
            try writer.writeByte('"');
            first = false;
        }
        try writer.writeAll("}}");

        try self.sendResponse(req, .ok, "application/json", response_buf.items);
    }

    fn handleUpload(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .POST) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        var query = try api.QueryParams.fromTarget(self.allocator, req.head.target);
        defer query.deinit();

        const session_id = query.get("sessionId") orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing sessionId");
        };
        const file_id = query.get("fileId") orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing fileId");
        };
        const token = query.get("token") orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing token");
        };

        // Validate session
        const session = self.upload_sessions.get(session_id) orelse {
            return self.sendResponse(req, .forbidden, "text/plain", "Invalid session");
        };

        const file_token = session.files.get(file_id) orelse {
            return self.sendResponse(req, .forbidden, "text/plain", "Invalid fileId");
        };

        if (!std.mem.eql(u8, file_token.token, token)) {
            return self.sendResponse(req, .forbidden, "text/plain", "Invalid token");
        }

        // Get content length
        const content_length = req.head.content_length orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing Content-Length");
        };

        // Read file data
        const file_data = try self.allocator.alloc(u8, content_length);
        defer self.allocator.free(file_data);

        var buf: [8192]u8 = undefined;
        const reader = req.readerExpectNone(&buf);
        try reader.readSliceAll(file_data);

        // Save file
        const filename = try std.fs.path.join(self.allocator, &.{ self.save_dir, file_token.file_info.fileName });
        defer self.allocator.free(filename);

        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();
        try file.writeAll(file_data);

        log.info("File saved: {s} ({d} bytes)", .{ filename, file_data.len });

        try self.sendResponse(req, .ok, "text/plain", "");
    }

    fn handleCancel(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .POST) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        var query = try api.QueryParams.fromTarget(self.allocator, req.head.target);
        defer query.deinit();

        const session_id = query.get("sessionId") orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing sessionId");
        };

        if (self.upload_sessions.fetchRemove(session_id)) |kv| {
            var session = kv.value;
            session.deinit(self.allocator);
            log.info("Session cancelled: {s}", .{session_id});
        }

        try self.sendResponse(req, .ok, "text/plain", "");
    }

    fn handlePrepareDownload(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .POST) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        var query = try api.QueryParams.fromTarget(self.allocator, req.head.target);
        defer query.deinit();

        // Check for existing session ID (page refresh scenario)
        const existing_session_id = query.get("sessionId");
        const pin = query.get("pin");

        // Validate PIN if required
        if (self.device_info.download) |has_download| {
            if (has_download and pin == null) {
                return self.sendResponse(req, .unauthorized, "text/plain", "PIN required");
            }
        }

        // Generate or reuse session ID
        const session_id = if (existing_session_id) |sid|
            try self.allocator.dupe(u8, sid)
        else
            try utils.generateId(self.allocator);
        errdefer self.allocator.free(session_id);

        // Create response with device info and empty file list
        // In a real implementation, you would populate this with actual files to download
        var files = std.StringHashMap(model.FilesDto).init(self.allocator);
        defer files.deinit();

        const response = model.PrepareDownloadResponseDto{
            .info = self.device_info,
            .sessionId = session_id,
            .files = files,
        };

        const json = try std.json.Stringify.valueAlloc(self.allocator, response, .{});
        defer self.allocator.free(json);

        try self.sendResponse(req, .ok, "application/json", json);
    }

    fn handleDownload(self: *Self, req: *std.http.Server.Request) !void {
        if (req.head.method != .GET) {
            return self.sendResponse(req, .method_not_allowed, "text/plain", "Method Not Allowed");
        }

        var query = try api.QueryParams.fromTarget(self.allocator, req.head.target);
        defer query.deinit();

        const session_id = query.get("sessionId") orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing sessionId");
        };
        const file_id = query.get("fileId") orelse {
            return self.sendResponse(req, .bad_request, "text/plain", "Missing fileId");
        };

        // Validate session
        const session = self.download_sessions.get(session_id) orelse {
            return self.sendResponse(req, .forbidden, "text/plain", "Invalid session");
        };

        const file_info = session.files.get(file_id) orelse {
            return self.sendResponse(req, .forbidden, "text/plain", "Invalid fileId");
        };

        // Read and send file
        const filename = try std.fs.path.join(self.allocator, &.{ self.save_dir, file_info.fileName });
        defer self.allocator.free(filename);

        const file = std.fs.cwd().openFile(filename, .{}) catch {
            return self.sendResponse(req, .not_found, "text/plain", "File not found");
        };
        defer file.close();

        const file_data = try file.readToEndAlloc(self.allocator, 100 * 1024 * 1024);
        defer self.allocator.free(file_data);

        log.info("File sent: {s} ({d} bytes)", .{ filename, file_data.len });

        try self.sendResponse(req, .ok, "application/octet-stream", file_data);
    }

    fn sendResponse(self: *Self, req: *std.http.Server.Request, status: std.http.Status, content_type: []const u8, body: []const u8) !void {
        _ = self;
        try req.respond(body, .{
            .status = status,
            .extra_headers = &.{
                .{ .name = "content-type", .value = content_type },
            },
        });
    }
};

test "server imports" {
    _ = @import("server.zig");
}
