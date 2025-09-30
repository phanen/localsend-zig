const std = @import("std");
const utils = @import("./utils.zig");
const Cons = @import("./main.zig").Cons;

// https://github.com/localsend/localsend/blob/f5e8a5652c3e313730341b386a3ac2dc33abc318/common/lib/model/dto/multicast_dto.dart#L11
pub const MultiCastDto = struct {
    alias: []const u8,
    version: ?[]const u8 = "2.1", // v2, format: major.minor
    deviceModel: ?[]const u8 = null,
    deviceType: ?[]const u8 = "headless", // nullable since v2
    fingerprint: []const u8,
    port: ?u16 = Cons.PORT, // v2
    protocol: ?[]const u8 = Cons.PROTOCOL, // v2
    download: ?bool = false, // v2
    announce: ?bool = false, // v2
    announcement: ?bool = false, // v1
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        const alias = try std.fmt.allocPrint(allocator, "{s}_{d}", .{
            std.posix.getenv("USER") orelse "zig",
            std.time.timestamp() & 0xffff,
        });
        var buf: [64]u8 = undefined;
        std.crypto.random.bytes(buf[0 .. buf.len / 2]);
        const hex = std.fmt.bytesToHex(buf[0 .. buf.len / 2], .upper);
        const fingerprint = try allocator.dupe(u8, &hex);
        return .{
            .alias = alias,
            .version = "2.1",
            .deviceModel = "Linux",
            .deviceType = "headless",
            .fingerprint = fingerprint,
            .port = Cons.PORT,
            .protocol = Cons.PROTOCOL,
            .download = false,
            .announce = true,
            .announcement = true,
        };
    }
    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        allocator.free(self.alias);
        allocator.free(self.fingerprint);
    }
};

pub const FileMetadata = struct {
    modified: ?[]const u8 = null, // "2021-01-01T12:34:56Z"
    accessed: ?[]const u8 = null, // "2021-01-01T12:34:56Z"
};

pub const FilesDto = struct {
    id: []const u8,
    fileName: []const u8,
    size: u64,
    fileType: []const u8,
    sha256: ?[]const u8 = null,
    preview: ?[]const u8 = null,
    metadata: ?FileMetadata = null,
    // non-protocol field, just a helper to remember the actual path..
    // actual path is required (stored it in model for convenient)
    path: ?[]const u8 = null,

    const Self = @This();

    /// path must be normalized
    pub fn init(path: []const u8, hash: []const u8) !Self {
        const name = std.fs.path.basename(path);
        const stat = try std.fs.cwd().statFile(path);
        return .{
            .id = hash,
            .fileName = name,
            .size = stat.size,
            .fileType = utils.getMimeType(name),
            .sha256 = hash,
            .preview = null,
            .metadata = null,
            .path = path,
        };
    }
};

// https://github.com/localsend/localsend/blob/f5e8a5652c3e313730341b386a3ac2dc33abc318/common/lib/model/dto/prepare_upload_request_dto.dart#L8
pub const PrepareUploadRequestDto = struct {
    info: MultiCastDto,
    files: std.StringHashMap(FilesDto),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, info: MultiCastDto, paths: []const []const u8) !Self {
        var files = std.StringHashMap(FilesDto).init(allocator);
        for (paths) |path| {
            const hash = try utils.sha256File(allocator, path);
            const file = try FilesDto.init(path, hash);
            // TODO: currently, just use hash as file_id
            try files.put(hash, file);
        }
        return .{
            .info = info,
            .files = files,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        var it = self.files.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.files.deinit();
    }

    // https://ziggit.dev/t/how-to-stringify-complex-struct/6511/3
    pub fn jsonStringify(self: Self, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("info");
        try jws.write(self.info);
        try jws.objectField("files");
        {
            try jws.beginObject();
            var it = self.files.iterator();
            while (it.next()) |kv| {
                try jws.objectField(kv.key_ptr.*);
                try jws.write(kv.value_ptr.*);
            }
            try jws.endObject();
        }
        try jws.endObject();
    }
};

pub const PrepareUploadResponseDto = struct {
    sessionId: []const u8,
    files: std.StringHashMapUnmanaged([]const u8),

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.files.deinit(allocator);
    }

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!Self {
        var files: std.StringHashMapUnmanaged([]const u8) = .empty;
        errdefer files.deinit(allocator);

        if (.object_begin != try source.next()) return error.UnexpectedToken;
        var session_id: ?[]const u8 = null;

        while (true) {
            switch (try source.nextAlloc(allocator, options.allocate.?)) {
                inline .string, .allocated_string => |k| {
                    if (std.mem.eql(u8, k, "sessionId")) {
                        session_id = switch (try source.nextAlloc(allocator, options.allocate.?)) {
                            inline .string, .allocated_string => |slice| slice,
                            else => return error.UnexpectedToken,
                        };
                    } else if (std.mem.eql(u8, k, "files")) {
                        if (.object_begin != try source.next()) return error.UnexpectedToken;
                        while (true) {
                            switch (try source.nextAlloc(allocator, options.allocate.?)) {
                                inline .string, .allocated_string => |file_key| {
                                    const gop = try files.getOrPut(allocator, file_key);
                                    if (gop.found_existing) {
                                        switch (options.duplicate_field_behavior) {
                                            .use_first => {
                                                // Parse and ignore the redundant value.
                                                _ = try source.nextAlloc(allocator, options.allocate.?);
                                                continue;
                                            },
                                            .@"error" => return error.DuplicateField,
                                            .use_last => {},
                                        }
                                    }
                                    gop.value_ptr.* = switch (try source.nextAlloc(allocator, options.allocate.?)) {
                                        .string, .allocated_string => |v| v,
                                        else => return error.UnexpectedToken,
                                    };
                                },
                                .object_end => break,
                                else => return error.UnexpectedToken,
                            }
                        }
                    } else {
                        // Skip unknown fields
                        _ = try source.nextAlloc(allocator, options.allocate.?);
                    }
                },
                .object_end => break,
                else => return error.UnexpectedToken,
            }
        }

        return .{
            .sessionId = session_id orelse return error.MissingField,
            .files = files,
        };
    }
};

/// Device info response structure
pub const InfoDto = struct {
    alias: []const u8,
    version: []const u8,
    deviceModel: ?[]const u8 = null,
    deviceType: ?[]const u8 = "headless",
    fingerprint: []const u8,
    download: ?bool = false,
};

/// Response for prepare-download endpoint (section 5.2 of protocol)
pub const PrepareDownloadResponseDto = struct {
    info: InfoDto,
    sessionId: []const u8,
    files: std.StringHashMap(FilesDto),

    const Self = @This();

    pub fn jsonStringify(self: Self, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("info");
        try jws.write(self.info);
        try jws.objectField("sessionId");
        try jws.write(self.sessionId);
        try jws.objectField("files");
        {
            try jws.beginObject();
            var it = self.files.iterator();
            while (it.next()) |kv| {
                try jws.objectField(kv.key_ptr.*);
                try jws.write(kv.value_ptr.*);
            }
            try jws.endObject();
        }
        try jws.endObject();
    }
};
