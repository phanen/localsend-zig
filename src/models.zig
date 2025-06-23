const std = @import("std");

// https://github.com/localsend/localsend/blob/f5e8a5652c3e313730341b386a3ac2dc33abc318/common/lib/model/dto/multicast_dto.dart#L11
pub const MultiCastDto = struct {
    alias: []const u8,
    version: ?[]const u8, // v2, format: major.minor
    deviceModel: ?[]const u8,
    deviceType: ?[]const u8, // nullable since v2
    fingerprint: []const u8,
    port: ?u16, // v2
    protocol: ?[]const u8, // v2
    download: ?bool, // v2
    announce: ?bool, // v2
    announcement: ?bool, // v1
};

pub const FileMetadata = struct {
    modified: ?[]const u8, // "2021-01-01T12:34:56Z"
    accessed: ?[]const u8, // "2021-01-01T12:34:56Z"
};

pub const FilesDto = struct {
    id: []const u8,
    fileName: []const u8,
    size: usize,
    fileType: []const u8,
    sha256: ?[]const u8,
    preview: ?[]const u8,
    metadata: ?FileMetadata,
};

// https://github.com/localsend/localsend/blob/f5e8a5652c3e313730341b386a3ac2dc33abc318/common/lib/model/dto/prepare_upload_request_dto.dart#L8
pub const PrepareUploadRequestDto = struct {
    info: MultiCastDto,
    files: std.StringHashMap(FilesDto),

    const Self = @This();

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
    // pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Self {
    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Self {
        var files: std.StringHashMapUnmanaged([]const u8) = .empty;
        errdefer files.deinit(allocator);
        if (.object_begin != try source.next()) return error.UnexpectedToken;
        var session_id: []const u8 = undefined;
        while (true) {
            switch (try source.nextAlloc(allocator, options.allocate.?)) {
                inline .string, .allocated_string => |k| {
                    if (std.mem.eql(u8, k, "sessionId")) {
                        session_id = switch (try source.nextAlloc(allocator, options.allocate.?)) {
                            inline .string, .allocated_string => |slice| slice,
                            else => unreachable,
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
                                                // We don't want to skip the value, because we want type checking.
                                                continue;
                                            },
                                            .@"error" => return error.DuplicateField,
                                            .use_last => {},
                                        }
                                    }
                                    gop.value_ptr.* = switch (try source.nextAlloc(allocator, options.allocate.?)) {
                                        .string, .allocated_string => |v| v,
                                        else => unreachable,
                                    };
                                },
                                .object_end => break,
                                else => return error.UnexpectedToken,
                            }
                        } else unreachable;
                    }
                },
                .object_end => break,
                else => unreachable,
            }
        }
        return .{
            .sessionId = session_id,
            .files = files,
        };
    }
};
