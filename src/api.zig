const std = @import("std");
const net = std.net;

/// LocalSend Protocol v2.1 API routes
/// Reference: https://github.com/localsend/protocol
pub const ApiRoute = enum {
    /// Get device info (for debugging)
    info,
    /// Two-way device discovery
    register,
    /// Receiver accepts file metadata
    prepare_upload,
    /// Sender uploads file to receiver
    upload,
    /// Cancel an upload session
    cancel,
    /// Receiver requests file metadata
    prepare_download,
    /// Receiver downloads file from sender
    download,

    /// Get the v2 API path for this route
    pub fn path(self: ApiRoute) []const u8 {
        return switch (self) {
            .info => "/api/localsend/v2/info",
            .register => "/api/localsend/v2/register",
            .prepare_upload => "/api/localsend/v2/prepare-upload",
            .upload => "/api/localsend/v2/upload",
            .cancel => "/api/localsend/v2/cancel",
            .prepare_download => "/api/localsend/v2/prepare-download",
            .download => "/api/localsend/v2/download",
        };
    }

    /// Build a full URL for this route
    pub fn url(
        self: ApiRoute,
        allocator: std.mem.Allocator,
        addr: *const net.Address,
        https: bool,
    ) ![]u8 {
        const scheme = if (https) "https" else "http";
        return std.fmt.allocPrint(allocator, "{s}://{f}{s}", .{ scheme, addr, self.path() });
    }

    /// Query parameter key-value pair for URL building
    const QueryParam = struct { []const u8, []const u8 };
    /// Build a full URL for this route with query parameters
    pub fn urlWithQuery(
        self: ApiRoute,
        allocator: std.mem.Allocator,
        addr: *const net.Address,
        https: bool,
        query_params: []const QueryParam,
    ) ![]u8 {
        if (query_params.len == 0) {
            return self.url(allocator, addr, https);
        }

        const scheme = if (https) "https" else "http";
        var url_buf: std.ArrayList(u8) = .empty;
        errdefer url_buf.deinit(allocator);

        // Build base URL
        // fixme: deprecatedd
        try url_buf.writer(allocator).print("{s}://{f}{s}?", .{ scheme, addr, self.path() });

        // Add query parameters
        for (query_params, 0..) |param, i| {
            if (i > 0) try url_buf.append(allocator, '&');
            try url_buf.writer(allocator).print("{s}={s}", .{ param[0], param[1] });
        }

        return url_buf.toOwnedSlice(allocator);
    }

    /// Match a path to an ApiRoute
    pub fn match(target_path: []const u8) ?ApiRoute {
        const routes = comptime std.StaticStringMap(ApiRoute).initComptime(.{
            .{ "/api/localsend/v2/info", .info },
            .{ "/api/localsend/v2/register", .register },
            .{ "/api/localsend/v2/prepare-upload", .prepare_upload },
            .{ "/api/localsend/v2/upload", .upload },
            .{ "/api/localsend/v2/cancel", .cancel },
            .{ "/api/localsend/v2/prepare-download", .prepare_download },
            .{ "/api/localsend/v2/download", .download },
        });

        // Strip query parameters if present
        const path_end = std.mem.indexOfScalar(u8, target_path, '?') orelse target_path.len;
        return routes.get(target_path[0..path_end]);
    }
};

/// Parse query parameters from a URL using std.Uri
pub const QueryParams = struct {
    allocator: std.mem.Allocator,
    params: std.StringHashMap([]const u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .params = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.params.deinit();
    }

    /// Parse query string into parameters
    pub fn parse(allocator: std.mem.Allocator, query: []const u8) !Self {
        var self = Self.init(allocator);
        errdefer self.deinit();

        var it = std.mem.splitScalar(u8, query, '&');
        while (it.next()) |param| {
            if (std.mem.indexOfScalar(u8, param, '=')) |eq_pos| {
                const key = param[0..eq_pos];
                const value = param[eq_pos + 1 ..];
                try self.params.put(key, value);
            }
        }
        return self;
    }

    /// Parse query from full URL target using std.Uri
    pub fn fromTarget(allocator: std.mem.Allocator, target: []const u8) !Self {
        // Parse the URI - handle both full URIs and path-only targets
        const uri = std.Uri.parse(target) catch {
            // If parsing fails, assume it's just a path with query
            if (std.mem.indexOfScalar(u8, target, '?')) |query_start| {
                return parse(allocator, target[query_start + 1 ..]);
            }
            return Self.init(allocator);
        };

        if (uri.query) |query| {
            return parse(allocator, query.raw);
        }
        return Self.init(allocator);
    }

    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        return self.params.get(key);
    }
};

test "ApiRoute.match" {
    try std.testing.expectEqual(ApiRoute.info, ApiRoute.match("/api/localsend/v2/info").?);
    try std.testing.expectEqual(ApiRoute.register, ApiRoute.match("/api/localsend/v2/register").?);
    try std.testing.expectEqual(ApiRoute.upload, ApiRoute.match("/api/localsend/v2/upload?sessionId=abc&token=xyz").?);
    try std.testing.expect(ApiRoute.match("/invalid/path") == null);
}

test "QueryParams" {
    const allocator = std.testing.allocator;
    var params = try QueryParams.parse(allocator, "sessionId=abc123&fileId=file1&token=xyz789");
    defer params.deinit();

    try std.testing.expectEqualStrings("abc123", params.get("sessionId").?);
    try std.testing.expectEqualStrings("file1", params.get("fileId").?);
    try std.testing.expectEqualStrings("xyz789", params.get("token").?);
    try std.testing.expect(params.get("nonexistent") == null);
}

test "QueryParams.fromTarget with path and query" {
    const allocator = std.testing.allocator;
    var params = try QueryParams.fromTarget(allocator, "/api/localsend/v2/upload?sessionId=test123&token=abc");
    defer params.deinit();

    try std.testing.expectEqualStrings("test123", params.get("sessionId").?);
    try std.testing.expectEqualStrings("abc", params.get("token").?);
}

test "ApiRoute.url generates correct URL" {
    const allocator = std.testing.allocator;

    const http_url = try ApiRoute.info.url(allocator, &try net.Address.parseIp("192.168.1.100", 53317), false);
    defer allocator.free(http_url);
    try std.testing.expectEqualStrings("http://192.168.1.100:53317/api/localsend/v2/info", http_url);

    const https_url = try ApiRoute.prepare_upload.url(allocator, &try net.Address.parseIp("10.0.0.5", 8080), true);
    defer allocator.free(https_url);
    try std.testing.expectEqualStrings("https://10.0.0.5:8080/api/localsend/v2/prepare-upload", https_url);
}

test "ApiRoute.urlWithQuery generates URL with query params" {
    const allocator = std.testing.allocator;

    // Test with no query params
    const url_no_query = try ApiRoute.upload.urlWithQuery(allocator, &try net.Address.parseIp("192.168.1.100", 53317), false, &.{});
    defer allocator.free(url_no_query);
    try std.testing.expectEqualStrings("http://192.168.1.100:53317/api/localsend/v2/upload", url_no_query);

    // Test with one query param
    const url_one = try ApiRoute.upload.urlWithQuery(allocator, &try net.Address.parseIp("192.168.1.100", 53317), false, &.{
        .{ "sessionId", "abc123" },
    });
    defer allocator.free(url_one);
    try std.testing.expectEqualStrings("http://192.168.1.100:53317/api/localsend/v2/upload?sessionId=abc123", url_one);

    // Test with multiple query params
    const url_multi = try ApiRoute.upload.urlWithQuery(allocator, &try net.Address.parseIp("10.0.0.5", 8080), true, &.{
        .{ "sessionId", "test-session" },
        .{ "fileId", "file123" },
        .{ "token", "secret-token" },
    });
    defer allocator.free(url_multi);
    try std.testing.expectEqualStrings("https://10.0.0.5:8080/api/localsend/v2/upload?sessionId=test-session&fileId=file123&token=secret-token", url_multi);
}
