const std = @import("std");
const UDP = @import("./udp.zig");
const models = @import("./models.zig");
const utils = @import("./utils.zig");

var buf: [1024]u8 = undefined;
var self_info: ?models.MultiCastDto = undefined;
var last_info: ?models.MultiCastDto = undefined;

var peer_info: ?models.MultiCastDto = undefined;
var peer_addr: ?std.posix.sockaddr = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const udp = try UDP.init("224.0.0.167", 53317);
    defer udp.close();

    while (true) {
        var addr: std.posix.sockaddr = undefined;
        const recv_bytes = try udp.recv(buf[0..], &addr);
        const info = blk: {
            const parsed = try std.json.parseFromSlice(models.MultiCastDto, gpa.allocator(), buf[0..recv_bytes], .{});
            defer parsed.deinit();
            break :blk parsed.value;
        };
        if (last_info != null and !std.mem.eql(u8, last_info.?.fingerprint, info.fingerprint)) {
            @panic("one peer only now");
        }
        const announce = info.announce orelse info.announcement orelse false;
        if (announce) { // response to peer's announcement
            try utils.makeAnnouncement(&self_info);
            var fba = std.heap.FixedBufferAllocator.init(&buf);
            var str = std.ArrayList(u8).init(fba.allocator());
            defer str.deinit();
            try std.json.stringify(self_info, .{}, str.writer());
            // std.debug.print("DEBUGPRINT[348]: main.zig:33: str.items={s}\n", .{str.items});
            const addrp: *std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
            addrp.port = std.mem.nativeToBig(u16, info.port orelse 53317);
            peer_info = peer_info orelse info;
            peer_addr = peer_addr orelse addr;
            _ = try udp.send(str.items, &addr);
        } else if (peer_info) |pinfo| { // peer response to our announcement
            var files = std.StringHashMap(models.FilesDto).init(gpa.allocator());
            try files.put("main.zig", models.FilesDto{
                .id = "main.zig",
                .fileName = "main.zig",
                .size = 1234,
                .fileType = "application/octet-stream",
                .sha256 = null,
                .preview = null,
                .metadata = null,
            });
            // std.debug.print("DEBUGPRINT[366]: main.zig:49: files={any}\n", .{files});
            const data = models.PrepareUploadRequestDto{ .info = self_info.?, .files = files };
            // std.debug.print("DEBUGPRINT[364]: main.zig:48: data={any}\n", .{data});
            const allocator = gpa.allocator();
            const str = try std.json.stringifyAlloc(allocator, data, .{});
            defer allocator.free(str);
            _ = try udp.send(str, &(peer_addr.?));
            std.debug.print("DEBUGPRINT[369]: main.zig:65: str={s}\n", .{str});

            const ip = try UDP.parseIPFromSockAddr(buf[0..recv_bytes], &addr);

            std.debug.print("DEBUGPRINT[373]: main.zig:62: pinfo.protocol.?={s}\n", .{pinfo.protocol.?});
            // const protocol = pinfo.protocol orelse "http";
            const protocol = "http";
            const port = pinfo.port orelse 53317;
            const url = try std.fmt.bufPrint(buf[recv_bytes..], "{s}://{s}:{d}/api/localsend/v2/prepare-upload", .{ protocol, ip, port });
            std.debug.print("DEBUGPRINT[365]: main.zig:46: url={s}\n", .{url});

            var client = std.http.Client{ .allocator = gpa.allocator() };
            const headers = &[_]std.http.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            };
            var resp_body = std.ArrayList(u8).init(gpa.allocator());
            const resp = try client.fetch(.{
                .method = .POST,
                .location = .{ .url = url },
                .extra_headers = headers, //put these here instead of .headers
                .payload = str,
                .response_storage = .{ .dynamic = &resp_body },
            });

            switch (resp.status) {
                .ok => {
                    std.debug.print("DEBUGPRINT[404]: main.zig:81: resp_body={s}\n", .{resp_body.items});
                },
                else => {
                    std.debug.print("DEBUGPRINT[375]: main.zig:82: resp={any}\n", .{resp});
                    @panic("unexpected response status");
                },
            }
        }
        last_info = info;
    }
}
