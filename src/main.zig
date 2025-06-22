const std = @import("std");
const UDP = @import("./udp.zig");
const models = @import("./models.zig");
const utils = @import("./utils.zig");

pub fn main() !void {
    const udp = try UDP.init("0.0.0.0", 3000);
    defer udp.close();

    const info = try utils.getMulticastInfo();
    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var payload = std.ArrayList(u8).init(fba.allocator());
    defer payload.deinit();
    try std.json.stringify(info, .{}, payload.writer());
}
