// https://github.com/localsend/localsend/blob/f5e8a5652c3e313730341b386a3ac2dc33abc318/common/lib/model/dto/multicast_dto.dart#L11
pub const MultiCastType = struct {
    alias: []const u8,
    version: ?[]const u8, // v2, format: major.minor
    deviceModel: ?[]const u8,
    deviceType: ?[]const u8, // nullable since v2
    fingerprint: []const u8,
    port: ?u16, // v2
    protocol: ?[]const u8, // v2
    download: ?bool, // v2
    announce: ?bool, // v2
};
