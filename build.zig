const std = @import("std");

pub fn build(b: *std.Build) void {
    const t = b.standardTargetOptions(.{});
    const o = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = "localsend_zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = t,
            .optimize = o,
        }),
    });
    exe.linkLibC();
    b.installArtifact(exe);

    if (b.lazyDependency("xev", .{ .target = t, .optimize = o })) |dep|
        exe.root_module.addImport("xev", dep.module("xev"));
    if (b.lazyDependency("vaxis", .{ .target = t, .optimize = o })) |dep|
        exe.root_module.addImport("vaxis", dep.module("vaxis"));
    if (b.lazyDependency("httpz", .{ .target = t, .optimize = o })) |dep|
        exe.root_module.addImport("httpz", dep.module("httpz"));

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    var src_dir = std.fs.cwd().openDir("src", .{ .iterate = true }) catch |err| {
        std.debug.print("Warning: Could not open src directory: {}\n", .{err});
        return;
    };
    defer src_dir.close();
    var iter = src_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".zig")) {
            const test_file = b.fmt("src/{s}", .{entry.name});
            const module_tests = b.addTest(.{
                .root_module = b.createModule(.{
                    .root_source_file = b.path(test_file),
                    .target = t,
                    .optimize = o,
                }),
            });
            const run_module_tests = b.addRunArtifact(module_tests);
            test_step.dependOn(&run_module_tests.step);
        }
    }
}
