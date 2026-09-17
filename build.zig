const std = @import("std");

/// Every file with tests needs its own test artifact: `zig test` only runs
/// tests in the root it is given, so pointing it at main.zig alone would
/// silently skip the parser tests, which are the ones that matter.
///
/// Being a hand-kept list, it can fall behind a new file, and it already did
/// once: html.zig was absent, so its tests would have been written and never
/// run. CI now fails when a file with tests is missing from here.
const test_roots = [_][]const u8{
    "src/hbc.zig",
    "src/strings.zig",
    "src/container.zig",
    "src/tree.zig",
    "src/budget.zig",
    "src/debug.zig",
    "src/sourcemap.zig",
    "src/modules.zig",
    "src/html.zig",
    "src/main.zig",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "hbcinfo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run hbcinfo").dependOn(&run.step);

    const test_step = b.step("test", "Run the tests");
    for (test_roots) |root| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(root),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
