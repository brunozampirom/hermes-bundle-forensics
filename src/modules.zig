//! Attributing bytecode back to the JavaScript modules it was compiled from.
//!
//! The link is the source map, not the bundle. A function's position in the map
//! is its virtual offset: the running sum of every function's bytecode size in
//! index order. That is not where the body sits in the file, because Hermes
//! deduplicates identical bodies and several functions then share one address,
//! but it is the space the map is written in.
//!
//! Attribution is by byte range rather than by function. The global function of
//! a Metro bundle is tens of kilobytes spanning every module's wrapper, so
//! giving all of it to whichever module happens to start it would be wrong by
//! more than everything else combined.

const std = @import("std");
const hbc = @import("hbc.zig");
const sourcemap = @import("sourcemap.zig");

pub const Module = struct {
    name: []const u8,
    bytes: u64,
};

pub const Result = struct {
    modules: []Module,
    attributed: u64,
    /// Bytes in ranges the map has no segment for, which is mostly whatever
    /// precedes its first mapping.
    unattributed: u64,
    /// Bodies shared between functions, counted once like everywhere else.
    distinct_bodies: u32,
};

fn moreByBytes(_: void, a: Module, b: Module) bool {
    if (a.bytes != b.bytes) return a.bytes > b.bytes;
    return std.mem.lessThan(u8, a.name, b.name);
}

/// `functions` must be in index order, which is how `hbc.parseFunctions`
/// returns them, because the virtual offset depends on that order.
pub fn attribute(
    gpa: std.mem.Allocator,
    functions: []const hbc.Function,
    map: sourcemap.Map,
) !Result {
    const totals = try gpa.alloc(u64, map.sources.len);
    defer gpa.free(totals);
    @memset(totals, 0);

    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer seen.deinit(gpa);

    var attributed: u64 = 0;
    var unattributed: u64 = 0;
    var distinct: u32 = 0;
    var virtual: u64 = 0;

    for (functions) |f| {
        const start = virtual;
        const end = virtual + f.bytecode_size;
        virtual = end;

        // A body several functions share is counted once, so these totals stay
        // comparable with the section the rest of the tool reports.
        const dup = try seen.getOrPut(gpa, f.offset);
        if (dup.found_existing) continue;
        distinct += 1;
        if (f.bytecode_size == 0) continue;

        var at = start;
        while (at < end) {
            const seg = map.segmentFor(@intCast(at)) orelse {
                // Before the first mapping. Give up on the rest of this range
                // only as far as the first segment, then carry on.
                const first = if (map.segments.len > 0) map.segments[0].offset else end;
                const stop = @min(end, @as(u64, first));
                unattributed += stop - at;
                at = stop;
                continue;
            };

            const next: u64 = if (seg + 1 < map.segments.len)
                map.segments[seg + 1].offset
            else
                end;
            const stop = @min(end, @max(next, at + 1));
            const src = map.segments[seg].source;
            if (src < totals.len) totals[src] += stop - at;
            attributed += stop - at;
            at = stop;
        }
    }

    var list: std.ArrayList(Module) = .empty;
    errdefer list.deinit(gpa);
    for (totals, 0..) |bytes, i| {
        if (bytes == 0) continue;
        try list.append(gpa, .{ .name = map.sources[i], .bytes = bytes });
    }
    const modules = try list.toOwnedSlice(gpa);
    std.sort.pdq(Module, modules, {}, moreByBytes);

    return .{
        .modules = modules,
        .attributed = attributed,
        .unattributed = unattributed,
        .distinct_bodies = distinct,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn fn_(index: u32, offset: u32, size: u32) hbc.Function {
    return .{
        .index = index,
        .offset = offset,
        .param_count = 0,
        .bytecode_size = size,
        .name_id = 0,
        .info_offset = 0,
        .frame_size = 0,
        .environment_size = 0,
        .flags = @bitCast(@as(u8, 0)),
        .from_large_header = false,
    };
}

fn mapOf(gpa: std.mem.Allocator, names: []const []const u8, segs: []const sourcemap.Segment) !sourcemap.Map {
    const s = try gpa.alloc([]const u8, names.len);
    for (names, 0..) |n, i| s[i] = n;
    return .{ .sources = s, .segments = try gpa.dupe(sourcemap.Segment, segs) };
}

test "a function spanning two modules is split between them" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const map = try mapOf(gpa, &.{ "a.js", "b.js" }, &.{
        .{ .offset = 0, .source = 0, .line = 1, .column = 0 },
        .{ .offset = 40, .source = 1, .line = 1, .column = 0 },
    });

    // One function of 100 bytes crossing the boundary at 40.
    const fns = [_]hbc.Function{fn_(0, 1000, 100)};
    const r = try attribute(gpa, &fns, map);

    try testing.expectEqual(@as(u64, 100), r.attributed);
    try testing.expectEqual(@as(u64, 0), r.unattributed);
    try testing.expectEqual(@as(usize, 2), r.modules.len);
    try testing.expectEqualStrings("b.js", r.modules[0].name);
    try testing.expectEqual(@as(u64, 60), r.modules[0].bytes);
    try testing.expectEqual(@as(u64, 40), r.modules[1].bytes);
}

test "a body two functions share is counted once" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const map = try mapOf(gpa, &.{"a.js"}, &.{
        .{ .offset = 0, .source = 0, .line = 1, .column = 0 },
    });

    // Two functions, same body offset, so only the first is attributed.
    const fns = [_]hbc.Function{ fn_(0, 500, 10), fn_(1, 500, 10) };
    const r = try attribute(gpa, &fns, map);

    try testing.expectEqual(@as(u32, 1), r.distinct_bodies);
    try testing.expectEqual(@as(u64, 10), r.attributed);
    try testing.expectEqual(@as(u64, 10), r.modules[0].bytes);
}

test "bytes before the first mapping are reported, not silently dropped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const map = try mapOf(gpa, &.{"a.js"}, &.{
        .{ .offset = 30, .source = 0, .line = 1, .column = 0 },
    });

    const fns = [_]hbc.Function{fn_(0, 100, 50)};
    const r = try attribute(gpa, &fns, map);

    try testing.expectEqual(@as(u64, 30), r.unattributed);
    try testing.expectEqual(@as(u64, 20), r.attributed);
}
