//! A hierarchical view of where a bundle's bytes went.
//!
//! Everything here allocates from the caller allocator and never frees: names
//! are built per node and some are borrowed from the bundle. Callers pass an
//! arena, which is what the tool does, and the tests do the same.
//!
//! Deliberately generic: a node is a name, a size and children, with no fixed
//! depth. The text report stays as it is and this is a second consumer of the
//! same parsed data, so attributing functions to source modules later adds a
//! level rather than replacing anything.

const std = @import("std");
const hbc = @import("hbc.zig");
const strings = @import("strings.zig");
const modules = @import("modules.zig");

pub const Node = struct {
    /// What the tile says.
    name: []const u8,
    /// What two builds are matched on. Function display names carry an index
    /// that shifts between builds, so the key is the bare name.
    key: []const u8,
    bytes: u64,
    children: []Node = &.{},

    pub fn isLeaf(self: Node) bool {
        return self.children.len == 0;
    }
};

pub const Options = struct {
    /// A treemap stops being readable long before a bundle stops having
    /// functions, so everything past this is folded into one node that still
    /// carries its bytes.
    max_children: usize = 300,
    /// When a source map was given, the bytecode section is broken down by
    /// module instead of by function. Module paths are stable across builds in
    /// a way function names are not, which also makes a diff of them mean
    /// something.
    attribution: ?modules.Result = null,
};

fn moreBySize(_: void, a: Node, b: Node) bool {
    return a.bytes > b.bytes;
}

/// Sorts `nodes` by size and folds the tail into a single node, so the totals
/// still add up when only the head is drawn.
fn cap(gpa: std.mem.Allocator, nodes: []Node, limit: usize, noun: []const u8) ![]Node {
    std.sort.pdq(Node, nodes, {}, moreBySize);
    if (nodes.len <= limit) return nodes;

    var rest: u64 = 0;
    for (nodes[limit..]) |n| rest += n.bytes;

    const out = try gpa.alloc(Node, limit + 1);
    @memcpy(out[0..limit], nodes[0..limit]);
    const tail = try std.fmt.allocPrint(gpa, "other ({d} {s})", .{ nodes.len - limit, noun });
    out[limit] = .{ .name = tail, .key = tail, .bytes = rest };
    return out;
}

fn functionNodes(
    gpa: std.mem.Allocator,
    functions: []const hbc.Function,
    table: ?strings.Table,
    opts: Options,
) ![]Node {
    if (functions.len == 0) return &.{};

    // Hermes shares identical bodies between headers, so a tree that listed
    // every header would invent bytes the file does not contain.
    const by_offset = try gpa.dupe(hbc.Function, functions);
    defer gpa.free(by_offset);
    std.sort.pdq(hbc.Function, by_offset, {}, lessByOffset);

    var nodes = try std.ArrayList(Node).initCapacity(gpa, functions.len);
    defer nodes.deinit(gpa);

    var i: usize = 0;
    while (i < by_offset.len) {
        const f = by_offset[i];
        const shared = blk: {
            var n: usize = 0;
            while (i + n < by_offset.len and by_offset[i + n].offset == f.offset) n += 1;
            break :blk n;
        };
        i += shared;
        if (f.bytecode_size == 0) continue;

        const named = try functionName(gpa, f, table, shared);
        try nodes.append(gpa, .{
            .name = named.display,
            .key = named.key,
            .bytes = f.bytecode_size,
        });
    }

    return cap(gpa, try nodes.toOwnedSlice(gpa), opts.max_children, "functions");
}

fn lessByOffset(_: void, a: hbc.Function, b: hbc.Function) bool {
    return a.offset < b.offset;
}

const Named = struct { display: []const u8, key: []const u8 };

fn functionName(
    gpa: std.mem.Allocator,
    f: hbc.Function,
    table: ?strings.Table,
    shared: usize,
) !Named {
    var kw = std.Io.Writer.Allocating.init(gpa);
    errdefer kw.deinit();

    if (table) |t| {
        if (t.get(f.name_id)) |name| {
            if (name.bytes.len == 0) {
                try kw.writer.print("(anonymous)", .{});
            } else {
                try strings.writeEscaped(&kw.writer, name, 80);
            }
        } else |_| {
            try kw.writer.print("(name {d} unreadable)", .{f.name_id});
        }
    } else {
        try kw.writer.print("name {d}", .{f.name_id});
    }
    const key = try kw.toOwnedSlice();

    var dw = std.Io.Writer.Allocating.init(gpa);
    errdefer dw.deinit();
    try dw.writer.print("{s} #{d}", .{ key, f.index });
    if (shared > 1) try dw.writer.print(" [body shared by {d}]", .{shared});

    return .{ .display = try dw.toOwnedSlice(), .key = key };
}

/// The package a module path belongs to, and the rest of the path after it.
/// A real bundle has hundreds of files but far fewer packages, and without the
/// grouping the tail of small modules becomes the largest tile on the map.
fn splitPackage(path: []const u8) struct { group: []const u8, rest: []const u8 } {
    const marker = "/node_modules/";
    if (std.mem.lastIndexOf(u8, path, marker)) |i| {
        const after = path[i + marker.len ..];
        var end = std.mem.indexOfScalar(u8, after, '/') orelse after.len;
        // A scoped package is two segments, not one.
        if (after.len > 0 and after[0] == '@') {
            if (std.mem.indexOfScalarPos(u8, after, end + 1, '/')) |j| end = j;
        }
        return .{ .group = after[0..end], .rest = if (end < after.len) after[end + 1 ..] else after };
    }

    // Anything else groups by its first two segments, which for an app is the
    // workspace and the package inside it.
    var start: usize = 0;
    if (path.len > 0 and path[0] == '/') start = 1;
    var end = start;
    var seen: usize = 0;
    while (end < path.len and seen < 2) : (end += 1) {
        if (path[end] == '/') seen += 1;
    }
    if (seen < 2) return .{ .group = path[start..], .rest = path[start..] };
    return .{ .group = path[start .. end - 1], .rest = path[end..] };
}

/// Two levels: a tile per package, each holding a tile per file. The key stays
/// the full module path, so a diff compares the thing that is stable between
/// builds.
fn moduleNodes(gpa: std.mem.Allocator, a: modules.Result, opts: Options) ![]Node {
    var groups: std.StringArrayHashMapUnmanaged(std.ArrayList(Node)) = .empty;
    defer groups.deinit(gpa);

    for (a.modules) |m| {
        if (m.bytes == 0) continue;
        const parts = splitPackage(m.name);
        const e = try groups.getOrPut(gpa, parts.group);
        if (!e.found_existing) e.value_ptr.* = .empty;
        try e.value_ptr.append(gpa, .{
            .name = parts.rest,
            .key = m.name,
            .bytes = m.bytes,
        });
    }

    var nodes = try std.ArrayList(Node).initCapacity(gpa, groups.count() + 1);
    defer nodes.deinit(gpa);

    var it = groups.iterator();
    while (it.next()) |e| {
        var total: u64 = 0;
        for (e.value_ptr.items) |c| total += c.bytes;

        const kids = try e.value_ptr.toOwnedSlice(gpa);
        try nodes.append(gpa, .{
            .name = e.key_ptr.*,
            .key = e.key_ptr.*,
            .bytes = total,
            // A package holding one file gains nothing from a level of nesting.
            .children = if (kids.len > 1) try cap(gpa, kids, opts.max_children, "files") else &.{},
        });
    }

    if (a.unattributed > 0) {
        try nodes.append(gpa, .{
            .name = "(no mapping)",
            .key = "(no mapping)",
            .bytes = a.unattributed,
        });
    }

    return cap(gpa, try nodes.toOwnedSlice(gpa), opts.max_children, "packages");
}

const Claim = struct { id: u32, offset: u32, len: u32, unique: u32 };

fn longestFirst(_: void, a: Claim, b: Claim) bool {
    if (a.len != b.len) return a.len > b.len;
    return a.id < b.id;
}

/// Hermes packs strings with a suffix array, so a string that is a suffix of
/// another shares its bytes and the lengths add up to more than the buffer
/// holds. A treemap is a partition of area, so sizing tiles by length would
/// draw children that overflow their parent.
///
/// Each byte of storage is instead given to exactly one string, longest first,
/// and a string is sized by what it alone keeps alive. The tiles then sum to
/// the storage the file actually spends, and a string fully contained in
/// another correctly costs nothing.
fn stringNodes(
    gpa: std.mem.Allocator,
    h: hbc.Header,
    table: strings.Table,
    opts: Options,
) ![]Node {
    const storage_size = h.string_storage_size;
    if (storage_size == 0 or table.count == 0) return &.{};

    var claims = try std.ArrayList(Claim).initCapacity(gpa, table.count);
    defer claims.deinit(gpa);

    var id: u32 = 0;
    while (id < table.count) : (id += 1) {
        const s = table.get(id) catch continue;
        if (s.bytes.len == 0) continue;
        const off = @intFromPtr(s.bytes.ptr) - @intFromPtr(table.file.ptr) - table.storage_at;
        try claims.append(gpa, .{
            .id = id,
            .offset = @intCast(off),
            .len = @intCast(s.bytes.len),
            .unique = 0,
        });
    }

    const owned = try gpa.alloc(bool, storage_size);
    defer gpa.free(owned);
    @memset(owned, false);

    std.sort.pdq(Claim, claims.items, {}, longestFirst);
    var covered: u64 = 0;
    for (claims.items) |*c| {
        const end = @min(@as(u64, c.offset) + c.len, storage_size);
        var i: u64 = c.offset;
        while (i < end) : (i += 1) {
            if (!owned[@intCast(i)]) {
                owned[@intCast(i)] = true;
                c.unique += 1;
                covered += 1;
            }
        }
    }

    var nodes = try std.ArrayList(Node).initCapacity(gpa, claims.items.len);
    defer nodes.deinit(gpa);

    for (claims.items) |c| {
        if (c.unique == 0) continue;
        const s = table.get(c.id) catch continue;

        var kw = std.Io.Writer.Allocating.init(gpa);
        errdefer kw.deinit();
        try strings.writeEscaped(&kw.writer, s, 80);
        const key = try kw.toOwnedSlice();

        var dw = std.Io.Writer.Allocating.init(gpa);
        errdefer dw.deinit();
        try dw.writer.print("{s} #{d}", .{ key, c.id });
        if (c.unique < c.len) {
            try dw.writer.print(" [{d} of {d} bytes shared]", .{ c.len - c.unique, c.len });
        }

        try nodes.append(gpa, .{ .name = try dw.toOwnedSlice(), .key = key, .bytes = c.unique });
    }

    if (covered < storage_size) {
        const text = try std.fmt.allocPrint(gpa, "unreferenced ({d} bytes)", .{storage_size - covered});
        try nodes.append(gpa, .{ .name = text, .key = "unreferenced", .bytes = storage_size - covered });
    }

    return cap(gpa, try nodes.toOwnedSlice(gpa), opts.max_children, "strings");
}

/// Builds the whole tree. Children are attached to the two sections where a
/// breakdown exists; the rest stay leaves because the file gives no finer
/// detail than their size.
pub fn build(
    gpa: std.mem.Allocator,
    h: hbc.Header,
    functions: []const hbc.Function,
    table: ?strings.Table,
    file_size: u64,
    opts: Options,
) !Node {
    const scratch = try gpa.dupe(hbc.Function, functions);
    defer gpa.free(scratch);
    const stats = hbc.bytecodeStats(scratch);

    var buf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const secs = hbc.sections(h, stats.distinct_bytes, stats.overflowed_headers, &buf);

    var kids: std.ArrayList(Node) = .empty;
    defer kids.deinit(gpa);

    var known: u64 = 0;
    for (secs) |s| {
        known += s.bytes;
        if (s.bytes == 0) continue;

        var node = Node{ .name = s.name, .key = s.name, .bytes = s.bytes };
        if (std.mem.eql(u8, s.name, "function bytecode")) {
            node.children = if (opts.attribution) |a|
                try moduleNodes(gpa, a, opts)
            else
                try functionNodes(gpa, functions, table, opts);
        } else if (std.mem.eql(u8, s.name, "string storage")) {
            if (table) |t| node.children = try stringNodes(gpa, h, t, opts);
        }
        try kids.append(gpa, node);
    }

    const rest = if (file_size > known) file_size - known else 0;
    if (rest > 0) {
        try kids.append(gpa, .{ .name = "rest (info + padding)", .key = "rest", .bytes = rest });
    }

    const children = try kids.toOwnedSlice(gpa);
    std.sort.pdq(Node, children, {}, moreBySize);

    return .{ .name = "bundle", .key = "bundle", .bytes = file_size, .children = children };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "capping keeps the folded bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const nodes = try gpa.alloc(Node, 5);
    defer gpa.free(nodes);
    for (nodes, 0..) |*n, i| n.* = .{ .name = "x", .key = "x", .bytes = (5 - i) * 10 };

    const out = try cap(gpa, nodes, 2, "things");

    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqual(@as(u64, 50), out[0].bytes);
    try testing.expectEqual(@as(u64, 40), out[1].bytes);
    // 30 + 20 + 10 folded into the tail node.
    try testing.expectEqual(@as(u64, 60), out[2].bytes);

    var total: u64 = 0;
    for (out) |n| total += n.bytes;
    try testing.expectEqual(@as(u64, 150), total);
}

test "a string contained in another costs no bytes of its own" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const storage_at = 136;
    var b = [_]u8{0} ** (storage_at + 11);
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);

    var h = std.mem.zeroes(hbc.Header);
    h.version = 96;
    h.string_count = 2;
    h.string_storage_size = 11;
    h.file_length = storage_at + 11;

    const l = hbc.layout(h);
    try testing.expectEqual(@as(u64, storage_at), l.string_storage);

    // "hello world", then "world" sitting inside it.
    std.mem.writeInt(u32, b[128..][0..4], (11 << 24) | (0 << 1), .little);
    std.mem.writeInt(u32, b[132..][0..4], (5 << 24) | (6 << 1), .little);
    @memcpy(b[storage_at..][0..11], "hello world");

    const t = try strings.Table.init(&b, h);
    const nodes = try stringNodes(gpa, h, t, .{});

    // Only the outer string is left; the suffix claims nothing.
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expectEqual(@as(u64, 11), nodes[0].bytes);

    var total: u64 = 0;
    for (nodes) |n| total += n.bytes;
    try testing.expectEqual(@as(u64, h.string_storage_size), total);
}

test "sections and their children reconcile with the file size" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var b = [_]u8{0} ** 256;
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);

    var h = std.mem.zeroes(hbc.Header);
    h.version = 96;
    h.file_length = b.len;

    const root = try build(gpa, h, &.{}, null, b.len, .{});

    var total: u64 = 0;
    for (root.children) |c| total += c.bytes;
    try testing.expectEqual(root.bytes, total);
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

pub const DiffNode = struct {
    name: []const u8,
    a_bytes: u64,
    b_bytes: u64,
    /// How many nodes on each side were folded under this key.
    a_count: u32,
    b_count: u32,
    children: []DiffNode = &.{},

    pub fn grew(self: DiffNode) bool {
        return self.b_bytes > self.a_bytes;
    }

    pub fn delta(self: DiffNode) i64 {
        return @as(i64, @intCast(self.b_bytes)) - @as(i64, @intCast(self.a_bytes));
    }
};

const Agg = struct {
    display: []const u8,
    bytes: u64,
    count: u32,
    /// The only node under this key, when there is exactly one. Recursing into
    /// a key that folded several nodes would be comparing different things.
    only: ?Node,
};

fn aggregate(
    gpa: std.mem.Allocator,
    children: []const Node,
    map: *std.StringArrayHashMapUnmanaged(Agg),
) !void {
    for (children) |c| {
        const e = try map.getOrPut(gpa, c.key);
        if (e.found_existing) {
            e.value_ptr.bytes += c.bytes;
            e.value_ptr.count += 1;
            e.value_ptr.only = null;
        } else {
            e.value_ptr.* = .{
                .display = c.name,
                .bytes = c.bytes,
                .count = 1,
                .only = c,
            };
        }
    }
}

fn label(gpa: std.mem.Allocator, key: []const u8, a: Agg, b: ?Agg) ![]const u8 {
    const count = @max(a.count, if (b) |x| x.count else 0);
    // 118 of the 301 largest functions in a real bundle are called
    // "(anonymous)". Nothing distinguishes them across builds, so they are
    // summed under one key and the count says so rather than implying a match.
    if (count > 1) return std.fmt.allocPrint(gpa, "{s} x{d}", .{ key, count });
    return a.display;
}

/// Matches children by key and sums the ones that share a key. Sizes come from
/// the second bundle, so the tiles still partition it; what is only in the
/// first has no area and is reported separately.
pub fn diff(gpa: std.mem.Allocator, a: Node, b: Node) !DiffNode {
    var am: std.StringArrayHashMapUnmanaged(Agg) = .empty;
    defer am.deinit(gpa);
    var bm: std.StringArrayHashMapUnmanaged(Agg) = .empty;
    defer bm.deinit(gpa);

    try aggregate(gpa, a.children, &am);
    try aggregate(gpa, b.children, &bm);

    var kids: std.ArrayList(DiffNode) = .empty;
    defer kids.deinit(gpa);

    var bi = bm.iterator();
    while (bi.next()) |e| {
        const key = e.key_ptr.*;
        const bv = e.value_ptr.*;
        const av: ?Agg = am.get(key);

        var node = DiffNode{
            .name = try label(gpa, key, bv, av),
            .a_bytes = if (av) |x| x.bytes else 0,
            .b_bytes = bv.bytes,
            .a_count = if (av) |x| x.count else 0,
            .b_count = bv.count,
        };

        if (av) |x| {
            if (x.only != null and bv.only != null and
                (x.only.?.children.len > 0 or bv.only.?.children.len > 0))
            {
                const sub = try diff(gpa, x.only.?, bv.only.?);
                node.children = sub.children;
            }
        }
        try kids.append(gpa, node);
    }

    var ai = am.iterator();
    while (ai.next()) |e| {
        if (bm.contains(e.key_ptr.*)) continue;
        const av = e.value_ptr.*;
        try kids.append(gpa, .{
            .name = try label(gpa, e.key_ptr.*, av, null),
            .a_bytes = av.bytes,
            .b_bytes = 0,
            .a_count = av.count,
            .b_count = 0,
        });
    }

    const children = try kids.toOwnedSlice(gpa);
    std.sort.pdq(DiffNode, children, {}, moreByNewSize);

    return .{
        .name = b.name,
        .a_bytes = a.bytes,
        .b_bytes = b.bytes,
        .a_count = 1,
        .b_count = 1,
        .children = children,
    };
}

fn moreByNewSize(_: void, x: DiffNode, y: DiffNode) bool {
    if (x.b_bytes != y.b_bytes) return x.b_bytes > y.b_bytes;
    return x.a_bytes > y.a_bytes;
}

test "diff sums nodes that share a key and counts them" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const a = Node{ .name = "root", .key = "root", .bytes = 30, .children = @constCast(&[_]Node{
        .{ .name = "(anonymous) #1", .key = "(anonymous)", .bytes = 10 },
        .{ .name = "(anonymous) #2", .key = "(anonymous)", .bytes = 20 },
    }) };
    const b = Node{ .name = "root", .key = "root", .bytes = 55, .children = @constCast(&[_]Node{
        .{ .name = "(anonymous) #7", .key = "(anonymous)", .bytes = 25 },
        .{ .name = "(anonymous) #9", .key = "(anonymous)", .bytes = 30 },
    }) };

    const d = try diff(gpa, a, b);

    try testing.expectEqual(@as(usize, 1), d.children.len);
    try testing.expectEqualStrings("(anonymous) x2", d.children[0].name);
    try testing.expectEqual(@as(u64, 30), d.children[0].a_bytes);
    try testing.expectEqual(@as(u64, 55), d.children[0].b_bytes);
    try testing.expectEqual(@as(i64, 25), d.children[0].delta());
}

test "a node only in the first bundle has no area but is kept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const a = Node{ .name = "root", .key = "root", .bytes = 10, .children = @constCast(&[_]Node{
        .{ .name = "gone", .key = "gone", .bytes = 10 },
    }) };
    const b = Node{ .name = "root", .key = "root", .bytes = 0, .children = &.{} };

    const d = try diff(gpa, a, b);

    try testing.expectEqual(@as(usize, 1), d.children.len);
    try testing.expectEqual(@as(u64, 0), d.children[0].b_bytes);
    try testing.expectEqual(@as(i64, -10), d.children[0].delta());
}

test "module paths group by package" {
    const cases = [_]struct { path: []const u8, group: []const u8 }{
        .{ .path = "/node_modules/i18next/dist/esm/i18next.js", .group = "i18next" },
        .{ .path = "/node_modules/@react-native/virtualized-lists/Lists/VirtualizedList.js", .group = "@react-native/virtualized-lists" },
        .{ .path = "/node_modules/react-native/Libraries/Renderer/x.js", .group = "react-native" },
        .{ .path = "/apps/mobile/app/game.tsx", .group = "apps/mobile" },
        .{ .path = "/apps/mobile/hooks/use-game-state.ts", .group = "apps/mobile" },
    };
    for (cases) |c| {
        const got = splitPackage(c.path);
        try testing.expectEqualStrings(c.group, got.group);
    }
}

test "a nested node_modules groups by the innermost package" {
    const got = splitPackage("/node_modules/a/node_modules/b/index.js");
    try testing.expectEqualStrings("b", got.group);
    try testing.expectEqualStrings("index.js", got.rest);
}
