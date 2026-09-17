//! A hierarchical view of where a bundle's bytes went.
//!
//! Deliberately generic: a node is a name, a size and children, with no fixed
//! depth. The text report stays as it is and this is a second consumer of the
//! same parsed data, so attributing functions to source modules later adds a
//! level rather than replacing anything.

const std = @import("std");
const hbc = @import("hbc.zig");
const strings = @import("strings.zig");

pub const Node = struct {
    name: []const u8,
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
    out[limit] = .{
        .name = try std.fmt.allocPrint(gpa, "other ({d} {s})", .{ nodes.len - limit, noun }),
        .bytes = rest,
    };
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

        try nodes.append(gpa, .{
            .name = try functionName(gpa, f, table, shared),
            .bytes = f.bytecode_size,
        });
    }

    return cap(gpa, try nodes.toOwnedSlice(gpa), opts.max_children, "functions");
}

fn lessByOffset(_: void, a: hbc.Function, b: hbc.Function) bool {
    return a.offset < b.offset;
}

fn functionName(
    gpa: std.mem.Allocator,
    f: hbc.Function,
    table: ?strings.Table,
    shared: usize,
) ![]const u8 {
    var aw = std.Io.Writer.Allocating.init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;

    if (table) |t| {
        if (t.get(f.name_id)) |name| {
            if (name.bytes.len == 0) {
                try w.print("(anonymous) #{d}", .{f.index});
            } else {
                try strings.writeEscaped(w, name, 80);
                try w.print(" #{d}", .{f.index});
            }
        } else |_| {
            try w.print("#{d} (name {d} unreadable)", .{ f.index, f.name_id });
        }
    } else {
        try w.print("#{d} name {d}", .{ f.index, f.name_id });
    }

    if (shared > 1) try w.print(" [body shared by {d}]", .{shared});
    return aw.toOwnedSlice();
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

        var aw = std.Io.Writer.Allocating.init(gpa);
        errdefer aw.deinit();
        try strings.writeEscaped(&aw.writer, s, 80);
        try aw.writer.print(" #{d}", .{c.id});
        if (c.unique < c.len) {
            try aw.writer.print(" [{d} of {d} bytes shared]", .{ c.len - c.unique, c.len });
        }

        try nodes.append(gpa, .{ .name = try aw.toOwnedSlice(), .bytes = c.unique });
    }

    if (covered < storage_size) {
        try nodes.append(gpa, .{
            .name = try std.fmt.allocPrint(gpa, "unreferenced ({d} bytes)", .{storage_size - covered}),
            .bytes = storage_size - covered,
        });
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

        var node = Node{ .name = s.name, .bytes = s.bytes };
        if (std.mem.eql(u8, s.name, "function bytecode")) {
            node.children = try functionNodes(gpa, functions, table, opts);
        } else if (std.mem.eql(u8, s.name, "string storage")) {
            if (table) |t| node.children = try stringNodes(gpa, h, t, opts);
        }
        try kids.append(gpa, node);
    }

    const rest = if (file_size > known) file_size - known else 0;
    if (rest > 0) {
        try kids.append(gpa, .{ .name = "rest (info + padding)", .bytes = rest });
    }

    const children = try kids.toOwnedSlice(gpa);
    std.sort.pdq(Node, children, {}, moreBySize);

    return .{ .name = "bundle", .bytes = file_size, .children = children };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "capping keeps the folded bytes" {
    const gpa = testing.allocator;
    const nodes = try gpa.alloc(Node, 5);
    defer gpa.free(nodes);
    for (nodes, 0..) |*n, i| n.* = .{ .name = "x", .bytes = (5 - i) * 10 };

    const out = try cap(gpa, nodes, 2, "things");
    defer gpa.free(out);

    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqual(@as(u64, 50), out[0].bytes);
    try testing.expectEqual(@as(u64, 40), out[1].bytes);
    // 30 + 20 + 10 folded into the tail node.
    try testing.expectEqual(@as(u64, 60), out[2].bytes);
    gpa.free(out[2].name);

    var total: u64 = 0;
    for (out) |n| total += n.bytes;
    try testing.expectEqual(@as(u64, 150), total);
}

test "a string contained in another costs no bytes of its own" {
    const gpa = testing.allocator;
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
    defer {
        for (nodes) |n| gpa.free(n.name);
        gpa.free(nodes);
    }

    // Only the outer string is left; the suffix claims nothing.
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expectEqual(@as(u64, 11), nodes[0].bytes);

    var total: u64 = 0;
    for (nodes) |n| total += n.bytes;
    try testing.expectEqual(@as(u64, h.string_storage_size), total);
}

test "sections and their children reconcile with the file size" {
    const gpa = testing.allocator;
    var b = [_]u8{0} ** 256;
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);

    var h = std.mem.zeroes(hbc.Header);
    h.version = 96;
    h.file_length = b.len;

    const root = try build(gpa, h, &.{}, null, b.len, .{});
    defer gpa.free(root.children);

    var total: u64 = 0;
    for (root.children) |c| total += c.bytes;
    try testing.expectEqual(root.bytes, total);
}
