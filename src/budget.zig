//! Per-section size budgets, for failing a build instead of noticing later.
//!
//! Section budgets rather than one total: "the bundle grew 40 KB" is not
//! actionable, "debug info came back" is. The finding this tool was written
//! for is a section that should be 28 bytes and was 1.7 MB, and a total-only
//! budget would have absorbed it.
//!
//! A name that matches no section is an error. A budget file quietly checking
//! nothing because of a typo is the one failure mode worth designing against.

const std = @import("std");
const hbc = @import("hbc.zig");

/// Checked against the sum of the file rather than any one section.
pub const TOTAL = "total";

pub const Limit = struct {
    name: []const u8,
    max_bytes: u64,
    line: u32,
};

pub const ParseError = error{
    MissingEquals,
    BadNumber,
    EmptyName,
};

/// Line number and what was wrong with it.
pub const Bad = struct { line: u32, err: ParseError };

pub const ParseResult = union(enum) {
    ok: []Limit,
    bad: Bad,
};

pub fn freeLimits(gpa: std.mem.Allocator, limits: []const Limit) void {
    for (limits) |l| gpa.free(l.name);
    gpa.free(limits);
}

/// Format is `section name = bytes`, one per line, `#` comments, blanks
/// ignored. Underscores are allowed in numbers so 1_000_000 reads as intended.
pub fn parse(gpa: std.mem.Allocator, text: []const u8) !ParseResult {
    var limits: std.ArrayList(Limit) = .empty;
    errdefer {
        for (limits.items) |l| gpa.free(l.name);
        limits.deinit(gpa);
    }

    // A rejected line is a return value rather than an error, so the names
    // parsed before it still have to be released on the way out.
    const bad: ?Bad = blk: {
        var line_no: u32 = 0;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |raw| {
            line_no += 1;
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;

            const eq = std.mem.indexOfScalar(u8, line, '=') orelse
                break :blk .{ .line = line_no, .err = error.MissingEquals };

            const name = std.mem.trim(u8, line[0..eq], " \t");
            if (name.len == 0) break :blk .{ .line = line_no, .err = error.EmptyName };

            const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
            var digits: std.ArrayList(u8) = .empty;
            defer digits.deinit(gpa);
            for (value) |c| {
                if (c == '_') continue;
                try digits.append(gpa, c);
            }
            const max = std.fmt.parseUnsigned(u64, digits.items, 10) catch
                break :blk .{ .line = line_no, .err = error.BadNumber };

            try limits.append(gpa, .{
                .name = try gpa.dupe(u8, name),
                .max_bytes = max,
                .line = line_no,
            });
        }
        break :blk null;
    };

    if (bad) |b| {
        for (limits.items) |l| gpa.free(l.name);
        limits.deinit(gpa);
        return .{ .bad = b };
    }

    return .{ .ok = try limits.toOwnedSlice(gpa) };
}

pub const Row = struct {
    name: []const u8,
    actual: u64,
    max_bytes: u64,
    /// No section carries this name, so nothing was checked.
    unknown: bool,

    pub fn over(self: Row) bool {
        return !self.unknown and self.actual > self.max_bytes;
    }
};

pub const Report = struct {
    rows: []Row,
    failed: u32,
    unknown: u32,
};

pub fn check(
    gpa: std.mem.Allocator,
    limits: []const Limit,
    sections: []const hbc.Section,
    file_size: u64,
) !Report {
    var rows = try gpa.alloc(Row, limits.len);
    var failed: u32 = 0;
    var unknown: u32 = 0;

    for (limits, 0..) |l, i| {
        var actual: u64 = 0;
        var found = false;

        if (std.mem.eql(u8, l.name, TOTAL)) {
            actual = file_size;
            found = true;
        } else for (sections) |s| {
            if (std.mem.eql(u8, s.name, l.name)) {
                actual = s.bytes;
                found = true;
                break;
            }
        }

        rows[i] = .{
            .name = l.name,
            .actual = actual,
            .max_bytes = l.max_bytes,
            .unknown = !found,
        };
        if (!found) unknown += 1 else if (rows[i].over()) failed += 1;
    }

    return .{ .rows = rows, .failed = failed, .unknown = unknown };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parses names with spaces, comments and underscores" {
    const gpa = testing.allocator;
    const text =
        \\# a comment
        \\total = 4_000_000
        \\
        \\debug info   =   1024
        \\
    ;
    const res = try parse(gpa, text);
    const limits = res.ok;
    defer freeLimits(gpa, limits);

    try testing.expectEqual(@as(usize, 2), limits.len);
    try testing.expectEqualStrings("total", limits[0].name);
    try testing.expectEqual(@as(u64, 4_000_000), limits[0].max_bytes);
    try testing.expectEqualStrings("debug info", limits[1].name);
    try testing.expectEqual(@as(u64, 1024), limits[1].max_bytes);
}

test "reports the line a bad entry is on" {
    const gpa = testing.allocator;
    const res = try parse(gpa, "total = 10\nbroken line\n");
    try testing.expectEqual(@as(u32, 2), res.bad.line);
    try testing.expectEqual(ParseError.MissingEquals, res.bad.err);

    const res2 = try parse(gpa, "total = not a number\n");
    try testing.expectEqual(ParseError.BadNumber, res2.bad.err);
}

test "a name matching no section is flagged, not silently passed" {
    const gpa = testing.allocator;
    const sections = [_]hbc.Section{
        .{ .name = "debug info", .bytes = 28 },
        .{ .name = "string storage", .bytes = 900 },
    };
    const limits = [_]Limit{
        .{ .name = "debug info", .max_bytes = 1024, .line = 1 },
        .{ .name = "debgu info", .max_bytes = 1024, .line = 2 },
    };

    const r = try check(gpa, &limits, &sections, 5000);
    defer gpa.free(r.rows);

    try testing.expectEqual(@as(u32, 1), r.unknown);
    try testing.expectEqual(@as(u32, 0), r.failed);
    try testing.expect(r.rows[1].unknown);
}

test "over budget is counted and under is not" {
    const gpa = testing.allocator;
    const sections = [_]hbc.Section{.{ .name = "debug info", .bytes = 1_722_956 }};
    const limits = [_]Limit{
        .{ .name = "debug info", .max_bytes = 1024, .line = 1 },
        .{ .name = TOTAL, .max_bytes = 10_000_000, .line = 2 },
    };

    const r = try check(gpa, &limits, &sections, 5_776_448);
    defer gpa.free(r.rows);

    try testing.expectEqual(@as(u32, 1), r.failed);
    try testing.expect(r.rows[0].over());
    try testing.expect(!r.rows[1].over());
    try testing.expectEqual(@as(u64, 5_776_448), r.rows[1].actual);
}
