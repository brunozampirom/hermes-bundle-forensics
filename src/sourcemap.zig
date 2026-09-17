//! Reading a Hermes source map well enough to say which file a byte of
//! bytecode came from.
//!
//! Hermes puts every mapping on one generated line whose column is the byte
//! offset into the bytecode region, so a lookup is a binary search over the
//! decoded segments rather than anything line oriented. The map that ships
//! alongside a React Native release is Metro's composed with Hermes's, which
//! means `sources` holds the original module paths.
//!
//! This is deliberately not a general source map library. It reads `sources`
//! and `mappings` and ignores everything else, because everything else is
//! irrelevant to attributing bytes.

const std = @import("std");

pub const Error = error{
    NoMappings,
    NoSources,
    BadVlq,
    /// A `mappings` string using more than one generated line is not a Hermes
    /// bytecode map, and treating it as one would attribute bytes at random.
    NotAHermesMap,
};

pub const Segment = struct {
    /// Byte offset into the bytecode region.
    offset: u32,
    source: u32,
    line: u32,
    column: u32,
};

pub const Map = struct {
    /// Owned by the arena the caller passed to `parse`.
    sources: [][]const u8,
    segments: []Segment,

    /// The file a given bytecode offset belongs to, or null when the offset
    /// falls before the first mapping.
    pub fn sourceFor(self: Map, offset: u32) ?[]const u8 {
        const i = self.segmentFor(offset) orelse return null;
        const s = self.segments[i].source;
        return if (s < self.sources.len) self.sources[s] else null;
    }

    /// Index of the last segment at or before `offset`.
    pub fn segmentFor(self: Map, offset: u32) ?usize {
        if (self.segments.len == 0 or self.segments[0].offset > offset) return null;
        var lo: usize = 0;
        var hi: usize = self.segments.len;
        while (lo + 1 < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.segments[mid].offset <= offset) lo = mid else hi = mid;
        }
        return lo;
    }
};

const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64Value(c: u8) ?u6 {
    const i = std.mem.indexOfScalar(u8, b64, c) orelse return null;
    return @intCast(i);
}

/// Base64 VLQ: five bits of payload per character, bit 5 continues, and the
/// low bit of the assembled value is the sign.
fn readVlq(s: []const u8, pos: *usize) Error!i64 {
    var result: i64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= s.len) return error.BadVlq;
        const d = b64Value(s[pos.*]) orelse return error.BadVlq;
        pos.* += 1;
        result |= @as(i64, d & 31) << shift;
        if (d & 32 == 0) break;
        if (shift > 56) return error.BadVlq;
        shift += 5;
    }
    const negative = result & 1 != 0;
    result >>= 1;
    return if (negative) -result else result;
}

/// Skips the string starting at `at`, which must be its opening quote, and
/// returns the index just past its closing quote.
fn skipString(json: []const u8, at: usize) usize {
    var i = at + 1;
    while (i < json.len) : (i += 1) {
        if (json[i] == '\\') {
            i += 1;
            continue;
        }
        if (json[i] == '"') return i + 1;
    }
    return json.len;
}

/// Finds a key of the outermost object and returns its raw value.
///
/// Searching for `"mappings"` as a substring finds the wrong thing: a composed
/// map carries a `names` array of minified identifiers, and one of them in a
/// real React Native bundle is the word mappings. So this tracks nesting and
/// only accepts a string that sits at depth one and is followed by a colon.
fn findTopLevelValue(json: []const u8, name: []const u8) ?[]const u8 {
    var at: usize = 0;
    while (at < json.len and json[at] != '{') at += 1;
    if (at >= json.len) return null;
    at += 1;

    var depth: usize = 1;
    while (at < json.len) {
        const c = json[at];
        if (c == '"') {
            const end = skipString(json, at);
            if (depth == 1) {
                const key = json[at + 1 .. end - 1];
                var j = end;
                while (j < json.len and (json[j] == ' ' or json[j] == '\t')) j += 1;
                if (j < json.len and json[j] == ':' and std.mem.eql(u8, key, name)) {
                    j += 1;
                    while (j < json.len and (json[j] == ' ' or json[j] == '\t')) j += 1;
                    return valueAt(json, j);
                }
            }
            at = end;
            continue;
        }
        switch (c) {
            '{', '[' => depth += 1,
            '}', ']' => {
                if (depth == 0) return null;
                depth -= 1;
                if (depth == 0) return null;
            },
            else => {},
        }
        at += 1;
    }
    return null;
}

/// The raw text of the value starting at `at`, brackets included.
fn valueAt(json: []const u8, at: usize) ?[]const u8 {
    if (at >= json.len) return null;
    switch (json[at]) {
        '"' => return json[at..skipString(json, at)],
        '[', '{' => {
            const open = json[at];
            const close: u8 = if (open == '[') ']' else '}';
            var depth: usize = 0;
            var i = at;
            while (i < json.len) {
                const c = json[i];
                if (c == '"') {
                    i = skipString(json, i);
                    continue;
                }
                if (c == open) depth += 1;
                if (c == close) {
                    depth -= 1;
                    if (depth == 0) return json[at .. i + 1];
                }
                i += 1;
            }
            return null;
        },
        else => return null,
    }
}

fn findStringField(json: []const u8, name: []const u8) ?[]const u8 {
    const raw = findTopLevelValue(json, name) orelse return null;
    if (raw.len < 2 or raw[0] != '"') return null;
    return raw[1 .. raw.len - 1];
}

fn findArrayField(json: []const u8, name: []const u8) ?[]const u8 {
    const raw = findTopLevelValue(json, name) orelse return null;
    if (raw.len < 2 or raw[0] != '[') return null;
    return raw;
}

/// Splits a JSON array of strings. Only the escapes a file path can contain
/// are unescaped, which on Windows means backslashes and little else.
fn parseStringArray(gpa: std.mem.Allocator, array: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);

    var at: usize = 1; // skip [
    while (at < array.len) {
        while (at < array.len and array[at] != '"' and array[at] != ']') at += 1;
        if (at >= array.len or array[at] == ']') break;
        at += 1;

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(gpa);
        while (at < array.len and array[at] != '"') {
            if (array[at] == '\\' and at + 1 < array.len) {
                at += 1;
                try buf.append(gpa, switch (array[at]) {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    else => array[at],
                });
            } else {
                try buf.append(gpa, array[at]);
            }
            at += 1;
        }
        at += 1;
        try out.append(gpa, try buf.toOwnedSlice(gpa));
    }

    return out.toOwnedSlice(gpa);
}

pub fn parse(gpa: std.mem.Allocator, json: []const u8) !Map {
    const mappings = findStringField(json, "mappings") orelse return error.NoMappings;
    const sources_array = findArrayField(json, "sources") orelse return error.NoSources;
    const sources = try parseStringArray(gpa, sources_array);

    var segments: std.ArrayList(Segment) = .empty;
    errdefer segments.deinit(gpa);

    var column: i64 = 0;
    var source: i64 = 0;
    var line: i64 = 0;
    var src_column: i64 = 0;
    var generated_lines: usize = 0;

    var at: usize = 0;
    while (at < mappings.len) {
        const c = mappings[at];
        if (c == ';') {
            generated_lines += 1;
            // A Hermes bytecode map is one line. More than one means this is a
            // JavaScript map, where a column is a character and not a byte.
            if (generated_lines > 1 and segments.items.len > 0) return error.NotAHermesMap;
            column = 0;
            at += 1;
            continue;
        }
        if (c == ',') {
            at += 1;
            continue;
        }

        const fields = try readFields(mappings, &at);
        column += fields.values[0];
        if (fields.count >= 4) {
            source += fields.values[1];
            line += fields.values[2];
            src_column += fields.values[3];
            try segments.append(gpa, .{
                .offset = @intCast(@max(column, 0)),
                .source = @intCast(@max(source, 0)),
                .line = @intCast(@max(line, 0) + 1),
                .column = @intCast(@max(src_column, 0)),
            });
        }
    }

    const segs = try segments.toOwnedSlice(gpa);
    std.sort.pdq(Segment, segs, {}, byOffset);
    return .{ .sources = sources, .segments = segs };
}

fn byOffset(_: void, a: Segment, b: Segment) bool {
    return a.offset < b.offset;
}

const Fields = struct { values: [5]i64, count: usize };

fn readFields(s: []const u8, at: *usize) Error!Fields {
    var f = Fields{ .values = .{ 0, 0, 0, 0, 0 }, .count = 0 };
    while (at.* < s.len and s[at.*] != ',' and s[at.*] != ';') {
        if (f.count == 5) return error.BadVlq;
        f.values[f.count] = try readVlq(s, at);
        f.count += 1;
    }
    if (f.count == 0) return error.BadVlq;
    return f;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "decodes the map hermesc emits" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Verbatim from `hermesc -emit-binary -output-source-map` on a four line
    // file; the generated columns are byte offsets into the bytecode.
    const json =
        \\{"version":3,"sources":["probe.js"],"mappings":"AAAA,YAAA,OAAA,MAAA,KAAA,MAEY,QAAW,KAAC,KAAD,KACvB,MAAe,MAAK,EAHpB,MAA8B,IAAP,EACvB,EAA0B,aAAK,SAAL,IAAP;","x_hermes_function_offsets":{"0":[0,73,85]}}
    ;

    const map = try parse(gpa, json);
    try testing.expectEqual(@as(usize, 1), map.sources.len);
    try testing.expectEqualStrings("probe.js", map.sources[0]);
    try testing.expectEqual(@as(usize, 20), map.segments.len);

    // The two function starts hermesc listed separately have to be present.
    try testing.expectEqual(@as(u32, 0), map.segments[0].offset);
    var has73 = false;
    var has85 = false;
    for (map.segments) |s| {
        if (s.offset == 73) has73 = true;
        if (s.offset == 85) has85 = true;
    }
    try testing.expect(has73);
    try testing.expect(has85);

    // Offset 73 is `function alpha` on the first line of the source.
    try testing.expectEqualStrings("probe.js", map.sourceFor(73).?);
    const i = map.segmentFor(73).?;
    try testing.expectEqual(@as(u32, 1), map.segments[i].line);

    // A byte inside a function resolves to that function's segment or a later
    // one within it, never to the next function's.
    try testing.expect(map.segmentFor(74).? >= i);
}

test "rejects a javascript map, where a column is a character" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const json =
        \\{"version":3,"sources":["a.js","b.js"],"mappings":"AAAA;AACA;AACA"}
    ;
    try testing.expectError(error.NotAHermesMap, parse(gpa, json));
}

test "binary search lands on the last segment at or before the offset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const segs = try gpa.alloc(Segment, 4);
    for ([_]u32{ 0, 10, 20, 30 }, 0..) |off, i| {
        segs[i] = .{ .offset = off, .source = 0, .line = 1, .column = 0 };
    }
    const names = try gpa.alloc([]const u8, 1);
    names[0] = "x.js";
    const map = Map{ .sources = names, .segments = segs };

    try testing.expectEqual(@as(usize, 0), map.segmentFor(0).?);
    try testing.expectEqual(@as(usize, 0), map.segmentFor(9).?);
    try testing.expectEqual(@as(usize, 1), map.segmentFor(10).?);
    try testing.expectEqual(@as(usize, 3), map.segmentFor(30).?);
    try testing.expectEqual(@as(usize, 3), map.segmentFor(9999).?);
}

test "an empty or malformed map is an error, not an empty answer" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    try testing.expectError(error.NoMappings, parse(gpa, "{\"version\":3}"));
    try testing.expectError(error.NoSources, parse(gpa, "{\"mappings\":\"AAAA\"}"));
}

test "a key word appearing in the names array is not mistaken for the field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // A real composed map carries minified identifiers in `names`, and one of
    // them in a React Native bundle is the word mappings. Searching for the
    // substring finds that one first.
    const json =
        \\{"version":3,"sources":["a.js"],"names":["mappings","sources"],"mappings":"AAAA,ICAA"}
    ;
    const map = try parse(gpa, json);
    try testing.expectEqual(@as(usize, 2), map.segments.len);
    try testing.expectEqualStrings("a.js", map.sources[0]);
}

test "fields are read regardless of their order in the object" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const json =
        \\{"mappings":"AAAA","names":[],"sourcesContent":["x"],"sources":["z.js"],"version":3}
    ;
    const map = try parse(gpa, json);
    try testing.expectEqualStrings("z.js", map.sources[0]);
    try testing.expectEqual(@as(usize, 1), map.segments.len);
}
