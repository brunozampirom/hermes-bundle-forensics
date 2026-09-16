//! The Hermes string table: a 4-byte entry per string packing
//! `isUTF16:1, offset:23, length:8`, plus one shared character buffer.
//!
//! When a string does not fit those widths, `length` is 0xFF and `offset`
//! becomes an *index* into the overflow table rather than a byte offset.

const std = @import("std");
const hbc = @import("hbc.zig");

pub const SMALL_ENTRY_SIZE: u64 = 4;
pub const OVERFLOW_ENTRY_SIZE: u64 = 8;
/// A small entry with this length points into the overflow table.
pub const INVALID_LENGTH: u32 = 0xFF;

pub const Error = error{
    TruncatedStringSection,
    NoSuchString,
    BadStringEntry,
};

pub const Str = struct {
    /// For UTF-16 these are little-endian code units, so `len` is half of
    /// `bytes.len`.
    bytes: []const u8,
    len: u32,
    is_utf16: bool,
    overflowed: bool,
};

pub const Table = struct {
    file: []const u8,
    table_at: usize,
    overflow_at: usize,
    storage_at: usize,
    storage_size: u32,
    count: u32,
    overflow_count: u32,

    pub fn init(file: []const u8, h: hbc.Header) Error!Table {
        const l = hbc.layout(h);
        const storage_end = l.string_storage + h.string_storage_size;
        if (storage_end > file.len) return error.TruncatedStringSection;

        return .{
            .file = file,
            .table_at = @intCast(l.string_table),
            .overflow_at = @intCast(l.overflow_string_table),
            .storage_at = @intCast(l.string_storage),
            .storage_size = h.string_storage_size,
            .count = h.string_count,
            .overflow_count = h.overflow_string_count,
        };
    }

    pub fn get(self: Table, id: u32) Error!Str {
        if (id >= self.count) return error.NoSuchString;

        const at = self.table_at + @as(usize, id) * SMALL_ENTRY_SIZE;
        const w = std.mem.readInt(u32, self.file[at..][0..4], .little);
        const is_utf16 = (w & 1) != 0;
        var offset: u32 = (w >> 1) & 0x7F_FFFF; // 23 bits
        var len: u32 = w >> 24; // 8 bits
        var overflowed = false;

        if (len == INVALID_LENGTH) {
            // `offset` is an index into the overflow table, not a byte offset.
            if (offset >= self.overflow_count) return error.BadStringEntry;
            const oat = self.overflow_at + @as(usize, offset) * OVERFLOW_ENTRY_SIZE;
            offset = std.mem.readInt(u32, self.file[oat..][0..4], .little);
            len = std.mem.readInt(u32, self.file[oat + 4 ..][0..4], .little);
            overflowed = true;
        }

        const byte_len: u64 = if (is_utf16) @as(u64, len) * 2 else @as(u64, len);
        if (@as(u64, offset) + byte_len > self.storage_size) return error.BadStringEntry;

        const start = self.storage_at + offset;
        return .{
            .bytes = self.file[start..][0..@intCast(byte_len)],
            .len = len,
            .is_utf16 = is_utf16,
            .overflowed = overflowed,
        };
    }
};

pub const Stats = struct {
    /// Normally *exceeds* the storage buffer, and that is not a bug: Hermes
    /// packs strings with a suffix array (ConsecutiveStringStorage.cpp) so a
    /// string that is a suffix of another shares its bytes.
    sum_of_lengths: u64,
    utf16_strings: u32,
    utf16_bytes: u64,
    overflowed: u32,
    unreadable: u32,
};

pub fn stats(t: Table) Stats {
    var s = Stats{
        .sum_of_lengths = 0,
        .utf16_strings = 0,
        .utf16_bytes = 0,
        .overflowed = 0,
        .unreadable = 0,
    };

    var id: u32 = 0;
    while (id < t.count) : (id += 1) {
        const str = t.get(id) catch {
            s.unreadable += 1;
            continue;
        };
        s.sum_of_lengths += str.bytes.len;
        if (str.is_utf16) {
            s.utf16_strings += 1;
            s.utf16_bytes += str.bytes.len;
        }
        if (str.overflowed) s.overflowed += 1;
    }

    return s;
}

/// Escapes anything outside printable ASCII and caps the result at `max`, so a
/// minified blob cannot flood the report.
pub fn writeEscaped(out: *std.Io.Writer, str: Str, max: usize) !void {
    var written: usize = 0;
    var i: usize = 0;

    while (i < str.bytes.len) {
        if (written >= max) {
            try out.print("...", .{});
            return;
        }
        var c: u32 = undefined;
        if (str.is_utf16) {
            c = std.mem.readInt(u16, str.bytes[i..][0..2], .little);
            i += 2;
        } else {
            c = str.bytes[i];
            i += 1;
        }

        if (c >= 0x20 and c <= 0x7E) {
            try out.print("{c}", .{@as(u8, @intCast(c))});
        } else switch (c) {
            '\n' => try out.print("\\n", .{}),
            '\r' => try out.print("\\r", .{}),
            '\t' => try out.print("\\t", .{}),
            else => try out.print("\\u{x:0>4}", .{c}),
        }
        written += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// Two strings: a plain one, and one whose small entry overflows. The overflow
// entry's index lives in the small entry's `offset` field, which is the part
// that reads like a byte offset and is not.
test "resolves strings through the overflow table" {
    const storage_at = 144;
    var b = [_]u8{0} ** (storage_at + 400);
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);

    var h = std.mem.zeroes(hbc.Header);
    h.string_count = 2;
    h.overflow_string_count = 1;
    h.string_storage_size = 305;

    const l = hbc.layout(h);
    try testing.expectEqual(@as(u64, 128), l.string_table);
    try testing.expectEqual(@as(u64, 136), l.overflow_string_table);
    try testing.expectEqual(@as(u64, storage_at), l.string_storage);

    // entry 0: offset 0, length 5, ascii
    std.mem.writeInt(u32, b[128..][0..4], (5 << 24) | (0 << 1), .little);
    // entry 1: length 0xFF marks overflow; offset field holds index 0
    std.mem.writeInt(u32, b[132..][0..4], (0xFF << 24) | (0 << 1), .little);
    // overflow entry 0: real offset 5, real length 300
    std.mem.writeInt(u32, b[136..][0..4], 5, .little);
    std.mem.writeInt(u32, b[140..][0..4], 300, .little);
    @memcpy(b[storage_at..][0..5], "hello");
    @memset(b[storage_at + 5 ..][0..300], 'x');

    const t = try Table.init(&b, h);

    const s0 = try t.get(0);
    try testing.expectEqualStrings("hello", s0.bytes);
    try testing.expect(!s0.overflowed);
    try testing.expect(!s0.is_utf16);

    const s1 = try t.get(1);
    try testing.expectEqual(@as(usize, 300), s1.bytes.len);
    try testing.expect(s1.overflowed);
    try testing.expectEqual(@as(u8, 'x'), s1.bytes[0]);

    try testing.expectError(error.NoSuchString, t.get(2));

    const st = stats(t);
    try testing.expectEqual(@as(u64, 305), st.sum_of_lengths);
    try testing.expectEqual(@as(u32, 1), st.overflowed);
    try testing.expectEqual(@as(u32, 0), st.unreadable);
}

test "utf-16 strings cost two bytes per code unit" {
    const storage_at = 132;
    var b = [_]u8{0} ** (storage_at + 16);
    var h = std.mem.zeroes(hbc.Header);
    h.string_count = 1;
    h.string_storage_size = 8;

    // offset 0, length 4 code units, isUTF16 set
    std.mem.writeInt(u32, b[128..][0..4], (4 << 24) | (0 << 1) | 1, .little);
    for ([_]u16{ 'a', 'b', 0x00E9, 0x2603 }, 0..) |cu, i| {
        std.mem.writeInt(u16, b[storage_at + i * 2 ..][0..2], cu, .little);
    }

    const t = try Table.init(&b, h);
    const s = try t.get(0);
    try testing.expect(s.is_utf16);
    try testing.expectEqual(@as(u32, 4), s.len);
    try testing.expectEqual(@as(usize, 8), s.bytes.len);

    const st = stats(t);
    try testing.expectEqual(@as(u64, 8), st.utf16_bytes);
    try testing.expectEqual(@as(u32, 1), st.utf16_strings);
}

test "rejects a string entry pointing outside storage" {
    var b = [_]u8{0} ** 160;
    var h = std.mem.zeroes(hbc.Header);
    h.string_count = 1;
    h.string_storage_size = 4;
    // offset 2, length 10 -> runs past the 4-byte storage
    std.mem.writeInt(u32, b[128..][0..4], (10 << 24) | (2 << 1), .little);

    const t = try Table.init(&b, h);
    try testing.expectError(error.BadStringEntry, t.get(0));
}
