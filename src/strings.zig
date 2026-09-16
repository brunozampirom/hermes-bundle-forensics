//! The Hermes string table.
//!
//! Strings live in two places: a fixed 4-byte entry per string, and one shared
//! character buffer. The small entry packs `isUTF16:1, offset:23, length:8`.
//! When a string is longer than 254 bytes or sits past 8 MiB in the buffer, the
//! small entry cannot hold it: `length` is set to 0xFF and `offset` becomes an
//! *index* into the overflow table, which stores the real offset and length as
//! full u32s. That indirection is easy to get wrong — `offset` looks like a
//! byte offset and is not — so it has its own test.

const std = @import("std");
const hbc = @import("hbc.zig");

pub const SMALL_ENTRY_SIZE: u64 = 4;
pub const OVERFLOW_ENTRY_SIZE: u64 = 8;
/// A small entry with this length is a pointer into the overflow table.
pub const INVALID_LENGTH: u32 = 0xFF;

pub const Error = error{
    /// A string section runs past the end of the file.
    TruncatedStringSection,
    /// A string id is not in the table.
    NoSuchString,
    /// An entry points outside the string storage buffer.
    BadStringEntry,
};

pub const Str = struct {
    /// Raw bytes from the storage buffer. For UTF-16 strings these are
    /// little-endian code units, so `bytes.len` is twice `len`.
    bytes: []const u8,
    /// Length in code units, as the table records it.
    len: u32,
    is_utf16: bool,
    /// Whether this string needed an overflow entry.
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
    /// Every string's length added up. This normally *exceeds* the storage
    /// buffer, and that is not a bug: Hermes lays strings out with a suffix
    /// array (`StringPacker` in ConsecutiveStringStorage.cpp) so that a string
    /// which is a suffix of another shares its bytes. The difference is how
    /// much that packing saved.
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

/// Writes a string for human eyes: UTF-16 is decoded per code unit, anything
/// outside printable ASCII is escaped, and the result is capped at `max` so a
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
