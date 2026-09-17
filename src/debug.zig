//! The Hermes debug info section: where each function came from in the source.
//!
//! Layout is DebugInfoHeader, a filename table, the filename bytes, the file
//! regions, then the debug data (DebugInfo.cpp, serializeDebugInfo).
//!
//! The obvious way in is each function's `infoOffset`, which points at a record
//! holding its debug offset. That field does not exist on the `static_h` line,
//! so this walks the data instead: every source location record starts with the
//! index of the function it belongs to, which makes the section self describing
//! and the walk work on both bytecode lines.

const std = @import("std");
const hbc = @import("hbc.zig");

/// The two lines disagree on this header. `classic` carries seven words;
/// `static_h` dropped the lexical scope data, the textified callees and the
/// debugger string table, and the three fields that located them, leaving four.
/// Reading 28 bytes off a `static_h` bundle takes the filename table as header
/// fields and every offset after it lands in the wrong place.
pub fn headerSize(format: hbc.Format) usize {
    return switch (format) {
        .classic => 28,
        .static_h => 16,
    };
}

pub const FILENAME_ENTRY_SIZE: usize = 8;
pub const FILE_REGION_SIZE: usize = 12;

pub const Header = struct {
    filename_count: u32,
    filename_storage_size: u32,
    file_region_count: u32,
    debug_data_size: u32,
    /// Source location records occupy the data from 0 up to here. `classic`
    /// stores it as `scopeDescDataOffset`, since the scope data follows the
    /// records inside the same blob. `static_h` has no scope data, so the
    /// records run to the end and this is the whole size.
    locations_end: u32,
    /// `classic` only. Both are zero on `static_h`, which does not carry them.
    textified_callee_offset: u32 = 0,
    string_table_offset: u32 = 0,
};

pub const FileRegion = struct {
    from_address: u32,
    filename_id: u32,
    source_mapping_url_id: u32,
};

pub const Error = error{
    /// The bundle has no debug info, or only the empty header a stripped build
    /// writes.
    NoDebugInfo,
    Truncated,
    /// A record ran past the end of the source location data.
    BadRecord,
};

pub const Info = struct {
    file: []const u8,
    header: Header,
    table_at: usize,
    storage_at: usize,
    regions_at: usize,
    data_at: usize,

    pub fn filename(self: Info, id: u32) ?[]const u8 {
        if (id >= self.header.filename_count) return null;
        const at = self.table_at + id * FILENAME_ENTRY_SIZE;
        const off = std.mem.readInt(u32, self.file[at..][0..4], .little);
        const raw = std.mem.readInt(u32, self.file[at + 4 ..][0..4], .little);
        const is_utf16 = (raw & 0x8000_0000) != 0;
        const len = raw & 0x7FFF_FFFF;
        const bytes: u64 = if (is_utf16) @as(u64, len) * 2 else len;
        if (@as(u64, off) + bytes > self.header.filename_storage_size) return null;
        return self.file[self.storage_at + off ..][0..@intCast(bytes)];
    }

    pub fn region(self: Info, i: u32) ?FileRegion {
        if (i >= self.header.file_region_count) return null;
        const at = self.regions_at + i * FILE_REGION_SIZE;
        return .{
            .from_address = std.mem.readInt(u32, self.file[at..][0..4], .little),
            .filename_id = std.mem.readInt(u32, self.file[at + 4 ..][0..4], .little),
            .source_mapping_url_id = std.mem.readInt(u32, self.file[at + 8 ..][0..4], .little),
        };
    }

    /// Which file a record at `data_offset` belongs to. Metro bundles carry a
    /// single region covering everything, so this is nearly always the same
    /// answer; it is here because the format allows more.
    pub fn filenameForOffset(self: Info, data_offset: u32) ?[]const u8 {
        var found: ?u32 = null;
        var i: u32 = 0;
        while (i < self.header.file_region_count) : (i += 1) {
            const r = self.region(i).?;
            if (r.from_address > data_offset) break;
            found = r.filename_id;
        }
        return if (found) |id| self.filename(id) else null;
    }
};

pub fn init(file: []const u8, h: hbc.Header) Error!Info {
    if (h.debug_info_offset == 0) return error.NoDebugInfo;
    const at: usize = h.debug_info_offset;
    const format = hbc.Format.forVersion(h.version);
    if (at + headerSize(format) > file.len) return error.Truncated;

    var p = at;
    const rd = struct {
        fn f(bytes: []const u8, pos: *usize) u32 {
            const v = std.mem.readInt(u32, bytes[pos.*..][0..4], .little);
            pos.* += 4;
            return v;
        }
    }.f;

    var header = Header{
        .filename_count = rd(file, &p),
        .filename_storage_size = rd(file, &p),
        .file_region_count = rd(file, &p),
        .debug_data_size = 0,
        .locations_end = 0,
    };
    switch (format) {
        .classic => {
            header.locations_end = rd(file, &p);
            header.textified_callee_offset = rd(file, &p);
            header.string_table_offset = rd(file, &p);
            header.debug_data_size = rd(file, &p);
        },
        .static_h => {
            header.debug_data_size = rd(file, &p);
            header.locations_end = header.debug_data_size;
        },
    }

    // A stripped build writes this header with every field zero and nothing
    // after it: 28 bytes on the classic line, 16 on static_h.
    if (header.debug_data_size == 0 and header.filename_count == 0) {
        return error.NoDebugInfo;
    }

    const table_at = p;
    const storage_at = table_at + header.filename_count * FILENAME_ENTRY_SIZE;
    const regions_at = storage_at + header.filename_storage_size;
    const data_at = regions_at + header.file_region_count * FILE_REGION_SIZE;
    if (data_at + header.debug_data_size > file.len) return error.Truncated;

    return .{
        .file = file,
        .header = header,
        .table_at = table_at,
        .storage_at = storage_at,
        .regions_at = regions_at,
        .data_at = data_at,
    };
}

/// Hermes writes these as signed LEB128 and relies on -1 as the end marker for
/// a function's records, so the sign extension matters.
pub fn readSignedLeb(bytes: []const u8, pos: *usize) error{Truncated}!i64 {
    var result: i64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= bytes.len) return error.Truncated;
        const b = bytes[pos.*];
        pos.* += 1;
        result |= @as(i64, b & 0x7F) << shift;
        if (shift < 57) shift += 7;
        if (b & 0x80 == 0) {
            if (shift < 64 and (b & 0x40) != 0) {
                result |= @as(i64, -1) << shift;
            }
            return result;
        }
    }
}

/// One function's source position, as the debug data records it.
pub const Location = struct {
    function_index: u32,
    /// Line and column in the file Hermes compiled, which for a React Native
    /// app is the Metro output, not anyone's source file.
    line: i64,
    column: i64,
    /// Address records after the first, one per statement boundary.
    entries: u32,
    /// Where this record starts in the debug data, which is what the file
    /// region table is indexed by.
    data_offset: u32,
};

pub const WalkResult = struct {
    locations: []Location,
    /// Where the walk stopped. Equal to locations_end when every
    /// record was decoded cleanly, which is the check worth making.
    ended_at: u32,
};

/// Decodes every source location record. Caller owns the returned slice.
pub fn walk(gpa: std.mem.Allocator, info: Info) !WalkResult {
    const end = info.header.locations_end;
    const data = info.file[info.data_at..][0..info.header.debug_data_size];

    var out: std.ArrayList(Location) = .empty;
    errdefer out.deinit(gpa);

    var p: usize = 0;
    while (p < end) {
        const start = p;
        const fn_index = try readSignedLeb(data, &p);
        const line = try readSignedLeb(data, &p);
        const column = try readSignedLeb(data, &p);

        var entries: u32 = 0;
        while (true) {
            if (p >= end) return error.BadRecord;
            const address_delta = try readSignedLeb(data, &p);
            if (address_delta == -1) break;
            // Statement delta rides on the low bit of the line delta.
            const line_delta = try readSignedLeb(data, &p);
            _ = try readSignedLeb(data, &p); // column delta
            _ = try readSignedLeb(data, &p); // scope address
            _ = try readSignedLeb(data, &p); // env register
            if (line_delta & 1 != 0) _ = try readSignedLeb(data, &p);
            entries += 1;
        }

        try out.append(gpa, .{
            .function_index = @intCast(@max(fn_index, 0)),
            .line = line,
            .column = column,
            .entries = entries,
            .data_offset = @intCast(start),
        });
    }

    return .{ .locations = try out.toOwnedSlice(gpa), .ended_at = @intCast(p) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn lebOf(gpa: std.mem.Allocator, values: []const i64) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (values) |v| {
        var x = v;
        var more = true;
        while (more) {
            var byte: u8 = @intCast(x & 0x7F);
            x >>= 7;
            const sign_bit = (byte & 0x40) != 0;
            if ((x == 0 and !sign_bit) or (x == -1 and sign_bit)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            try buf.append(gpa, byte);
        }
    }
    return buf.toOwnedSlice(gpa);
}

test "signed leb round trips through negatives" {
    const gpa = testing.allocator;
    const values = [_]i64{ 0, 1, -1, 63, 64, -64, -65, 127, -128, 300, -300, 1_000_000, -1_000_000 };
    const bytes = try lebOf(gpa, &values);
    defer gpa.free(bytes);

    var p: usize = 0;
    for (values) |want| {
        const got = try readSignedLeb(bytes, &p);
        try testing.expectEqual(want, got);
    }
    try testing.expectEqual(bytes.len, p);
}

test "reading past the end is an error, not a wrong number" {
    var p: usize = 0;
    try testing.expectError(error.Truncated, readSignedLeb(&[_]u8{0x80}, &p));
}

test "a stripped section reads as having no debug info" {
    var b = [_]u8{0} ** 200;
    var h = std.mem.zeroes(hbc.Header);
    h.debug_info_offset = 100;
    try testing.expectError(error.NoDebugInfo, init(&b, h));

    h.debug_info_offset = 0;
    try testing.expectError(error.NoDebugInfo, init(&b, h));
}

/// Builds a debug section with `records` source location records, so the walk
/// can be tested without a 5 MB bundle on disk.
fn synthSection(
    gpa: std.mem.Allocator,
    format: hbc.Format,
    records: []const [3]i64,
) !struct { bytes: []u8, header: hbc.Header } {
    var data: std.ArrayList(u8) = .empty;
    errdefer data.deinit(gpa);

    for (records) |r| {
        const head = try lebOf(gpa, &.{ r[0], r[1], r[2] });
        defer gpa.free(head);
        try data.appendSlice(gpa, head);
        // One address entry, then the -1 that ends the record. The line delta
        // is even so no statement delta follows.
        const entry = try lebOf(gpa, &.{ 4, 2, 0, 0, 0 });
        defer gpa.free(entry);
        try data.appendSlice(gpa, entry);
        const stop = try lebOf(gpa, &.{-1});
        defer gpa.free(stop);
        try data.appendSlice(gpa, stop);
    }

    const name = "bundle.js";
    const debug_at = 256;
    const size = debug_at + headerSize(format) + FILENAME_ENTRY_SIZE + name.len +
        FILE_REGION_SIZE + data.items.len;
    const bytes = try gpa.alloc(u8, size);
    @memset(bytes, 0);

    var p: usize = debug_at;
    const wr = struct {
        fn f(b: []u8, pos: *usize, v: u32) void {
            std.mem.writeInt(u32, b[pos.*..][0..4], v, .little);
            pos.* += 4;
        }
    }.f;
    wr(bytes, &p, 1); // filenameCount
    wr(bytes, &p, @intCast(name.len)); // filenameStorageSize
    wr(bytes, &p, 1); // fileRegionCount
    if (format == .classic) {
        wr(bytes, &p, @intCast(data.items.len)); // scopeDescDataOffset
        wr(bytes, &p, @intCast(data.items.len)); // textifiedCalleeOffset
        wr(bytes, &p, @intCast(data.items.len)); // stringTableOffset
    }
    wr(bytes, &p, @intCast(data.items.len)); // debugDataSize

    wr(bytes, &p, 0); // filename offset
    wr(bytes, &p, @intCast(name.len)); // filename length
    @memcpy(bytes[p..][0..name.len], name);
    p += name.len;

    wr(bytes, &p, 0); // fromAddress
    wr(bytes, &p, 0); // filenameId
    wr(bytes, &p, 0); // sourceMappingUrlId

    @memcpy(bytes[p..][0..data.items.len], data.items);
    data.deinit(gpa);

    var h = std.mem.zeroes(hbc.Header);
    h.version = switch (format) {
        .classic => hbc.CLASSIC_VERSION_MAX,
        .static_h => hbc.CLASSIC_VERSION_MAX + 1,
    };
    h.debug_info_offset = debug_at;
    return .{ .bytes = bytes, .header = h };
}

test "walks every record and lands on the boundary" {
    const gpa = testing.allocator;
    const records = [_][3]i64{ .{ 0, 1, 0 }, .{ 1, 42, 7 }, .{ 2, 1000, 3 } };

    // Both lines, because the header they sit behind is not the same size and
    // reading the wrong one still produces a plausible looking walk.
    for ([_]hbc.Format{ .classic, .static_h }) |format| {
        const s = try synthSection(gpa, format, &records);
        defer gpa.free(s.bytes);

        const info = try init(s.bytes, s.header);
        try testing.expectEqualStrings("bundle.js", info.filename(0).?);
        try testing.expectEqualStrings("bundle.js", info.filenameForOffset(0).?);

        const w = try walk(gpa, info);
        defer gpa.free(w.locations);

        try testing.expectEqual(records.len, w.locations.len);
        // Landing anywhere else means the records were decoded wrong.
        try testing.expectEqual(info.header.locations_end, w.ended_at);

        for (records, w.locations) |want, got| {
            try testing.expectEqual(@as(u32, @intCast(want[0])), got.function_index);
            try testing.expectEqual(want[1], got.line);
            try testing.expectEqual(want[2], got.column);
            try testing.expectEqual(@as(u32, 1), got.entries);
        }
    }
}

test "the static_h header is four words, not seven" {
    const gpa = testing.allocator;
    const records = [_][3]i64{.{ 0, 1, 0 }};
    const s = try synthSection(gpa, .static_h, &records);
    defer gpa.free(s.bytes);

    const info = try init(s.bytes, s.header);
    // Reading 28 bytes here would swallow the filename table and the region,
    // which is what shipped before: a 5.6 MB section decoded as nothing.
    try testing.expectEqual(@as(usize, 256 + 16), info.table_at);
    try testing.expectEqual(info.header.debug_data_size, info.header.locations_end);
    try testing.expectEqual(@as(u32, 0), info.header.textified_callee_offset);
}

test "a record running past the boundary is an error" {
    const gpa = testing.allocator;
    const s = try synthSection(gpa, .classic, &[_][3]i64{.{ 0, 1, 0 }});
    defer gpa.free(s.bytes);

    const info = try init(s.bytes, s.header);
    // Cut the boundary short so the terminator falls outside it.
    var cut = info;
    cut.header.locations_end -= 1;
    try testing.expectError(error.BadRecord, walk(gpa, cut));
}
