//! Parser for the Hermes bytecode (HBC) file format, following
//! `include/hermes/BCGen/HBC/BytecodeFileFormat.h` in facebook/hermes.
//!
//! Parsed field by field rather than through an `extern struct`: relying on the
//! compiler's ABI would hide the layout mismatches this tool exists to find.

const std = @import("std");

pub const MAGIC: u64 = 0x1F1903C103BC1FC6;
/// The "delta prepped" form: same file, inverted magic.
pub const DELTA_MAGIC: u64 = ~MAGIC;

pub const HEADER_SIZE: usize = 128;
pub const SHA1_NUM_BYTES: usize = 20;
pub const FOOTER_SIZE: usize = SHA1_NUM_BYTES;

/// Each section is padded to this before it starts (BytecodeStream.cpp).
pub const ALIGNMENT: u64 = 4;

/// Two bytecode lines are in the wild and they disagree about the function
/// header layout.
///
/// `facebook/hermes` main tops out at 96. React Native does not ship that one:
/// since Hermes V1 became the default it ships the `static_h` line, which emits
/// 98 and up. `RCT_HERMES_V1_ENABLED=0` opts back into the 96 line.
///
/// Below 90 some file header fields do not exist, so we refuse rather than read
/// garbage.
pub const VERSION_MIN: u32 = 90;
pub const CLASSIC_VERSION_MAX: u32 = 96;
pub const VERSION_MAX: u32 = 99;

pub const Format = enum {
    /// Bytecode 90 to 96, `facebook/hermes` main.
    classic,
    /// Bytecode 97 and up, the `static_h` line that React Native ships.
    static_h,

    pub fn forVersion(version: u32) Format {
        return if (version <= CLASSIC_VERSION_MAX) .classic else .static_h;
    }

    /// Entry size in the function header table.
    pub fn funcHeaderSize(self: Format) u64 {
        return switch (self) {
            // Four little-endian words of bitfields.
            .classic => 16,
            // Two words plus three bytes plus flags: the third word went away
            // when `infoOffset` was dropped from the field list.
            .static_h => 12,
        };
    }

    /// Size of the overflow form, same fields at full width.
    pub fn largeFuncHeaderSize(self: Format) u64 {
        return switch (self) {
            // 7 * u32 + 2 * u8 + flags.
            .classic => 31,
            // 8 * u32 + 3 * u8 + flags.
            .static_h => 36,
        };
    }
};

pub const Options = packed struct(u8) {
    static_builtins: bool,
    cjs_modules_statically_resolved: bool,
    has_async: bool,
    _reserved: u5,
};

pub const Header = struct {
    magic: u64,
    version: u32,
    source_hash: [SHA1_NUM_BYTES]u8,
    file_length: u32,
    global_code_index: u32,
    function_count: u32,
    string_kind_count: u32,
    identifier_count: u32,
    string_count: u32,
    overflow_string_count: u32,
    string_storage_size: u32,
    bigint_count: u32,
    bigint_storage_size: u32,
    regexp_count: u32,
    regexp_storage_size: u32,
    /// `arrayBufferSize` on the classic line, `literalValueBufferSize` on
    /// `static_h`. Same slot, and a byte count either way.
    array_buffer_size: u32,
    obj_key_buffer_size: u32,
    /// `objValueBufferSize`, a byte count, on the classic line.
    /// `objShapeTableCount`, an entry count, on `static_h`. Use
    /// `objValueSectionSize` rather than reading this directly.
    obj_value_buffer_size: u32,
    /// `static_h` only. The classic line has no such field.
    num_string_switch_imms: u32,
    segment_id: u32,
    cjs_module_count: u32,
    function_source_count: u32,
    debug_info_offset: u32,
    options: Options,
};

pub const ParseError = error{
    TooSmall,
    BadMagic,
    DeltaPrepped,
    UnsupportedVersion,
};

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn u64le(self: *Cursor) u64 {
        const v = std.mem.readInt(u64, self.bytes[self.pos..][0..8], .little);
        self.pos += 8;
        return v;
    }

    fn u32le(self: *Cursor) u32 {
        const v = std.mem.readInt(u32, self.bytes[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }

    fn u8v(self: *Cursor) u8 {
        const v = self.bytes[self.pos];
        self.pos += 1;
        return v;
    }

    fn array(self: *Cursor, comptime n: usize) [n]u8 {
        const v = self.bytes[self.pos..][0..n].*;
        self.pos += n;
        return v;
    }
};

pub fn parseHeader(bytes: []const u8) ParseError!Header {
    if (bytes.len < HEADER_SIZE) return error.TooSmall;

    var c = Cursor{ .bytes = bytes };
    const magic = c.u64le();
    if (magic == DELTA_MAGIC) return error.DeltaPrepped;
    if (magic != MAGIC) return error.BadMagic;

    const version = c.u32le();
    if (version < VERSION_MIN or version > VERSION_MAX) return error.UnsupportedVersion;

    const h = Header{
        .magic = magic,
        .version = version,
        .source_hash = c.array(SHA1_NUM_BYTES),
        .file_length = c.u32le(),
        .global_code_index = c.u32le(),
        .function_count = c.u32le(),
        .string_kind_count = c.u32le(),
        .identifier_count = c.u32le(),
        .string_count = c.u32le(),
        .overflow_string_count = c.u32le(),
        .string_storage_size = c.u32le(),
        .bigint_count = c.u32le(),
        .bigint_storage_size = c.u32le(),
        .regexp_count = c.u32le(),
        .regexp_storage_size = c.u32le(),
        .array_buffer_size = c.u32le(),
        .obj_key_buffer_size = c.u32le(),
        .obj_value_buffer_size = c.u32le(),
        // `static_h` inserted a field here and shrank the trailing padding to
        // keep the header at 128 bytes. Everything after it shifts by 4.
        .num_string_switch_imms = if (Format.forVersion(version) == .static_h) c.u32le() else 0,
        .segment_id = c.u32le(),
        .cjs_module_count = c.u32le(),
        .function_source_count = c.u32le(),
        .debug_info_offset = c.u32le(),
        .options = @bitCast(c.u8v()),
    };

    // Fields plus the options byte; the rest up to 128 is padding, which
    // `static_h` shortened by the four bytes its extra field takes.
    const fields_end: usize = switch (Format.forVersion(version)) {
        .classic => 109,
        .static_h => 113,
    };
    std.debug.assert(c.pos == fields_end);
    return h;
}

// ---------------------------------------------------------------------------
// Function headers
// ---------------------------------------------------------------------------

pub const FunctionFlags = packed struct(u8) {
    /// Which kinds of call are prohibited (ProhibitCall/Construct/None).
    prohibit_invoke: u2,
    strict_mode: bool,
    has_exception_handler: bool,
    has_debug_info: bool,
    overflowed: bool,
    _reserved: u2,
};

pub const Function = struct {
    index: u32,
    offset: u32,
    param_count: u32,
    bytecode_size: u32,
    /// Index into the string table; resolve it with `strings.zig`.
    name_id: u32,
    info_offset: u32,
    frame_size: u32,
    environment_size: u32,
    flags: FunctionFlags,
    /// Values came from a large header elsewhere in the file.
    from_large_header: bool,
};

pub const FunctionError = error{
    TruncatedFunctionTable,
    BadLargeHeaderOffset,
};

/// Entries in the `static_h` object shape table; the classic line stores a
/// byte count in that slot instead.
pub const SHAPE_TABLE_ENTRY_SIZE: u64 = 8;

/// Bytes held by the third literal section, whichever form it takes.
pub fn objValueSectionSize(h: Header) u64 {
    return switch (Format.forVersion(h.version)) {
        .classic => h.obj_value_buffer_size,
        .static_h => @as(u64, h.obj_value_buffer_size) * SHAPE_TABLE_ENTRY_SIZE,
    };
}

pub fn functionTableSize(h: Header) u64 {
    return @as(u64, h.function_count) * Format.forVersion(h.version).funcHeaderSize();
}

/// Reads one function header, following the overflow indirection when the
/// small header could not hold the real values.
pub fn parseFunction(bytes: []const u8, h: Header, index: u32) FunctionError!Function {
    const fmt = Format.forVersion(h.version);
    const entry = fmt.funcHeaderSize();
    const base = HEADER_SIZE + @as(u64, index) * entry;
    if (base + entry > bytes.len) return error.TruncatedFunctionTable;

    const at: usize = @intCast(base);
    var f = switch (fmt) {
        .classic => parseSmallClassic(bytes, at, index),
        .static_h => parseSmallStaticH(bytes, at, index),
    };

    if (!f.flags.overflowed) return f;

    const large_at = largeHeaderOffset(fmt, f);
    if (large_at + fmt.largeFuncHeaderSize() > bytes.len) return error.BadLargeHeaderOffset;

    var c = Cursor{ .bytes = bytes, .pos = @intCast(large_at) };
    switch (fmt) {
        .classic => {
            f.offset = c.u32le();
            f.param_count = c.u32le();
            f.bytecode_size = c.u32le();
            f.name_id = c.u32le();
            f.info_offset = c.u32le();
            f.frame_size = c.u32le();
            f.environment_size = c.u32le();
            _ = c.u8v(); // highestReadCacheIndex
            _ = c.u8v(); // highestWriteCacheIndex
        },
        .static_h => {
            f.offset = c.u32le();
            f.param_count = c.u32le();
            _ = c.u32le(); // loopDepth
            f.bytecode_size = c.u32le();
            f.name_id = c.u32le();
            _ = c.u32le(); // numberRegCount
            _ = c.u32le(); // nonPtrRegCount
            f.frame_size = c.u32le();
            _ = c.u8v(); // readCacheSize
            _ = c.u8v(); // writeCacheSize
            _ = c.u8v(); // privateNameCacheSize
        },
    }
    f.flags = @bitCast(c.u8v());
    f.from_large_header = true;
    return f;
}

/// Where the large header lives, recovered from the small header fields that
/// were reused to store it. Classic splits it 16/16 across `infoOffset` and
/// `offset`. The `static_h` line has no `infoOffset`, so it splits it 24/8
/// across `offset` and `functionName`.
fn largeHeaderOffset(fmt: Format, f: Function) u64 {
    return switch (fmt) {
        .classic => (@as(u64, f.info_offset) << 16) | @as(u64, f.offset),
        .static_h => (@as(u64, f.name_id) << 24) | @as(u64, f.offset),
    };
}

fn parseSmallClassic(bytes: []const u8, at: usize, index: u32) Function {
    const w0 = std.mem.readInt(u32, bytes[at..][0..4], .little);
    const w1 = std.mem.readInt(u32, bytes[at + 4 ..][0..4], .little);
    const w2 = std.mem.readInt(u32, bytes[at + 8 ..][0..4], .little);
    const w3 = std.mem.readInt(u32, bytes[at + 12 ..][0..4], .little);

    return .{
        .index = index,
        .offset = w0 & 0x01FF_FFFF, // 25 bits
        .param_count = w0 >> 25, // 7 bits
        .bytecode_size = w1 & 0x7FFF, // 15 bits
        .name_id = w1 >> 15, // 17 bits
        .info_offset = w2 & 0x01FF_FFFF, // 25 bits
        .frame_size = w2 >> 25, // 7 bits
        .environment_size = w3 & 0xFF,
        .flags = @bitCast(@as(u8, @truncate(w3 >> 24))),
        .from_large_header = false,
    };
}

/// The `static_h` small header: two words of bitfields, then three bytes, then
/// flags. `infoOffset` and `environmentSize` no longer exist, and the fields
/// that took their place (loop depth, register counts, cache sizes) are not
/// needed for a size report, so they are read and dropped.
fn parseSmallStaticH(bytes: []const u8, at: usize, index: u32) Function {
    const w0 = std.mem.readInt(u32, bytes[at..][0..4], .little);
    const w1 = std.mem.readInt(u32, bytes[at + 4 ..][0..4], .little);
    const frame_size = bytes[at + 8];
    const flags: FunctionFlags = @bitCast(bytes[at + 11]);

    return .{
        .index = index,
        .offset = w0 & 0x01FF_FFFF, // 25 bits
        .param_count = (w0 >> 25) & 0x1F, // 5 bits
        .bytecode_size = w1 & 0x3FFF, // 14 bits
        .name_id = (w1 >> 14) & 0xFF, // 8 bits
        .info_offset = 0, // not in this layout
        .frame_size = frame_size,
        .environment_size = 0, // not in this layout
        .flags = flags,
        .from_large_header = false,
    };
}

/// Caller owns the returned slice.
pub fn parseFunctions(
    gpa: std.mem.Allocator,
    bytes: []const u8,
    h: Header,
) (FunctionError || std.mem.Allocator.Error)![]Function {
    const list = try gpa.alloc(Function, h.function_count);
    errdefer gpa.free(list);
    for (list, 0..) |*slot, i| slot.* = try parseFunction(bytes, h, @intCast(i));
    return list;
}

pub const BytecodeStats = struct {
    /// Counted once per distinct body offset.
    distinct_bytes: u64,
    /// Summed over every function, counting shared bodies repeatedly.
    total_bytes: u64,
    distinct_bodies: u32,
    overflowed_headers: u32,
};

/// Hermes deduplicates identical function bodies, so several headers can point
/// at one offset and summing every `bytecode_size` overcounts. Sorts `scratch`
/// in place.
pub fn bytecodeStats(scratch: []Function) BytecodeStats {
    var stats = BytecodeStats{
        .distinct_bytes = 0,
        .total_bytes = 0,
        .distinct_bodies = 0,
        .overflowed_headers = 0,
    };

    for (scratch) |f| {
        stats.total_bytes += f.bytecode_size;
        if (f.from_large_header) stats.overflowed_headers += 1;
    }

    std.sort.pdq(Function, scratch, {}, lessByOffset);

    var i: usize = 0;
    while (i < scratch.len) {
        const off = scratch[i].offset;
        stats.distinct_bytes += scratch[i].bytecode_size;
        stats.distinct_bodies += 1;
        while (i < scratch.len and scratch[i].offset == off) i += 1;
    }

    return stats;
}

fn lessByOffset(_: void, a: Function, b: Function) bool {
    return a.offset < b.offset;
}

pub fn moreByBytecodeSize(_: void, a: Function, b: Function) bool {
    if (a.bytecode_size != b.bytecode_size) return a.bytecode_size > b.bytecode_size;
    return a.index < b.index;
}

// ---------------------------------------------------------------------------
// Section offsets
// ---------------------------------------------------------------------------

pub fn alignUp(v: u64) u64 {
    return (v + (ALIGNMENT - 1)) & ~@as(u64, ALIGNMENT - 1);
}

/// Order follows `visitBytecodeSegmentsInOrder()`. Only the sections up to
/// string storage are computed; nothing later is ever addressed by offset.
pub const Layout = struct {
    function_headers: u64,
    string_kinds: u64,
    identifier_hashes: u64,
    string_table: u64,
    overflow_string_table: u64,
    string_storage: u64,
};

pub fn layout(h: Header) Layout {
    var at: u64 = HEADER_SIZE;

    const function_headers = alignUp(at);
    at = function_headers + functionTableSize(h);

    const string_kinds = alignUp(at);
    at = string_kinds + @as(u64, h.string_kind_count) * 4;

    const identifier_hashes = alignUp(at);
    at = identifier_hashes + @as(u64, h.identifier_count) * 4;

    const string_table = alignUp(at);
    at = string_table + @as(u64, h.string_count) * 4;

    const overflow_string_table = alignUp(at);
    at = overflow_string_table + @as(u64, h.overflow_string_count) * 8;

    const string_storage = alignUp(at);

    return .{
        .function_headers = function_headers,
        .string_kinds = string_kinds,
        .identifier_hashes = identifier_hashes,
        .string_table = string_table,
        .overflow_string_table = overflow_string_table,
        .string_storage = string_storage,
    };
}

// ---------------------------------------------------------------------------
// Section map
// ---------------------------------------------------------------------------

/// A section whose size is exactly derivable.
pub const Section = struct {
    name: []const u8,
    bytes: u64,
};

pub const SECTION_COUNT = 16;

/// Total the sections account for. A sum past the end of the file means a
/// section was mis-sized, which is worth saying out loud: the alternative is
/// subtracting it from the leftover bucket and printing a report that looks
/// fine.
pub fn sectionSum(secs: []const Section) u64 {
    var total: u64 = 0;
    for (secs) |s| total += s.bytes;
    return total;
}

/// Only what the header states exactly. The caller reports whatever is left
/// over as one `rest` bucket rather than estimating it.
pub fn sections(
    h: Header,
    bytecode_bytes: u64,
    overflowed_headers: u32,
    buf: *[SECTION_COUNT]Section,
) []Section {
    const debug_info: u64 = blk: {
        if (h.debug_info_offset == 0) break :blk 0;
        const end = @as(u64, h.file_length);
        const start = @as(u64, h.debug_info_offset) + FOOTER_SIZE;
        break :blk if (end > start) end - start else 0;
    };

    var n: usize = 0;
    const add = struct {
        fn f(list: *[SECTION_COUNT]Section, i: *usize, name: []const u8, v: u64) void {
            list[i.*] = .{ .name = name, .bytes = v };
            i.* += 1;
        }
    }.f;

    add(buf, &n, "header", HEADER_SIZE);
    add(buf, &n, "function headers", functionTableSize(h));
    // A header that did not fit stores its real values in a full size header
    // further into the file. That is a rounding error on the classic line, but
    // `static_h` shrank the inline name field to 8 bits, so on a real bundle
    // almost every function overflows and this becomes a section of its own.
    add(buf, &n, "large function headers", @as(u64, overflowed_headers) *
        Format.forVersion(h.version).largeFuncHeaderSize());
    add(buf, &n, "string kinds", @as(u64, h.string_kind_count) * 4);
    add(buf, &n, "identifier hashes", @as(u64, h.identifier_count) * 4);
    add(buf, &n, "string table", @as(u64, h.string_count) * 4);
    add(buf, &n, "overflow string table", @as(u64, h.overflow_string_count) * 8);
    add(buf, &n, "string storage", h.string_storage_size);
    switch (Format.forVersion(h.version)) {
        .classic => {
            add(buf, &n, "array buffer", h.array_buffer_size);
            add(buf, &n, "obj key buffer", h.obj_key_buffer_size);
            add(buf, &n, "obj value buffer", h.obj_value_buffer_size);
        },
        .static_h => {
            add(buf, &n, "literal value buffer", h.array_buffer_size);
            add(buf, &n, "obj key buffer", h.obj_key_buffer_size);
            add(buf, &n, "obj shape table", objValueSectionSize(h));
        },
    }
    add(buf, &n, "bigint storage", h.bigint_storage_size);
    add(buf, &n, "regexp storage", h.regexp_storage_size);
    add(buf, &n, "function bytecode", bytecode_bytes);
    add(buf, &n, "debug info", debug_info);
    add(buf, &n, "footer", FOOTER_SIZE);

    return buf[0..n];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "rejects an empty file" {
    try testing.expectError(error.TooSmall, parseHeader(""));
}

test "rejects a bad magic" {
    var b = [_]u8{0} ** HEADER_SIZE;
    try testing.expectError(error.BadMagic, parseHeader(&b));
    b[0] = 0xFF;
    try testing.expectError(error.BadMagic, parseHeader(&b));
}

test "detects delta-prepped" {
    var b = [_]u8{0} ** HEADER_SIZE;
    std.mem.writeInt(u64, b[0..8], DELTA_MAGIC, .little);
    try testing.expectError(error.DeltaPrepped, parseHeader(&b));
}

test "refuses a version outside the supported range" {
    var b = [_]u8{0} ** HEADER_SIZE;
    std.mem.writeInt(u64, b[0..8], MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 42, .little);
    try testing.expectError(error.UnsupportedVersion, parseHeader(&b));
}

test "reads header fields at the right offsets" {
    var b = [_]u8{0} ** HEADER_SIZE;
    std.mem.writeInt(u64, b[0..8], MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);
    b[12] = 0xAB; // first byte of sourceHash
    std.mem.writeInt(u32, b[32..36], 1234, .little); // fileLength
    std.mem.writeInt(u32, b[40..44], 77, .little); // functionCount
    std.mem.writeInt(u32, b[60..64], 999, .little); // stringStorageSize
    b[108] = 0b101; // staticBuiltins + hasAsync

    const h = try parseHeader(&b);
    try testing.expectEqual(@as(u32, 96), h.version);
    try testing.expectEqual(@as(u8, 0xAB), h.source_hash[0]);
    try testing.expectEqual(@as(u32, 1234), h.file_length);
    try testing.expectEqual(@as(u32, 77), h.function_count);
    try testing.expectEqual(@as(u32, 999), h.string_storage_size);
    try testing.expect(h.options.static_builtins);
    try testing.expect(!h.options.cjs_modules_statically_resolved);
    try testing.expect(h.options.has_async);
}

/// Packs the bitfields by hand so the test fails if the layout is read wrong.
fn oneFunctionFile(buf: []u8, w0: u32, w1: u32, w2: u32, w3: u32) void {
    @memset(buf, 0);
    std.mem.writeInt(u64, buf[0..8], MAGIC, .little);
    std.mem.writeInt(u32, buf[8..12], 96, .little);
    std.mem.writeInt(u32, buf[40..44], 1, .little); // functionCount
    std.mem.writeInt(u32, buf[128..][0..4], w0, .little);
    std.mem.writeInt(u32, buf[132..][0..4], w1, .little);
    std.mem.writeInt(u32, buf[136..][0..4], w2, .little);
    std.mem.writeInt(u32, buf[140..][0..4], w3, .little);
}

test "unpacks small function header bitfields" {
    var b = [_]u8{0} ** (HEADER_SIZE + 16);
    oneFunctionFile(
        &b,
        (3 << 25) | 0x0012_3456, // paramCount 3, offset 0x123456
        (777 << 15) | 0x1234, // functionName 777, bytecodeSize 0x1234
        (9 << 25) | 0x0000_ABCD, // frameSize 9, infoOffset 0xABCD
        // flags: strictMode (bit 2) + hasExceptionHandler (bit 3).
        (0b00_1100 << 24) | (5 << 16) | (4 << 8) | 42,
    );

    const f = try parseFunction(&b, try parseHeader(&b), 0);
    try testing.expectEqual(@as(u32, 0x0012_3456), f.offset);
    try testing.expectEqual(@as(u32, 3), f.param_count);
    try testing.expectEqual(@as(u32, 0x1234), f.bytecode_size);
    try testing.expectEqual(@as(u32, 777), f.name_id);
    try testing.expectEqual(@as(u32, 0x0000_ABCD), f.info_offset);
    try testing.expectEqual(@as(u32, 9), f.frame_size);
    try testing.expectEqual(@as(u32, 42), f.environment_size);
    try testing.expect(f.flags.strict_mode);
    try testing.expect(f.flags.has_exception_handler);
    try testing.expect(!f.flags.overflowed);
    try testing.expect(!f.from_large_header);
}

test "follows an overflowed function header" {
    const large_at = 200;
    var b = [_]u8{0} ** (large_at + 64);
    // The overflowed bit is bit 5 of the flags byte; the large header offset
    // is split as (infoOffset << 16) | offset.
    oneFunctionFile(
        &b,
        large_at & 0xFFFF,
        0,
        large_at >> 16,
        0b10_0000 << 24,
    );
    var c: usize = large_at;
    for ([_]u32{ 0xDEAD, 11, 70_000, 90_000, 0xBEEF, 22, 33 }) |v| {
        std.mem.writeInt(u32, b[c..][0..4], v, .little);
        c += 4;
    }

    const f = try parseFunction(&b, try parseHeader(&b), 0);
    try testing.expect(f.from_large_header);
    try testing.expectEqual(@as(u32, 0xDEAD), f.offset);
    try testing.expectEqual(@as(u32, 11), f.param_count);
    // Both exceed what the small header's 15 and 17 bits could hold.
    try testing.expectEqual(@as(u32, 70_000), f.bytecode_size);
    try testing.expectEqual(@as(u32, 90_000), f.name_id);
}

test "rejects a truncated function table" {
    var b = [_]u8{0} ** (HEADER_SIZE + 8); // room for half an entry
    std.mem.writeInt(u64, b[0..8], MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);
    std.mem.writeInt(u32, b[40..44], 1, .little);
    try testing.expectError(error.TruncatedFunctionTable, parseFunction(&b, try parseHeader(&b), 0));
}

test "counts shared function bodies once" {
    const blank: FunctionFlags = @bitCast(@as(u8, 0));
    var fns = [_]Function{
        .{ .index = 0, .offset = 100, .param_count = 0, .bytecode_size = 10, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = blank, .from_large_header = false },
        .{ .index = 1, .offset = 100, .param_count = 0, .bytecode_size = 10, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = blank, .from_large_header = false },
        .{ .index = 2, .offset = 200, .param_count = 0, .bytecode_size = 25, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = blank, .from_large_header = false },
    };

    const st = bytecodeStats(&fns);
    try testing.expectEqual(@as(u64, 45), st.total_bytes);
    try testing.expectEqual(@as(u64, 35), st.distinct_bytes);
    try testing.expectEqual(@as(u32, 2), st.distinct_bodies);
}

test "alignUp rounds to the next 4-byte boundary" {
    try testing.expectEqual(@as(u64, 0), alignUp(0));
    try testing.expectEqual(@as(u64, 4), alignUp(1));
    try testing.expectEqual(@as(u64, 4), alignUp(4));
    try testing.expectEqual(@as(u64, 8), alignUp(5));
}

test "section layout pads each section to 4 bytes" {
    var h = std.mem.zeroes(Header);
    h.function_count = 1; // 16 bytes, already aligned
    h.string_kind_count = 1; // 4 bytes
    h.identifier_count = 1; // 4 bytes
    h.string_count = 3; // 12 bytes
    h.overflow_string_count = 1; // 8 bytes

    const l = layout(h);
    try testing.expectEqual(@as(u64, 128), l.function_headers);
    try testing.expectEqual(@as(u64, 144), l.string_kinds);
    try testing.expectEqual(@as(u64, 148), l.identifier_hashes);
    try testing.expectEqual(@as(u64, 152), l.string_table);
    try testing.expectEqual(@as(u64, 164), l.overflow_string_table);
    try testing.expectEqual(@as(u64, 172), l.string_storage);
}

test "the section sum is a real check, not the leftover bucket" {
    var h = std.mem.zeroes(Header);
    h.function_count = 1;
    h.string_kind_count = 1;
    h.identifier_count = 1;
    h.string_count = 3;
    h.overflow_string_count = 1;
    h.string_storage_size = 40;

    var buf: [SECTION_COUNT]Section = undefined;
    const fits = sectionSum(sections(h, 64, 0, &buf));

    // 128 header + 16 + 4 + 4 + 12 + 8 + 40 storage + 64 bytecode + 20 footer.
    try testing.expectEqual(@as(u64, 296), fits);

    // A file that small cannot hold them, and the caller must be able to tell.
    // Before this the overshoot was clamped away and the report read as clean.
    try testing.expect(fits > 200);

    const bigger = sectionSum(sections(h, 4096, 0, &buf));
    try testing.expectEqual(fits + 4096 - 64, bigger);
}

// --- static_h line ---------------------------------------------------------

/// Writes a `static_h` file header. The field order matters: `static_h`
/// inserted `numStringSwitchImms` after the object shape table count, so
/// everything from `segmentID` on sits four bytes later than on the classic
/// line.
fn staticHFile(buf: []u8, values: [20]u32) void {
    @memset(buf, 0);
    std.mem.writeInt(u64, buf[0..8], MAGIC, .little);
    std.mem.writeInt(u32, buf[8..12], 98, .little);
    for (values, 0..) |v, i| {
        std.mem.writeInt(u32, buf[32 + i * 4 ..][0..4], v, .little);
    }
}

test "static_h shifts every field after the object shape table" {
    var b = [_]u8{0} ** HEADER_SIZE;
    var v = [_]u32{0} ** 20;
    v[0] = 4096; // fileLength
    v[2] = 7; // functionCount
    v[12] = 111; // literalValueBufferSize
    v[13] = 222; // objKeyBufferSize
    v[14] = 333; // objShapeTableCount
    v[15] = 444; // numStringSwitchImms, absent on the classic line
    v[16] = 555; // segmentID
    v[19] = 666; // debugInfoOffset
    staticHFile(&b, v);

    const h = try parseHeader(&b);
    try testing.expectEqual(Format.static_h, Format.forVersion(h.version));
    try testing.expectEqual(@as(u32, 111), h.array_buffer_size);
    try testing.expectEqual(@as(u32, 333), h.obj_value_buffer_size);
    try testing.expectEqual(@as(u32, 444), h.num_string_switch_imms);
    try testing.expectEqual(@as(u32, 555), h.segment_id);
    try testing.expectEqual(@as(u32, 666), h.debug_info_offset);
}

test "the object shape table stores a count, not a size" {
    var b = [_]u8{0} ** HEADER_SIZE;
    var v = [_]u32{0} ** 20;
    v[14] = 10; // ten shape table entries
    staticHFile(&b, v);
    const h = try parseHeader(&b);
    try testing.expectEqual(@as(u64, 10 * SHAPE_TABLE_ENTRY_SIZE), objValueSectionSize(h));

    // The same slot on the classic line is already a byte count.
    var classic = std.mem.zeroes(Header);
    classic.version = 96;
    classic.obj_value_buffer_size = 10;
    try testing.expectEqual(@as(u64, 10), objValueSectionSize(classic));
}

test "unpacks a static_h small function header" {
    var b = [_]u8{0} ** (HEADER_SIZE + 12);
    var v = [_]u32{0} ** 20;
    v[2] = 1; // functionCount
    staticHFile(&b, v);

    // offset 0x123456, paramCount 3, loopDepth 1
    std.mem.writeInt(u32, b[128..][0..4], (1 << 30) | (3 << 25) | 0x0012_3456, .little);
    // bytecodeSize 0x1234, functionName 200, then the register counts
    std.mem.writeInt(u32, b[132..][0..4], (7 << 27) | (5 << 22) | (200 << 14) | 0x1234, .little);
    b[136] = 9; // frameSize
    b[139] = 0b00_1100; // strictMode + hasExceptionHandler

    const f = try parseFunction(&b, try parseHeader(&b), 0);
    try testing.expectEqual(@as(u32, 0x0012_3456), f.offset);
    try testing.expectEqual(@as(u32, 3), f.param_count);
    try testing.expectEqual(@as(u32, 0x1234), f.bytecode_size);
    try testing.expectEqual(@as(u32, 200), f.name_id);
    try testing.expectEqual(@as(u32, 9), f.frame_size);
    try testing.expect(f.flags.strict_mode);
    try testing.expect(f.flags.has_exception_handler);
    try testing.expect(!f.flags.overflowed);
}

test "the large header offset is split differently on each line" {
    const blank: FunctionFlags = @bitCast(@as(u8, 0));
    var f = Function{
        .index = 0,
        .offset = 0,
        .param_count = 0,
        .bytecode_size = 0,
        .name_id = 0,
        .info_offset = 0,
        .frame_size = 0,
        .environment_size = 0,
        .flags = blank,
        .from_large_header = false,
    };

    // Classic packs the high half into infoOffset, 16 bits each.
    f.offset = 0xBEEF;
    f.info_offset = 0x00AB;
    try testing.expectEqual(@as(u64, 0x00AB_BEEF), largeHeaderOffset(.classic, f));

    // static_h has no infoOffset, so the high byte moved into functionName.
    f.offset = 0x00CD_BEEF;
    f.name_id = 0xAB;
    try testing.expectEqual(@as(u64, 0xABCD_BEEF), largeHeaderOffset(.static_h, f));
}

test "follows an overflowed static_h header" {
    const large_at = 300;
    var b = [_]u8{0} ** (large_at + 64);
    var v = [_]u32{0} ** 20;
    v[2] = 1; // functionCount
    staticHFile(&b, v);

    std.mem.writeInt(u32, b[128..][0..4], large_at & 0xFF_FFFF, .little);
    std.mem.writeInt(u32, b[132..][0..4], ((large_at >> 24) & 0xFF) << 14, .little);
    b[139] = 0b10_0000; // overflowed

    // offset, paramCount, loopDepth, bytecodeSize, functionName, two register
    // counts, frameSize, then three cache bytes and flags.
    var c: usize = large_at;
    for ([_]u32{ 0xDEAD, 11, 2, 70_000, 90_000, 3, 4, 22 }) |x| {
        std.mem.writeInt(u32, b[c..][0..4], x, .little);
        c += 4;
    }

    const f = try parseFunction(&b, try parseHeader(&b), 0);
    try testing.expect(f.from_large_header);
    try testing.expectEqual(@as(u32, 0xDEAD), f.offset);
    try testing.expectEqual(@as(u32, 11), f.param_count);
    // Both exceed what the small header's 14 and 8 bits could hold.
    try testing.expectEqual(@as(u32, 70_000), f.bytecode_size);
    try testing.expectEqual(@as(u32, 90_000), f.name_id);
    try testing.expectEqual(@as(u32, 22), f.frame_size);
}

test "the function table entry size follows the format" {
    var classic = std.mem.zeroes(Header);
    classic.version = 96;
    classic.function_count = 10;
    try testing.expectEqual(@as(u64, 160), functionTableSize(classic));

    var modern = std.mem.zeroes(Header);
    modern.version = 98;
    modern.function_count = 10;
    try testing.expectEqual(@as(u64, 120), functionTableSize(modern));
}
