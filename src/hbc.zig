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

/// 96 is current for Hermes and is what React Native ships. Below 90 some
/// header fields do not exist, so we refuse rather than read garbage.
pub const VERSION_MIN: u32 = 90;
pub const VERSION_MAX: u32 = 96;

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
    array_buffer_size: u32,
    obj_key_buffer_size: u32,
    obj_value_buffer_size: u32,
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
        .segment_id = c.u32le(),
        .cjs_module_count = c.u32le(),
        .function_source_count = c.u32le(),
        .debug_info_offset = c.u32le(),
        .options = @bitCast(c.u8v()),
    };

    // 108 bytes of fields plus one for options; the rest up to 128 is padding.
    std.debug.assert(c.pos == 109);
    return h;
}

// ---------------------------------------------------------------------------
// Function headers
// ---------------------------------------------------------------------------

/// Four little-endian words of bitfields, allocated from the least significant
/// bit as Clang and GCC do on little-endian targets.
pub const FUNC_HEADER_SIZE: u64 = 16;

/// The overflow form: same fields at full width, packed. 7 * u32 + 3 * u8.
pub const LARGE_FUNC_HEADER_SIZE: u64 = 31;

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

pub fn functionTableSize(h: Header) u64 {
    return @as(u64, h.function_count) * FUNC_HEADER_SIZE;
}

/// Reads one function header, following the overflow indirection when the
/// small header could not hold the real values.
pub fn parseFunction(bytes: []const u8, index: u32) FunctionError!Function {
    const base = HEADER_SIZE + @as(u64, index) * FUNC_HEADER_SIZE;
    if (base + FUNC_HEADER_SIZE > bytes.len) return error.TruncatedFunctionTable;

    const at: usize = @intCast(base);
    const w0 = std.mem.readInt(u32, bytes[at..][0..4], .little);
    const w1 = std.mem.readInt(u32, bytes[at + 4 ..][0..4], .little);
    const w2 = std.mem.readInt(u32, bytes[at + 8 ..][0..4], .little);
    const w3 = std.mem.readInt(u32, bytes[at + 12 ..][0..4], .little);

    const flags: FunctionFlags = @bitCast(@as(u8, @truncate(w3 >> 24)));

    var f = Function{
        .index = index,
        .offset = w0 & 0x01FF_FFFF, // 25 bits
        .param_count = w0 >> 25, // 7 bits
        .bytecode_size = w1 & 0x7FFF, // 15 bits
        .name_id = w1 >> 15, // 17 bits
        .info_offset = w2 & 0x01FF_FFFF, // 25 bits
        .frame_size = w2 >> 25, // 7 bits
        .environment_size = w3 & 0xFF,
        .flags = flags,
        .from_large_header = false,
    };

    if (!flags.overflowed) return f;

    // The offset is split across two of the small header's own fields; see
    // SmallFuncHeader::getLargeHeaderOffset().
    const large_at: u64 = (@as(u64, f.info_offset) << 16) | @as(u64, f.offset);
    if (large_at + LARGE_FUNC_HEADER_SIZE > bytes.len) return error.BadLargeHeaderOffset;

    var c = Cursor{ .bytes = bytes, .pos = @intCast(large_at) };
    f.offset = c.u32le();
    f.param_count = c.u32le();
    f.bytecode_size = c.u32le();
    f.name_id = c.u32le();
    f.info_offset = c.u32le();
    f.frame_size = c.u32le();
    f.environment_size = c.u32le();
    _ = c.u8v(); // highestReadCacheIndex
    _ = c.u8v(); // highestWriteCacheIndex
    f.flags = @bitCast(c.u8v());
    f.from_large_header = true;
    return f;
}

/// Caller owns the returned slice.
pub fn parseFunctions(
    gpa: std.mem.Allocator,
    bytes: []const u8,
    h: Header,
) (FunctionError || std.mem.Allocator.Error)![]Function {
    const list = try gpa.alloc(Function, h.function_count);
    errdefer gpa.free(list);
    for (list, 0..) |*slot, i| slot.* = try parseFunction(bytes, @intCast(i));
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

pub const SECTION_COUNT = 15;

/// Only what the header states exactly. The caller reports whatever is left
/// over as one `rest` bucket rather than estimating it.
pub fn sections(h: Header, bytecode_bytes: u64, buf: *[SECTION_COUNT]Section) []Section {
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
    add(buf, &n, "string kinds", @as(u64, h.string_kind_count) * 4);
    add(buf, &n, "identifier hashes", @as(u64, h.identifier_count) * 4);
    add(buf, &n, "string table", @as(u64, h.string_count) * 4);
    add(buf, &n, "overflow string table", @as(u64, h.overflow_string_count) * 8);
    add(buf, &n, "string storage", h.string_storage_size);
    add(buf, &n, "array buffer", h.array_buffer_size);
    add(buf, &n, "obj key buffer", h.obj_key_buffer_size);
    add(buf, &n, "obj value buffer", h.obj_value_buffer_size);
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

    const f = try parseFunction(&b, 0);
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

    const f = try parseFunction(&b, 0);
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
    try testing.expectError(error.TruncatedFunctionTable, parseFunction(&b, 0));
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
