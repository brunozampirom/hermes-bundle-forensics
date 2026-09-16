//! Parser for the Hermes bytecode (HBC) file header.
//!
//! The layout comes from `include/hermes/BCGen/HBC/BytecodeFileFormat.h` in
//! facebook/hermes. The struct is `LLVM_PACKED`, but every field happens to
//! land on a naturally aligned offset, so the file is just a run of
//! little-endian integers. We parse it field by field on purpose: leaning on
//! the ABI of an `extern struct` would hide exactly the kind of layout
//! mismatch this tool exists to find.

const std = @import("std");

pub const MAGIC: u64 = 0x1F1903C103BC1FC6;
/// The "delta prepped" form: same file, inverted magic.
pub const DELTA_MAGIC: u64 = ~MAGIC;

pub const HEADER_SIZE: usize = 128;
pub const SHA1_NUM_BYTES: usize = 20;
pub const FOOTER_SIZE: usize = SHA1_NUM_BYTES;

/// The range this parser claims to understand. 96 is current for Hermes
/// (BytecodeVersion.h, last touched Aug 2023) and is what React Native ships.
/// Below 90 some fields simply are not in the header, so we refuse rather than
/// read garbage.
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
    /// File is smaller than the 128-byte header.
    TooSmall,
    /// Not an HBC file at all.
    BadMagic,
    /// Valid HBC, but in the delta-prepped form — unsupported.
    DeltaPrepped,
    /// Valid HBC, but a bytecode version outside the range we can read.
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

/// A section whose size falls straight out of the header.
pub const Section = struct {
    name: []const u8,
    bytes: u64,
};

pub const SECTION_COUNT = 9;

/// Breaks the file down into what the header lets us state with certainty.
/// Everything not derivable becomes `rest` — function tables, the string
/// table, identifier hashes and the bytecode itself. Separating those means
/// walking the function headers, which is the next step for this project.
pub fn sections(h: Header, buf: *[SECTION_COUNT]Section) []Section {
    const debug_info: u64 = blk: {
        if (h.debug_info_offset == 0) break :blk 0;
        const end = @as(u64, h.file_length);
        const start = @as(u64, h.debug_info_offset) + FOOTER_SIZE;
        break :blk if (end > start) end - start else 0;
    };

    var known: u64 = 0;
    var n: usize = 0;
    const add = struct {
        fn f(list: *[SECTION_COUNT]Section, i: *usize, acc: *u64, name: []const u8, v: u64) void {
            list[i.*] = .{ .name = name, .bytes = v };
            i.* += 1;
            acc.* += v;
        }
    }.f;

    add(buf, &n, &known, "header", HEADER_SIZE);
    add(buf, &n, &known, "string storage", h.string_storage_size);
    add(buf, &n, &known, "array buffer", h.array_buffer_size);
    add(buf, &n, &known, "obj key buffer", h.obj_key_buffer_size);
    add(buf, &n, &known, "obj value buffer", h.obj_value_buffer_size);
    add(buf, &n, &known, "regexp storage", h.regexp_storage_size);
    add(buf, &n, &known, "bigint storage", h.bigint_storage_size);
    add(buf, &n, &known, "debug info", debug_info);
    add(buf, &n, &known, "footer", FOOTER_SIZE);

    return buf[0..n];
}
