//! hbcinfo — what is inside a Hermes bundle, and what each part costs.

const std = @import("std");
const Io = std.Io;
const hbc = @import("hbc.zig");
const strings = @import("strings.zig");
const container = @import("container.zig");

const usage =
    \\hbcinfo — Hermes bundle forensics
    \\
    \\usage:
    \\  hbcinfo [options] <file>
    \\
    \\<file> is either a raw Hermes bundle, or an .apk / .aab / .ipa to
    \\pull one out of. Containers are detected by signature, not extension.
    \\
    \\options:
    \\  --top N        list the N largest functions and strings (default 10,
    \\                 0 to skip both listings)
    \\  --entry PATH   which bundle to read, when a container holds several
    \\  --list         list the bundles in a container and exit
    \\
;

/// Real bundles run to tens of megabytes; 512 MiB is enough headroom that the
/// limit never needs thinking about.
const max_bundle: Io.Limit = .limited(512 * 1024 * 1024);

const Args = struct {
    path: []const u8,
    top: u32 = 10,
    entry: ?[]const u8 = null,
    list: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const out = &stdout_writer.interface;

    const argv = try init.minimal.args.toSlice(arena);
    const args = parseArgs(argv) orelse {
        try out.print("{s}", .{usage});
        try out.flush();
        std.process.exit(2);
    };

    const loaded = load(arena, io, out, args) catch |err| switch (err) {
        error.Reported => {
            try out.flush();
            std.process.exit(1);
        },
        else => {
            try out.print("error: could not read {s}: {s}\n", .{ args.path, @errorName(err) });
            try out.flush();
            std.process.exit(1);
        },
    };
    if (args.list) {
        try out.flush();
        return;
    }
    const bytes = loaded.bytes;
    const label = loaded.label;

    const h = hbc.parseHeader(bytes) catch |err| {
        try reportParseError(out, label, bytes, err);
        try out.flush();
        std.process.exit(1);
    };

    // A file shorter than the declared fileLength is truncated. Carrying on
    // would produce a section map with percentages above 100%, which is worse
    // than not answering.
    if (bytes.len < h.file_length) {
        try reportIdentity(out, args.path, bytes.len, h);
        try out.print(
            "\nerror: truncated — header declares {d} bytes, {d} missing\n",
            .{ h.file_length, h.file_length - bytes.len },
        );
        try out.flush();
        std.process.exit(1);
    }

    const functions = hbc.parseFunctions(arena, bytes, h) catch |err| {
        try reportIdentity(out, args.path, bytes.len, h);
        try out.print("\nerror: bad function header table: {s}\n", .{@errorName(err)});
        try out.flush();
        std.process.exit(1);
    };

    // A bundle whose string sections do not line up is still worth reporting
    // on — the caller loses names, not the whole analysis.
    const table: ?strings.Table = strings.Table.init(bytes, h) catch null;

    try report(out, label, bytes.len, h, functions, table, args.top);
    try out.flush();
}

const Loaded = struct {
    bytes: []u8,
    /// What to print as the source: the plain path, or `container!entry`.
    label: []const u8,
};

/// Signals that a specific, useful message has already been written, so the
/// caller should exit rather than print a generic error on top of it.
const Reported = error{Reported};

fn load(
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    args: Args,
) !Loaded {
    const file = try Io.Dir.cwd().openFile(io, args.path, .{});
    defer file.close(io);

    const buf = try arena.alloc(u8, 64 * 1024);
    var reader = file.reader(io, buf);

    var sig: [4]u8 = undefined;
    const n = try reader.interface.readSliceShort(&sig);
    const is_zip = container.looksLikeZip(sig[0..n]);

    if (!is_zip) {
        if (args.list) {
            try out.print("{s} is not a container; nothing to list\n", .{args.path});
            return error.Reported;
        }
        if (args.entry != null) {
            try out.print("error: --entry only applies to .apk/.aab/.ipa containers\n", .{});
            return error.Reported;
        }
        const bytes = try Io.Dir.cwd().readFileAlloc(io, args.path, arena, max_bundle);
        return .{ .bytes = bytes, .label = args.path };
    }

    const found = try container.findBundles(arena, &reader);

    if (args.list) {
        if (found.len == 0) {
            try out.print("{s}: no Hermes bundle found\n", .{args.path});
        } else {
            try out.print("{s}\n", .{args.path});
            for (found) |e| {
                try out.print("  {d:>10} bytes  {s}{s}\n", .{
                    e.uncompressed_size,
                    e.name,
                    if (e.stored) "  (stored)" else "",
                });
            }
        }
        return .{ .bytes = &.{}, .label = args.path };
    }

    const name = if (args.entry) |want| blk: {
        for (found) |e| {
            if (std.mem.eql(u8, e.name, want)) break :blk e.name;
        }
        try out.print("error: {s} has no entry {s}\n", .{ args.path, want });
        try out.print("       run with --list to see the bundles it does have\n", .{});
        return error.Reported;
    } else switch (found.len) {
        0 => {
            try out.print("error: no Hermes bundle inside {s}\n", .{args.path});
            return error.Reported;
        },
        1 => found[0].name,
        // Split APKs and multi-module AABs legitimately carry several. Picking
        // one silently would make the numbers a guess about which.
        else => {
            try out.print("error: {s} holds {d} bundles; pick one with --entry\n", .{
                args.path, found.len,
            });
            for (found) |e| {
                try out.print("       {d:>10} bytes  {s}\n", .{ e.uncompressed_size, e.name });
            }
            return error.Reported;
        },
    };

    const bytes = try container.readEntry(arena, &reader, name);
    const label = try std.fmt.allocPrint(arena, "{s}!{s}", .{ args.path, name });
    return .{ .bytes = bytes, .label = label };
}

fn parseArgs(argv: []const [:0]const u8) ?Args {
    var path: ?[]const u8 = null;
    var top: u32 = 10;
    var entry: ?[]const u8 = null;
    var list = false;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--top")) {
            i += 1;
            if (i >= argv.len) return null;
            top = std.fmt.parseUnsigned(u32, argv[i], 10) catch return null;
        } else if (std.mem.eql(u8, a, "--entry")) {
            i += 1;
            if (i >= argv.len) return null;
            entry = argv[i];
        } else if (std.mem.eql(u8, a, "--list")) {
            list = true;
        } else if (std.mem.startsWith(u8, a, "-")) {
            return null;
        } else {
            if (path != null) return null;
            path = a;
        }
    }

    return .{ .path = path orelse return null, .top = top, .entry = entry, .list = list };
}

fn reportParseError(
    out: *Io.Writer,
    path: []const u8,
    bytes: []const u8,
    err: hbc.ParseError,
) !void {
    switch (err) {
        error.TooSmall => try out.print(
            "error: {s} is {d} bytes; the HBC header is {d}\n",
            .{ path, bytes.len, hbc.HEADER_SIZE },
        ),
        error.BadMagic => {
            try out.print("error: {s} is not a Hermes bundle\n", .{path});
            // The usual mistake: a dev bundle, which is plain JS because it
            // never went through hermesc.
            if (looksLikeText(bytes)) {
                try out.print("       looks like plain JS — dev bundles skip hermesc\n", .{});
            }
        },
        error.DeltaPrepped => try out.print(
            "error: {s} is delta-prepped; not supported\n",
            .{path},
        ),
        error.UnsupportedVersion => {
            const v = std.mem.readInt(u32, bytes[8..12], .little);
            try out.print(
                "error: bytecode version {d}; this parser reads {d}-{d}\n",
                .{ v, hbc.VERSION_MIN, hbc.VERSION_MAX },
            );
        },
    }
}

/// Heuristic for the most common mistake: pointing the tool at a dev bundle,
/// which is JS in plain text. If the start of the file is all printable ASCII,
/// it is not bytecode.
fn looksLikeText(bytes: []const u8) bool {
    const n = @min(bytes.len, 64);
    if (n == 0) return false;
    for (bytes[0..n]) |c| {
        const printable = c >= 0x20 and c <= 0x7E;
        const ws = c == '\n' or c == '\r' or c == '\t';
        if (!printable and !ws) return false;
    }
    return true;
}

fn reportIdentity(out: *Io.Writer, path: []const u8, file_size: usize, h: hbc.Header) !void {
    try out.print("file             {s}\n", .{path});
    try out.print("size             {d} bytes\n", .{file_size});
    try out.print("version          {d}\n", .{h.version});
    try out.print("source hash      {s}\n", .{std.fmt.bytesToHex(h.source_hash, .lower)});
    try out.print("options          staticBuiltins={} cjsResolved={} hasAsync={}\n", .{
        h.options.static_builtins,
        h.options.cjs_modules_statically_resolved,
        h.options.has_async,
    });
}

fn report(
    out: *Io.Writer,
    path: []const u8,
    file_size: usize,
    h: hbc.Header,
    functions: []hbc.Function,
    table: ?strings.Table,
    top: u32,
) !void {
    try reportIdentity(out, path, file_size, h);

    // fileLength covers through the end of the footer, so a file larger than
    // declared is just padding or concatenation — note it and move on.
    if (file_size > h.file_length) {
        try out.print("warning          header declares {d} bytes; {d} trail the footer\n", .{
            h.file_length, file_size - h.file_length,
        });
    }

    // bytecodeStats sorts in place, so give it its own copy and keep
    // `functions` in table order for the listing below.
    const by_offset = try std.heap.page_allocator.dupe(hbc.Function, functions);
    defer std.heap.page_allocator.free(by_offset);
    const stats = hbc.bytecodeStats(by_offset);

    try out.print("\ncounts\n", .{});
    try out.print("  functions          {d}\n", .{h.function_count});
    try out.print("  strings            {d}  (identifiers {d}, overflow {d})\n", .{
        h.string_count, h.identifier_count, h.overflow_string_count,
    });
    try out.print("  bigints            {d}\n", .{h.bigint_count});
    try out.print("  regexps            {d}\n", .{h.regexp_count});
    try out.print("  CJS modules        {d}\n", .{h.cjs_module_count});
    try out.print("  function sources   {d}\n", .{h.function_source_count});

    try out.print("\nfunctions\n", .{});
    try out.print("  distinct bodies    {d}\n", .{stats.distinct_bodies});
    try out.print("  bytecode bytes     {d}\n", .{stats.distinct_bytes});
    if (stats.total_bytes > stats.distinct_bytes) {
        const saved = stats.total_bytes - stats.distinct_bytes;
        try out.print("  shared bodies      {d} headers reuse a body, saving {d} bytes\n", .{
            h.function_count - stats.distinct_bodies, saved,
        });
    }
    try out.print("  overflowed headers {d}\n", .{stats.overflowed_headers});

    if (table) |t| {
        const ss = strings.stats(t);
        try out.print("\nstrings\n", .{});
        try out.print("  storage buffer     {d} bytes\n", .{h.string_storage_size});
        try out.print("  sum of lengths     {d} bytes\n", .{ss.sum_of_lengths});
        // Hermes packs strings so that one which is a suffix of another shares
        // its bytes, so the lengths normally add up to more than the buffer.
        if (ss.sum_of_lengths > h.string_storage_size) {
            const saved = ss.sum_of_lengths - h.string_storage_size;
            const tenths = saved * 1000 / ss.sum_of_lengths;
            try out.print("  packer overlap     {d} bytes saved ({d}.{d}%)\n", .{
                saved, tenths / 10, tenths % 10,
            });
        } else if (ss.sum_of_lengths < h.string_storage_size) {
            try out.print("  unreferenced       {d} bytes no entry points at\n", .{
                h.string_storage_size - ss.sum_of_lengths,
            });
        }
        try out.print("  utf-16 strings     {d}  ({d} bytes, 2 per code unit)\n", .{
            ss.utf16_strings, ss.utf16_bytes,
        });
        try out.print("  overflowed entries {d}\n", .{ss.overflowed});
        if (ss.unreadable > 0) {
            try out.print("  unreadable         {d}\n", .{ss.unreadable});
        }
    } else {
        try out.print("\nstrings            section offsets do not fit the file; skipped\n", .{});
    }

    try out.print("\nsection map\n", .{});
    var buf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const secs = hbc.sections(h, stats.distinct_bytes, &buf);

    var known: u64 = 0;
    for (secs) |s| known += s.bytes;

    for (secs) |s| try printSection(out, s.name, s.bytes, file_size);

    const rest = if (file_size > known) file_size - known else 0;
    try printSection(out, "rest (info + padding)", rest, file_size);

    if (top > 0 and functions.len > 0) try reportTopFunctions(out, functions, table, top);
    if (top > 0) {
        if (table) |t| try reportTopStrings(out, t, top);
    }
}

fn reportTopFunctions(
    out: *Io.Writer,
    functions: []hbc.Function,
    table: ?strings.Table,
    top: u32,
) !void {
    std.sort.pdq(hbc.Function, functions, {}, hbc.moreByBytecodeSize);
    const n = @min(@as(usize, top), functions.len);

    try out.print("\ntop {d} functions by bytecode size\n", .{n});
    for (functions[0..n]) |f| {
        try out.print("  {d:>8} bytes  #{d:<7} params {d:<3} frame {d:<4} ", .{
            f.bytecode_size, f.index, f.param_count, f.frame_size,
        });
        if (table) |t| {
            if (t.get(f.name_id)) |name| {
                if (name.bytes.len == 0) {
                    try out.print("(anonymous)", .{});
                } else {
                    try strings.writeEscaped(out, name, 60);
                }
            } else |_| {
                try out.print("name id {d} (unreadable)", .{f.name_id});
            }
        } else {
            try out.print("name id {d}", .{f.name_id});
        }
        try out.print("\n", .{});
    }
}

const StringRef = struct { id: u32, bytes: u32 };

fn moreByStringBytes(_: void, a: StringRef, b: StringRef) bool {
    if (a.bytes != b.bytes) return a.bytes > b.bytes;
    return a.id < b.id;
}

fn reportTopStrings(out: *Io.Writer, t: strings.Table, top: u32) !void {
    const gpa = std.heap.page_allocator;
    const refs = gpa.alloc(StringRef, t.count) catch return;
    defer gpa.free(refs);

    var n: usize = 0;
    var id: u32 = 0;
    while (id < t.count) : (id += 1) {
        const s = t.get(id) catch continue;
        refs[n] = .{ .id = id, .bytes = @intCast(s.bytes.len) };
        n += 1;
    }
    if (n == 0) return;

    std.sort.pdq(StringRef, refs[0..n], {}, moreByStringBytes);
    const show = @min(@as(usize, top), n);

    try out.print("\ntop {d} strings by size\n", .{show});
    for (refs[0..show]) |r| {
        const s = t.get(r.id) catch continue;
        try out.print("  {d:>8} bytes  #{d:<7} {s}", .{
            r.bytes, r.id, if (s.is_utf16) "utf16 " else "      ",
        });
        try strings.writeEscaped(out, s, 60);
        try out.print("\n", .{});
    }
}

fn printSection(out: *Io.Writer, name: []const u8, bytes: u64, total: u64) !void {
    // Percentages in tenths, using integers: identical output on every
    // platform, which matters once this gates a size check in CI.
    const tenths: u64 = if (total == 0) 0 else bytes * 1000 / total;
    try out.print("  {s:<30} {d:>12}  {d:>3}.{d}%\n", .{
        name, bytes, tenths / 10, tenths % 10,
    });
}

test "rejects an empty file" {
    try std.testing.expectError(error.TooSmall, hbc.parseHeader(""));
}

test "rejects a bad magic" {
    var b = [_]u8{0} ** hbc.HEADER_SIZE;
    try std.testing.expectError(error.BadMagic, hbc.parseHeader(&b));
    b[0] = 0xFF;
    try std.testing.expectError(error.BadMagic, hbc.parseHeader(&b));
}

test "detects delta-prepped" {
    var b = [_]u8{0} ** hbc.HEADER_SIZE;
    std.mem.writeInt(u64, b[0..8], hbc.DELTA_MAGIC, .little);
    try std.testing.expectError(error.DeltaPrepped, hbc.parseHeader(&b));
}

test "refuses a version outside the supported range" {
    var b = [_]u8{0} ** hbc.HEADER_SIZE;
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 42, .little);
    try std.testing.expectError(error.UnsupportedVersion, hbc.parseHeader(&b));
}

test "reads fields at the right offsets" {
    var b = [_]u8{0} ** hbc.HEADER_SIZE;
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);
    b[12] = 0xAB; // first byte of sourceHash
    std.mem.writeInt(u32, b[32..36], 1234, .little); // fileLength
    std.mem.writeInt(u32, b[40..44], 77, .little); // functionCount
    std.mem.writeInt(u32, b[60..64], 999, .little); // stringStorageSize
    b[108] = 0b101; // staticBuiltins + hasAsync

    const h = try hbc.parseHeader(&b);
    try std.testing.expectEqual(@as(u32, 96), h.version);
    try std.testing.expectEqual(@as(u8, 0xAB), h.source_hash[0]);
    try std.testing.expectEqual(@as(u32, 1234), h.file_length);
    try std.testing.expectEqual(@as(u32, 77), h.function_count);
    try std.testing.expectEqual(@as(u32, 999), h.string_storage_size);
    try std.testing.expect(h.options.static_builtins);
    try std.testing.expect(!h.options.cjs_modules_statically_resolved);
    try std.testing.expect(h.options.has_async);
}

test "looksLikeText spots a plain-JS dev bundle" {
    try std.testing.expect(looksLikeText("\"use strict\";\nvar x = 1;"));
    try std.testing.expect(looksLikeText("// comment\n(function(){})()"));
    try std.testing.expect(!looksLikeText(&[_]u8{ 0xC6, 0x1F, 0xBC, 0x03 }));
    try std.testing.expect(!looksLikeText(""));
}

/// Builds a file with one small function header whose bitfields are packed by
/// hand, so the test fails if the bit layout is ever read wrong.
fn oneFunctionFile(buf: []u8, w0: u32, w1: u32, w2: u32, w3: u32) void {
    @memset(buf, 0);
    std.mem.writeInt(u64, buf[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, buf[8..12], 96, .little);
    std.mem.writeInt(u32, buf[40..44], 1, .little); // functionCount
    std.mem.writeInt(u32, buf[128..][0..4], w0, .little);
    std.mem.writeInt(u32, buf[132..][0..4], w1, .little);
    std.mem.writeInt(u32, buf[136..][0..4], w2, .little);
    std.mem.writeInt(u32, buf[140..][0..4], w3, .little);
}

test "unpacks small function header bitfields" {
    var b = [_]u8{0} ** (hbc.HEADER_SIZE + 16);
    oneFunctionFile(
        &b,
        (3 << 25) | 0x0012_3456, // paramCount 3, offset 0x123456
        (777 << 15) | 0x1234, // functionName 777, bytecodeSize 0x1234
        (9 << 25) | 0x0000_ABCD, // frameSize 9, infoOffset 0xABCD
        // flags: strictMode (bit 2) + hasExceptionHandler (bit 3).
        (0b00_1100 << 24) | (5 << 16) | (4 << 8) | 42, // flags, caches, envSize
    );

    const f = try hbc.parseFunction(&b, 0);
    try std.testing.expectEqual(@as(u32, 0x0012_3456), f.offset);
    try std.testing.expectEqual(@as(u32, 3), f.param_count);
    try std.testing.expectEqual(@as(u32, 0x1234), f.bytecode_size);
    try std.testing.expectEqual(@as(u32, 777), f.name_id);
    try std.testing.expectEqual(@as(u32, 0x0000_ABCD), f.info_offset);
    try std.testing.expectEqual(@as(u32, 9), f.frame_size);
    try std.testing.expectEqual(@as(u32, 42), f.environment_size);
    try std.testing.expect(f.flags.strict_mode); // bit 2
    try std.testing.expect(f.flags.has_exception_handler); // bit 3
    try std.testing.expect(!f.flags.overflowed);
    try std.testing.expect(!f.from_large_header);
}

test "follows an overflowed function header" {
    const large_at = 200;
    var b = [_]u8{0} ** (large_at + 64);
    // overflowed bit is bit 5 of the flags byte; the large header offset is
    // split as (infoOffset << 16) | offset.
    oneFunctionFile(
        &b,
        large_at & 0xFFFF, // low half of the large offset
        0,
        large_at >> 16, // high half
        0b10_0000 << 24, // overflowed
    );
    var c: usize = large_at;
    for ([_]u32{ 0xDEAD, 11, 70_000, 90_000, 0xBEEF, 22, 33 }) |v| {
        std.mem.writeInt(u32, b[c..][0..4], v, .little);
        c += 4;
    }

    const f = try hbc.parseFunction(&b, 0);
    try std.testing.expect(f.from_large_header);
    try std.testing.expectEqual(@as(u32, 0xDEAD), f.offset);
    try std.testing.expectEqual(@as(u32, 11), f.param_count);
    // Both exceed what the small header's 15 and 17 bits could hold.
    try std.testing.expectEqual(@as(u32, 70_000), f.bytecode_size);
    try std.testing.expectEqual(@as(u32, 90_000), f.name_id);
}

test "counts shared function bodies once" {
    var fns = [_]hbc.Function{
        .{ .index = 0, .offset = 100, .param_count = 0, .bytecode_size = 10, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = @bitCast(@as(u8, 0)), .from_large_header = false },
        .{ .index = 1, .offset = 100, .param_count = 0, .bytecode_size = 10, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = @bitCast(@as(u8, 0)), .from_large_header = false },
        .{ .index = 2, .offset = 200, .param_count = 0, .bytecode_size = 25, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = @bitCast(@as(u8, 0)), .from_large_header = false },
    };

    const stats = hbc.bytecodeStats(&fns);
    try std.testing.expectEqual(@as(u64, 45), stats.total_bytes);
    try std.testing.expectEqual(@as(u64, 35), stats.distinct_bytes);
    try std.testing.expectEqual(@as(u32, 2), stats.distinct_bodies);
}

test "section layout pads each section to 4 bytes" {
    var h = std.mem.zeroes(hbc.Header);
    h.function_count = 1; // 16 bytes, already aligned
    h.string_kind_count = 1; // 4 bytes
    h.identifier_count = 1; // 4 bytes
    h.string_count = 3; // 12 bytes
    h.overflow_string_count = 1; // 8 bytes

    const l = hbc.layout(h);
    try std.testing.expectEqual(@as(u64, 128), l.function_headers);
    try std.testing.expectEqual(@as(u64, 144), l.string_kinds);
    try std.testing.expectEqual(@as(u64, 148), l.identifier_hashes);
    try std.testing.expectEqual(@as(u64, 152), l.string_table);
    try std.testing.expectEqual(@as(u64, 164), l.overflow_string_table);
    try std.testing.expectEqual(@as(u64, 172), l.string_storage);
}

test "alignUp rounds to the next 4-byte boundary" {
    try std.testing.expectEqual(@as(u64, 0), hbc.alignUp(0));
    try std.testing.expectEqual(@as(u64, 4), hbc.alignUp(1));
    try std.testing.expectEqual(@as(u64, 4), hbc.alignUp(4));
    try std.testing.expectEqual(@as(u64, 8), hbc.alignUp(5));
}

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
    try std.testing.expectEqual(@as(u64, 128), l.string_table);
    try std.testing.expectEqual(@as(u64, 136), l.overflow_string_table);
    try std.testing.expectEqual(@as(u64, storage_at), l.string_storage);

    // entry 0: offset 0, length 5, ascii
    std.mem.writeInt(u32, b[128..][0..4], (5 << 24) | (0 << 1), .little);
    // entry 1: length 0xFF marks overflow; offset field holds index 0
    std.mem.writeInt(u32, b[132..][0..4], (0xFF << 24) | (0 << 1), .little);
    // overflow entry 0: real offset 5, real length 300
    std.mem.writeInt(u32, b[136..][0..4], 5, .little);
    std.mem.writeInt(u32, b[140..][0..4], 300, .little);
    @memcpy(b[storage_at..][0..5], "hello");
    @memset(b[storage_at + 5 ..][0..300], 'x');

    const t = try strings.Table.init(&b, h);

    const s0 = try t.get(0);
    try std.testing.expectEqualStrings("hello", s0.bytes);
    try std.testing.expect(!s0.overflowed);
    try std.testing.expect(!s0.is_utf16);

    const s1 = try t.get(1);
    try std.testing.expectEqual(@as(usize, 300), s1.bytes.len);
    try std.testing.expect(s1.overflowed);
    try std.testing.expectEqual(@as(u8, 'x'), s1.bytes[0]);

    try std.testing.expectError(error.NoSuchString, t.get(2));

    const st = strings.stats(t);
    try std.testing.expectEqual(@as(u64, 305), st.sum_of_lengths);
    try std.testing.expectEqual(@as(u32, 1), st.overflowed);
    try std.testing.expectEqual(@as(u32, 0), st.unreadable);
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

    const t = try strings.Table.init(&b, h);
    const s = try t.get(0);
    try std.testing.expect(s.is_utf16);
    try std.testing.expectEqual(@as(u32, 4), s.len);
    try std.testing.expectEqual(@as(usize, 8), s.bytes.len);

    const st = strings.stats(t);
    try std.testing.expectEqual(@as(u64, 8), st.utf16_bytes);
    try std.testing.expectEqual(@as(u32, 1), st.utf16_strings);
}

test "rejects a string entry pointing outside storage" {
    var b = [_]u8{0} ** 160;
    var h = std.mem.zeroes(hbc.Header);
    h.string_count = 1;
    h.string_storage_size = 4;
    // offset 2, length 10 -> runs past the 4-byte storage
    std.mem.writeInt(u32, b[128..][0..4], (10 << 24) | (2 << 1), .little);

    const t = try strings.Table.init(&b, h);
    try std.testing.expectError(error.BadStringEntry, t.get(0));
}

test "detects a zip container by signature, not extension" {
    try std.testing.expect(container.looksLikeZip("PK\x03\x04rest"));
    try std.testing.expect(!container.looksLikeZip("PK\x05\x06")); // empty-archive record
    try std.testing.expect(!container.looksLikeZip(&[_]u8{ 0xC6, 0x1F, 0xBC, 0x03 }));
    try std.testing.expect(!container.looksLikeZip("PK"));
    try std.testing.expect(!container.looksLikeZip(""));
}

test "recognises bundle paths in each container layout" {
    try std.testing.expect(container.looksLikeBundleName("assets/index.android.bundle"));
    try std.testing.expect(container.looksLikeBundleName("base/assets/index.android.bundle"));
    try std.testing.expect(container.looksLikeBundleName("Payload/Sintonia.app/main.jsbundle"));
    try std.testing.expect(container.looksLikeBundleName("whatever/app.hbc"));
    try std.testing.expect(!container.looksLikeBundleName("res/drawable/icon.png"));
    try std.testing.expect(!container.looksLikeBundleName("AndroidManifest.xml"));
}

test "rejects a truncated function table" {
    var b = [_]u8{0} ** (hbc.HEADER_SIZE + 8); // room for half an entry
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);
    std.mem.writeInt(u32, b[40..44], 1, .little);
    try std.testing.expectError(error.TruncatedFunctionTable, hbc.parseFunction(&b, 0));
}
