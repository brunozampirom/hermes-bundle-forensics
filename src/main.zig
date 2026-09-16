//! hbcinfo — what is inside a Hermes bundle, and what each part costs.

const std = @import("std");
const Io = std.Io;
const hbc = @import("hbc.zig");

const usage =
    \\hbcinfo — Hermes bundle forensics
    \\
    \\usage:
    \\  hbcinfo [--top N] <file.hbc|index.android.bundle>
    \\
    \\options:
    \\  --top N   list the N largest functions by bytecode size (default 10,
    \\            0 to skip the listing)
    \\
    \\The file must be raw HBC. Pulling the bundle out of an .apk is not
    \\supported yet — unzip it first:
    \\  unzip -p app.apk assets/index.android.bundle > bundle.hbc
    \\
;

/// Real bundles run to tens of megabytes; 512 MiB is enough headroom that the
/// limit never needs thinking about.
const max_bundle: Io.Limit = .limited(512 * 1024 * 1024);

const Args = struct {
    path: []const u8,
    top: u32 = 10,
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

    const bytes = Io.Dir.cwd().readFileAlloc(io, args.path, arena, max_bundle) catch |err| {
        try out.print("error: could not read {s}: {s}\n", .{ args.path, @errorName(err) });
        try out.flush();
        std.process.exit(1);
    };

    const h = hbc.parseHeader(bytes) catch |err| {
        try reportParseError(out, args.path, bytes, err);
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

    try report(out, args.path, bytes.len, h, functions, args.top);
    try out.flush();
}

fn parseArgs(argv: []const [:0]const u8) ?Args {
    var path: ?[]const u8 = null;
    var top: u32 = 10;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--top")) {
            i += 1;
            if (i >= argv.len) return null;
            top = std.fmt.parseUnsigned(u32, argv[i], 10) catch return null;
        } else if (std.mem.startsWith(u8, a, "-")) {
            return null;
        } else {
            if (path != null) return null;
            path = a;
        }
    }

    return .{ .path = path orelse return null, .top = top };
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

    try out.print("\nsection map\n", .{});
    var buf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const secs = hbc.sections(h, stats.distinct_bytes, &buf);

    var known: u64 = 0;
    for (secs) |s| known += s.bytes;

    for (secs) |s| try printSection(out, s.name, s.bytes, file_size);

    const rest = if (file_size > known) file_size - known else 0;
    try printSection(out, "rest (info + padding)", rest, file_size);

    if (top > 0 and functions.len > 0) try reportTopFunctions(out, functions, top);
}

fn reportTopFunctions(out: *Io.Writer, functions: []hbc.Function, top: u32) !void {
    std.sort.pdq(hbc.Function, functions, {}, hbc.moreByBytecodeSize);
    const n = @min(@as(usize, top), functions.len);

    try out.print("\ntop {d} functions by bytecode size\n", .{n});
    for (functions[0..n]) |f| {
        try out.print("  {d:>8} bytes  #{d:<7} name id {d:<7} params {d:<3} frame {d}\n", .{
            f.bytecode_size, f.index, f.name_id, f.param_count, f.frame_size,
        });
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

test "rejects a truncated function table" {
    var b = [_]u8{0} ** (hbc.HEADER_SIZE + 8); // room for half an entry
    std.mem.writeInt(u64, b[0..8], hbc.MAGIC, .little);
    std.mem.writeInt(u32, b[8..12], 96, .little);
    std.mem.writeInt(u32, b[40..44], 1, .little);
    try std.testing.expectError(error.TruncatedFunctionTable, hbc.parseFunction(&b, 0));
}
