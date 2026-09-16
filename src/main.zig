//! hbcinfo — what is inside a Hermes bundle, and what each part costs.

const std = @import("std");
const Io = std.Io;
const hbc = @import("hbc.zig");

const usage =
    \\hbcinfo — Hermes bundle forensics
    \\
    \\usage:
    \\  hbcinfo <file.hbc|index.android.bundle>
    \\
    \\The file must be raw HBC. Pulling the bundle out of an .apk is not
    \\supported yet — unzip it first:
    \\  unzip -p app.apk assets/index.android.bundle > bundle.hbc
    \\
;

/// Real bundles run to tens of megabytes; 512 MiB is enough headroom that the
/// limit never needs thinking about.
const max_bundle: Io.Limit = .limited(512 * 1024 * 1024);

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const out = &stdout_writer.interface;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 2) {
        try out.print("{s}", .{usage});
        try out.flush();
        std.process.exit(2);
    }

    const path = args[1];
    const bytes = Io.Dir.cwd().readFileAlloc(io, path, arena, max_bundle) catch |err| {
        try out.print("error: could not read {s}: {s}\n", .{ path, @errorName(err) });
        try out.flush();
        std.process.exit(1);
    };

    const h = hbc.parseHeader(bytes) catch |err| {
        try reportParseError(out, path, bytes, err);
        try out.flush();
        std.process.exit(1);
    };

    // A file shorter than the declared fileLength is truncated. Carrying on
    // would produce a section map with percentages above 100%, which is worse
    // than not answering.
    if (bytes.len < h.file_length) {
        try reportIdentity(out, path, bytes.len, h);
        try out.print(
            "\nerror: truncated — header declares {d} bytes, {d} missing\n",
            .{ h.file_length, h.file_length - bytes.len },
        );
        try out.flush();
        std.process.exit(1);
    }

    try report(out, path, bytes.len, h);
    try out.flush();
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

fn report(out: *Io.Writer, path: []const u8, file_size: usize, h: hbc.Header) !void {
    try reportIdentity(out, path, file_size, h);

    // fileLength covers through the end of the footer, so a file larger than
    // declared is just padding or concatenation — note it and move on.
    if (file_size > h.file_length) {
        try out.print("warning          header declares {d} bytes; {d} trail the footer\n", .{
            h.file_length, file_size - h.file_length,
        });
    }

    try out.print("\ncounts\n", .{});
    try out.print("  functions          {d}\n", .{h.function_count});
    try out.print("  strings            {d}  (identifiers {d}, overflow {d})\n", .{
        h.string_count, h.identifier_count, h.overflow_string_count,
    });
    try out.print("  bigints            {d}\n", .{h.bigint_count});
    try out.print("  regexps            {d}\n", .{h.regexp_count});
    try out.print("  CJS modules        {d}\n", .{h.cjs_module_count});
    try out.print("  function sources   {d}\n", .{h.function_source_count});

    try out.print("\nsection map\n", .{});
    var buf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const secs = hbc.sections(h, &buf);

    var known: u64 = 0;
    for (secs) |s| known += s.bytes;

    for (secs) |s| try printSection(out, s.name, s.bytes, file_size);

    const rest = if (file_size > known) file_size - known else 0;
    try printSection(out, "rest (tables + bytecode)", rest, file_size);
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
