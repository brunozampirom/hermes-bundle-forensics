//! hbcinfo: what is inside a Hermes bundle, and what each part costs.

const std = @import("std");
const Io = std.Io;
const hbc = @import("hbc.zig");
const strings = @import("strings.zig");
const container = @import("container.zig");
const tree = @import("tree.zig");
const html = @import("html.zig");
const budget = @import("budget.zig");
const debug = @import("debug.zig");
const sourcemap = @import("sourcemap.zig");
const modules = @import("modules.zig");

const usage =
    \\hbcinfo: Hermes bundle forensics
    \\
    \\usage:
    \\  hbcinfo [options] <file>
    \\
    \\<file> is either a raw Hermes bundle, or an .apk / .aab / .ipa to
    \\pull one out of. Containers are detected by signature, not extension.
    \\
    \\Give a second file to diff the two.
    \\
    \\options:
    \\  --top N        list the N largest functions and strings (default 10,
    \\                 0 to skip both listings)
    \\  --entry PATH   which bundle to read, when a container holds several
    \\  --entry-b PATH same, for the second file in a diff
    \\  --html PATH    write a treemap of the bundle to PATH as one html file
    \\  --budget PATH  check section sizes against a budget file; over exits 1
    \\  --sourcemap P  attribute bytecode to modules using a composed source map
    \\  --list         list the bundles in a container and exit
    \\
;

/// Real bundles run to tens of megabytes.
const max_bundle: Io.Limit = .limited(512 * 1024 * 1024);

const Args = struct {
    path: []const u8,
    top: u32 = 10,
    entry: ?[]const u8 = null,
    list: bool = false,
    /// When set, the run is a diff of path -> path_b.
    path_b: ?[]const u8 = null,
    entry_b: ?[]const u8 = null,
    /// Where to write the treemap, when asked for one.
    html: ?[]const u8 = null,
    /// Budget file to check the bundle against; a breach exits non-zero.
    budget: ?[]const u8 = null,
    /// Source map to attribute bytecode back to modules with.
    sourcemap: ?[]const u8 = null,
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

    const a = try open(arena, io, out, args, args.path, args.entry);
    if (args.list) {
        try out.flush();
        return;
    }

    if (args.path_b) |pb| {
        const b = try open(arena, io, out, args, pb, args.entry_b);
        try reportDiff(out, arena, a, b, args.top);
        if (args.html) |dest| {
            // reportDiff refuses to compare across bytecode lines. Drawing what
            // the table declined to print would be worse for being prettier.
            if (comparable(a, b)) {
                try writeDiffTreemap(arena, io, out, a, b, dest);
            } else {
                try out.print("no treemap written; the bundles are different format lines\n", .{});
            }
        }
    } else {
        try report(out, a, args.top);
        const attribution = if (args.sourcemap) |mp|
            try reportModules(arena, io, out, a, mp, args.top)
        else
            null;
        if (args.html) |dest| try writeTreemap(arena, io, out, a, dest, attribution);
    }

    if (args.budget) |path| {
        const code = try runBudget(arena, io, out, a, path);
        try out.flush();
        if (code != 0) std.process.exit(code);
        return;
    }
    try out.flush();
}

/// Attributes bytecode to the modules it came from, using the source map that
/// shipped with the build.
fn reportModules(
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    b: Bundle,
    path: []const u8,
    top: u32,
) !?modules.Result {
    const json = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(512 * 1024 * 1024)) catch |err| {
        try out.print("\nerror: could not read source map {s}: {s}\n", .{ path, @errorName(err) });
        return null;
    };

    const map = sourcemap.parse(arena, json) catch |err| {
        try out.print("\nsource map {s}\n  unusable: {s}\n", .{ path, @errorName(err) });
        if (err == error.NotAHermesMap) {
            try out.print(
                "  this looks like Metro's JavaScript map. The one that maps bytecode\n" ++
                    "  is Metro's composed with Hermes's, which is what a release build\n" ++
                    "  uploads for symbolication.\n",
                .{},
            );
        }
        return null;
    };

    const r = try modules.attribute(arena, b.functions, map);

    try out.print("\nmodules\n", .{});
    try out.print("  source map        {s}\n", .{path});
    try out.print("  attributed        {d} bytes across {d} modules\n", .{ r.attributed, r.modules.len });
    if (r.unattributed > 0) {
        try out.print("  unattributed      {d} bytes with no mapping\n", .{r.unattributed});
    }

    if (top == 0 or r.modules.len == 0) return r;
    const n = @min(@as(usize, top), r.modules.len);
    try out.print("\ntop {d} modules by bytecode\n", .{n});
    for (r.modules[0..n]) |m| {
        try out.print("  {d:>9}  {s}\n", .{ m.bytes, m.name });
    }
    return r;
}

/// What the debug info section holds, for the bundles that carry one.
///
/// Two checks guard the decode. The walk has to finish exactly on the scope
/// descriptor boundary, and the number of records has to match the number of
/// function headers whose flags claim to have one. Those are written by
/// different parts of the compiler, so a reader that drifted would break the
/// match rather than quietly print plausible line numbers.
fn reportDebugInfo(out: *Io.Writer, gpa: std.mem.Allocator, b: Bundle) !void {
    // NoDebugInfo is the normal case for a release bundle and says nothing
    // worth printing. Any other failure means the section is there and this
    // could not read it, which stayed silent before and hid a whole megabyte.
    const info = debug.init(b.bytes, b.header) catch |err| {
        if (err == error.NoDebugInfo) return;
        try out.print("\ndebug info\n  unreadable: {s}\n", .{@errorName(err)});
        return;
    };

    const walked = debug.walk(gpa, info) catch |err| {
        try out.print("\ndebug info\n  unreadable: {s}\n", .{@errorName(err)});
        return;
    };
    defer gpa.free(walked.locations);

    try out.print("\ndebug info\n", .{});
    if (info.filename(0)) |name| {
        try out.print("  compiled from     {s}\n", .{name});
    }
    if (info.header.file_region_count != 1) {
        try out.print("  file regions      {d}\n", .{info.header.file_region_count});
    }

    var entries: u64 = 0;
    var min_line: i64 = std.math.maxInt(i64);
    var max_line: i64 = std.math.minInt(i64);
    for (walked.locations) |l| {
        entries += l.entries;
        min_line = @min(min_line, l.line);
        max_line = @max(max_line, l.line);
    }

    var flagged: u32 = 0;
    for (b.functions) |f| {
        if (f.flags.has_debug_info) flagged += 1;
    }

    try out.print("  functions covered {d} of {d}\n", .{ walked.locations.len, b.header.function_count });
    try out.print("  location records  {d}\n", .{entries});
    if (walked.locations.len > 0) {
        try out.print("  source lines      {d} to {d}\n", .{ min_line, max_line });
    }

    // Cross-checking the record count against the headers only works on the
    // classic line. `static_h` still has the HasDebugInfo bit, but measured
    // against bytecode 98 it is zero on all 116846 headers of a bundle
    // carrying 5.6 MB of debug info, so a mismatch there says nothing about
    // the decode. Claiming otherwise would be a warning that always fires.
    if (hbc.Format.forVersion(b.header.version) == .classic and flagged != walked.locations.len) {
        try out.print("  MISMATCH          {d} headers flag debug info, {d} records found\n", .{
            flagged, walked.locations.len,
        });
    }
    if (walked.ended_at != info.header.locations_end) {
        try out.print("  DESYNC            walk ended at {d}, expected {d}\n", .{
            walked.ended_at, info.header.locations_end,
        });
    }
}

/// The two bytecode lines name different sections in the same slots, so any
/// side by side view of them labels a row from one side and fills it from the
/// other.
fn comparable(a: Bundle, b: Bundle) bool {
    return hbc.Format.forVersion(a.header.version) ==
        hbc.Format.forVersion(b.header.version);
}

fn writeDiffTreemap(
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    a: Bundle,
    b: Bundle,
    dest: []const u8,
) !void {
    const ta = try tree.build(arena, a.header, a.functions, a.table, a.bytes.len, .{});
    const tb = try tree.build(arena, b.header, b.functions, b.table, b.bytes.len, .{});
    const d = try tree.diff(arena, ta, tb);

    const file = try Io.Dir.cwd().createFile(io, dest, .{});
    defer file.close(io);

    var buf: [64 * 1024]u8 = undefined;
    var writer = file.writer(io, &buf);
    try html.writeDiff(&writer.interface, a.label, b.label, d);
    try writer.interface.flush();

    try out.print("\ndiff treemap written to {s}\n", .{dest});
}

/// Checks a bundle against a budget file and returns the process exit code.
/// An unknown section name fails too: a budget quietly checking nothing is the
/// failure mode worth designing against.
fn runBudget(
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    b: Bundle,
    path: []const u8,
) !u8 {
    const text = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20)) catch |err| {
        try out.print("error: could not read budget {s}: {s}\n", .{ path, @errorName(err) });
        return 1;
    };

    const parsed = try budget.parse(arena, text);
    const limits = switch (parsed) {
        .bad => |bad| {
            try out.print("error: {s}:{d}: {s}\n", .{ path, bad.line, switch (bad.err) {
                error.MissingEquals => "expected 'section = bytes'",
                error.BadNumber => "the limit is not a number",
                error.EmptyName => "the section name is empty",
            } });
            return 1;
        },
        .ok => |l| l,
    };

    const scratch = try arena.dupe(hbc.Function, b.functions);
    const stats = hbc.bytecodeStats(scratch);
    var buf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const secs = hbc.sections(b.header, stats.distinct_bytes, stats.overflowed_headers, &buf);

    const report_ = try budget.check(arena, limits, secs, b.bytes.len);

    try out.print("\nbudget {s}\n", .{path});
    for (report_.rows) |r| {
        if (r.unknown) {
            try out.print("  {s:<24} {s:>12}   no section by that name\n", .{ r.name, "-" });
            continue;
        }
        try out.print("  {s:<24} {d:>12} / {d:<12} {s}\n", .{
            r.name,
            r.actual,
            r.max_bytes,
            if (r.over()) "OVER" else "ok",
        });
    }

    if (report_.failed > 0 or report_.unknown > 0) {
        try out.print("\n{d} over budget, {d} unknown\n", .{ report_.failed, report_.unknown });
        return 1;
    }
    try out.print("\nall {d} within budget\n", .{report_.rows.len});
    return 0;
}

/// Writes the treemap and says where it went. Printing the path rather than
/// opening a browser keeps this to one static binary with no per-platform code.
fn writeTreemap(
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    b: Bundle,
    dest: []const u8,
    attribution: ?modules.Result,
) !void {
    const root = try tree.build(arena, b.header, b.functions, b.table, b.bytes.len, .{
        .attribution = attribution,
    });

    const file = try Io.Dir.cwd().createFile(io, dest, .{});
    defer file.close(io);

    var buf: [64 * 1024]u8 = undefined;
    var writer = file.writer(io, &buf);
    try html.write(&writer.interface, b.label, b.header.version, root);
    try writer.interface.flush();

    try out.print("\ntreemap written to {s}\n", .{dest});
}

const Loaded = struct {
    bytes: []u8,
    /// What to print as the source: the plain path, or `container!entry`.
    label: []const u8,
};

/// Everything both the single-file report and the diff need.
const Bundle = struct {
    label: []const u8,
    bytes: []u8,
    header: hbc.Header,
    functions: []hbc.Function,
    table: ?strings.Table,
};

/// Loads and parses one bundle, or writes a specific error and exits.
fn open(
    arena: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    args: Args,
    path: []const u8,
    entry: ?[]const u8,
) !Bundle {
    var one = args;
    one.path = path;
    one.entry = entry;

    const loaded = load(arena, io, out, one) catch |err| switch (err) {
        error.Reported => {
            try out.flush();
            std.process.exit(1);
        },
        else => {
            try out.print("error: could not read {s}: {s}\n", .{ path, @errorName(err) });
            try out.flush();
            std.process.exit(1);
        },
    };
    if (args.list) return .{
        .label = loaded.label,
        .bytes = loaded.bytes,
        .header = undefined,
        .functions = &.{},
        .table = null,
    };

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
        try reportIdentity(out, label, bytes.len, h);
        try out.print(
            "\nerror: truncated; header declares {d} bytes, {d} missing\n",
            .{ h.file_length, h.file_length - bytes.len },
        );
        try out.flush();
        std.process.exit(1);
    }

    const functions = hbc.parseFunctions(arena, bytes, h) catch |err| {
        try reportIdentity(out, label, bytes.len, h);
        try out.print("\nerror: bad function header table: {s}\n", .{@errorName(err)});
        try out.flush();
        std.process.exit(1);
    };

    // A bundle whose string sections do not line up is still worth reporting
    // on; the caller loses names, not the whole analysis.
    const table: ?strings.Table = strings.Table.init(bytes, h) catch null;

    return .{
        .label = label,
        .bytes = bytes,
        .header = h,
        .functions = functions,
        .table = table,
    };
}

/// A specific message was already written; do not print a generic one over it.
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
    var entry_b: ?[]const u8 = null;
    var list = false;
    var path_b: ?[]const u8 = null;
    var html_out: ?[]const u8 = null;
    var budget_file: ?[]const u8 = null;
    var map_file: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, a, "--entry-b")) {
            i += 1;
            if (i >= argv.len) return null;
            entry_b = argv[i];
        } else if (std.mem.eql(u8, a, "--sourcemap")) {
            i += 1;
            if (i >= argv.len) return null;
            map_file = argv[i];
        } else if (std.mem.eql(u8, a, "--budget")) {
            i += 1;
            if (i >= argv.len) return null;
            budget_file = argv[i];
        } else if (std.mem.eql(u8, a, "--html")) {
            i += 1;
            if (i >= argv.len) return null;
            html_out = argv[i];
        } else if (std.mem.eql(u8, a, "--list")) {
            list = true;
        } else if (std.mem.startsWith(u8, a, "-")) {
            return null;
        } else {
            if (path == null) {
                path = a;
            } else if (path_b == null) {
                path_b = a;
            } else return null;
        }
    }

    return .{
        .path = path orelse return null,
        .top = top,
        .entry = entry,
        .html = html_out,
        .budget = budget_file,
        .sourcemap = map_file,
        .list = list,
        .path_b = path_b,
        .entry_b = entry_b,
    };
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
                try out.print("       looks like plain JS; dev bundles skip hermesc\n", .{});
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

/// Catches the common mistake of pointing the tool at a dev bundle, which is
/// plain JS text rather than bytecode.
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

fn printDelta(out: *Io.Writer, name: []const u8, a: u64, b: u64) !void {
    const grew = b >= a;
    const delta = if (grew) b - a else a - b;
    try out.print("  {s:<24} {d:>12} {d:>12}   {s}{d}\n", .{
        name, a, b, if (delta == 0) " " else if (grew) "+" else "-", delta,
    });
}

/// Sections and counts line up exactly. Functions are matched by name, which
/// only works for names unique to both bundles, so the report says how many it
/// could not match.
fn reportDiff(out: *Io.Writer, gpa: std.mem.Allocator, a: Bundle, b: Bundle, top: u32) !void {
    try out.print("a  {s}\n", .{a.label});
    try out.print("b  {s}\n", .{b.label});

    // The two bytecode lines name different sections in the same slots, so a
    // row would be labelled from one side and filled from the other. Refuse
    // rather than print a table where the labels only describe column a.
    const a_fmt = hbc.Format.forVersion(a.header.version);
    const b_fmt = hbc.Format.forVersion(b.header.version);
    if (a_fmt != b_fmt) {
        try out.print(
            "\nbytecode {d} and {d} are different format lines and their section" ++
                " tables do not line up; diff bundles from one line\n",
            .{ a.header.version, b.header.version },
        );
        return;
    }

    if (std.mem.eql(u8, &a.header.source_hash, &b.header.source_hash)) {
        try out.print("\nsame source hash; these were built from identical sources\n", .{});
    }

    try out.print("\n{s:<26} {s:>12} {s:>12}   {s}\n", .{ "", "a", "b", "delta" });
    try printDelta(out, "total size", a.bytes.len, b.bytes.len);

    const a_by_offset = try gpa.dupe(hbc.Function, a.functions);
    defer gpa.free(a_by_offset);
    const b_by_offset = try gpa.dupe(hbc.Function, b.functions);
    defer gpa.free(b_by_offset);
    const a_stats = hbc.bytecodeStats(a_by_offset);
    const b_stats = hbc.bytecodeStats(b_by_offset);

    try out.print("\nsections\n", .{});
    var abuf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    var bbuf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const asecs = hbc.sections(a.header, a_stats.distinct_bytes, a_stats.overflowed_headers, &abuf);
    const bsecs = hbc.sections(b.header, b_stats.distinct_bytes, b_stats.overflowed_headers, &bbuf);
    var a_known: u64 = 0;
    var b_known: u64 = 0;
    for (asecs, bsecs) |sa, sb| {
        a_known += sa.bytes;
        b_known += sb.bytes;
        if (sa.bytes == 0 and sb.bytes == 0) continue;
        try printDelta(out, sa.name, sa.bytes, sb.bytes);
    }
    // Without this the deltas quietly fail to add up to the total. An overshoot
    // is called out rather than clamped, for the reason given in reportFile.
    if (a_known > a.bytes.len or b_known > b.bytes.len) {
        try out.print("  {s:<30} sections overrun the file\n", .{"INCONSISTENT"});
    } else {
        try printDelta(
            out,
            "rest (info + padding)",
            a.bytes.len - a_known,
            b.bytes.len - b_known,
        );
    }

    try out.print("\ncounts\n", .{});
    try printDelta(out, "functions", a.header.function_count, b.header.function_count);
    try printDelta(out, "distinct bodies", a_stats.distinct_bodies, b_stats.distinct_bodies);
    try printDelta(out, "strings", a.header.string_count, b.header.string_count);
    try printDelta(out, "regexps", a.header.regexp_count, b.header.regexp_count);

    if (top == 0) return;
    if (a.table == null or b.table == null) return;
    try reportStringDiff(out, gpa, a.table.?, b.table.?);
    try reportFunctionDiff(out, gpa, a, b, top);
}

/// Strings are content-addressable, so they diff exactly.
fn reportStringDiff(out: *Io.Writer, gpa: std.mem.Allocator, ta: strings.Table, tb: strings.Table) !void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(gpa);

    var id: u32 = 0;
    while (id < ta.count) : (id += 1) {
        const s = ta.get(id) catch continue;
        try seen.put(gpa, s.bytes, {});
    }

    var added: u32 = 0;
    var added_bytes: u64 = 0;
    id = 0;
    while (id < tb.count) : (id += 1) {
        const s = tb.get(id) catch continue;
        if (!seen.contains(s.bytes)) {
            added += 1;
            added_bytes += s.bytes.len;
        }
    }

    try out.print("\nstrings only in b\n", .{});
    try out.print("  {d} strings, {d} bytes\n", .{ added, added_bytes });
}

const NameSize = struct { size: u64, count: u32 };

fn reportFunctionDiff(
    out: *Io.Writer,
    gpa: std.mem.Allocator,
    a: Bundle,
    b: Bundle,
    top: u32,
) !void {
    var map: std.StringHashMapUnmanaged(NameSize) = .empty;
    defer map.deinit(gpa);

    for (a.functions) |f| {
        const name = (a.table.?.get(f.name_id) catch continue).bytes;
        if (name.len == 0) continue;
        const e = try map.getOrPut(gpa, name);
        if (e.found_existing) {
            e.value_ptr.count += 1;
        } else {
            e.value_ptr.* = .{ .size = f.bytecode_size, .count = 1 };
        }
    }

    const Change = struct { name: []const u8, before: u64, after: u64 };
    var changes: std.ArrayList(Change) = .empty;
    defer changes.deinit(gpa);

    var ambiguous: u32 = 0;
    var unmatched: u32 = 0;

    for (b.functions) |f| {
        const name = (b.table.?.get(f.name_id) catch continue).bytes;
        if (name.len == 0) continue;
        const hit = map.get(name) orelse {
            unmatched += 1;
            continue;
        };
        if (hit.count > 1) {
            ambiguous += 1;
            continue;
        }
        if (hit.size == f.bytecode_size) continue;
        try changes.append(gpa, .{ .name = name, .before = hit.size, .after = f.bytecode_size });
    }

    if (changes.items.len == 0) {
        try out.print("\nno uniquely-named function changed size\n", .{});
    } else {
        std.sort.pdq(Change, changes.items, {}, struct {
            fn f(_: void, x: Change, y: Change) bool {
                const dx = if (x.after > x.before) x.after - x.before else x.before - x.after;
                const dy = if (y.after > y.before) y.after - y.before else y.before - y.after;
                return dx > dy;
            }
        }.f);

        const n = @min(@as(usize, top), changes.items.len);
        try out.print("\ntop {d} functions by size change (matched by name)\n", .{n});
        for (changes.items[0..n]) |c| {
            const grew = c.after >= c.before;
            const d = if (grew) c.after - c.before else c.before - c.after;
            try out.print("  {s}{d:<9} {d:>8} -> {d:<8}  {s}\n", .{
                if (grew) "+" else "-", d, c.before, c.after, c.name,
            });
        }
    }

    try out.print("\n  {d} names appear more than once in a and were skipped\n", .{ambiguous});
    try out.print("  {d} named functions in b have no counterpart in a\n", .{unmatched});
}

fn report(out: *Io.Writer, b: Bundle, top: u32) !void {
    const h = b.header;
    const file_size = b.bytes.len;
    const functions = b.functions;
    const table = b.table;

    try reportIdentity(out, b.label, file_size, h);

    // fileLength covers through the end of the footer, so a file larger than
    // declared is just padding or concatenation; note it and move on.
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

    try reportDebugInfo(out, std.heap.page_allocator, b);

    try out.print("\nsection map\n", .{});
    var buf: [hbc.SECTION_COUNT]hbc.Section = undefined;
    const secs = hbc.sections(h, stats.distinct_bytes, stats.overflowed_headers, &buf);

    const known = hbc.sectionSum(secs);

    for (secs) |s| try printSection(out, s.name, s.bytes, file_size);

    // Each section is sized from the header independently, so the sum landing
    // inside the file is a real property rather than an identity. Clamping an
    // overshoot to zero would hide the one bug worth catching here: a mis-sized
    // section then reads as a tidy report with a slightly smaller rest.
    if (known > file_size) {
        try out.print("  {s:<30} {d:>12}  sections overrun the file by {d}\n", .{
            "INCONSISTENT", known, known - file_size,
        });
    } else {
        try printSection(out, "rest (info + padding)", file_size - known, file_size);
    }

    if (top > 0 and functions.len > 0) try reportTopFunctions(out, functions, table, top);
    if (top > 0) {
        if (table) |t| try reportTopStrings(out, t, top);
    }
}

fn reportTopFunctions(
    out: *Io.Writer,
    functions: []const hbc.Function,
    table: ?strings.Table,
    top: u32,
) !void {
    // On its own copy. Sorting the caller's slice left the bundle's functions
    // in size order for everything that ran afterwards, and module attribution
    // walks them in index order to rebuild each one's virtual offset. It read
    // whatever this had left behind and attributed the bytes to the wrong
    // modules, which is a wrong answer rather than a missing one.
    const gpa = std.heap.page_allocator;
    const sorted = try gpa.dupe(hbc.Function, functions);
    defer gpa.free(sorted);
    std.sort.pdq(hbc.Function, sorted, {}, hbc.moreByBytecodeSize);
    const n = @min(@as(usize, top), sorted.len);

    try out.print("\ntop {d} functions by bytecode size\n", .{n});
    for (sorted[0..n]) |f| {
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
    // Integer tenths, so output is identical on every platform.
    const tenths: u64 = if (total == 0) 0 else bytes * 1000 / total;
    try out.print("  {s:<30} {d:>12}  {d:>3}.{d}%\n", .{
        name, bytes, tenths / 10, tenths % 10,
    });
}

test "listing the top functions leaves the caller's order alone" {
    const gpa = std.testing.allocator;

    // Index order, sizes deliberately not in it. Module attribution rebuilds
    // each function's virtual offset by summing sizes in this order, so a
    // report that reorders them in place silently moves the bytes.
    var functions = [_]hbc.Function{
        .{ .index = 0, .offset = 0, .param_count = 0, .bytecode_size = 10, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = @bitCast(@as(u8, 0)), .from_large_header = false },
        .{ .index = 1, .offset = 10, .param_count = 0, .bytecode_size = 900, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = @bitCast(@as(u8, 0)), .from_large_header = false },
        .{ .index = 2, .offset = 910, .param_count = 0, .bytecode_size = 50, .name_id = 0, .info_offset = 0, .frame_size = 0, .environment_size = 0, .flags = @bitCast(@as(u8, 0)), .from_large_header = false },
    };
    const before = functions;

    var w = std.Io.Writer.Allocating.init(gpa);
    defer w.deinit();
    try reportTopFunctions(&w.writer, &functions, null, 3);

    for (before, functions) |want, got| {
        try std.testing.expectEqual(want.index, got.index);
        try std.testing.expectEqual(want.bytecode_size, got.bytecode_size);
    }
    // The listing itself still has to come out largest first.
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "900").? <
        std.mem.indexOf(u8, w.written(), "50").?);
}

test "looksLikeText spots a plain-JS dev bundle" {
    try std.testing.expect(looksLikeText("\"use strict\";\nvar x = 1;"));
    try std.testing.expect(looksLikeText("// comment\n(function(){})()"));
    try std.testing.expect(!looksLikeText(&[_]u8{ 0xC6, 0x1F, 0xBC, 0x03 }));
    try std.testing.expect(!looksLikeText(""));
}
