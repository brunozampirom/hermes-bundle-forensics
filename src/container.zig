//! `.apk`, `.aab` and `.ipa` are all zip files, so one path covers all three.
//!
//! `std.zip`'s `Entry.extract` only writes to a directory, so we reuse its
//! central directory iterator and walk to the local header ourselves.

const std = @import("std");
const Io = std.Io;
const zip = std.zip;

pub const Error = error{
    NoBundleFound,
    EntryNotFound,
    UnsupportedCompressionMethod,
    BadLocalHeader,
    ShortRead,
};

pub const signature = zip.local_file_header_sig;

pub fn looksLikeZip(first_bytes: []const u8) bool {
    return first_bytes.len >= 4 and std.mem.eql(u8, first_bytes[0..4], &signature);
}

/// Matched on the tail, since the prefix varies across split APKs and feature
/// modules: `assets/`, `base/assets/`, `Payload/<App>.app/`.
pub fn looksLikeBundleName(name: []const u8) bool {
    return std.mem.endsWith(u8, name, "index.android.bundle") or
        std.mem.endsWith(u8, name, "main.jsbundle") or
        std.mem.endsWith(u8, name, ".hbc");
}

pub const Entry = struct {
    name: []u8,
    uncompressed_size: u64,
    compressed_size: u64,
    stored: bool,
};

/// Every entry that looks like a Hermes bundle.
pub fn findBundles(gpa: std.mem.Allocator, input: *Io.File.Reader) ![]Entry {
    var found: std.ArrayList(Entry) = .empty;
    errdefer {
        for (found.items) |e| gpa.free(e.name);
        found.deinit(gpa);
    }

    var name_buf: [std.math.maxInt(u16)]u8 = undefined;
    var it = try zip.Iterator.init(input);
    while (try it.next()) |entry| {
        const name = name_buf[0..entry.filename_len];
        try input.seekTo(entry.header_zip_offset + @sizeOf(zip.CentralDirectoryFileHeader));
        try input.interface.readSliceAll(name);

        if (!looksLikeBundleName(name)) continue;

        try found.append(gpa, .{
            .name = try gpa.dupe(u8, name),
            .uncompressed_size = entry.uncompressed_size,
            .compressed_size = entry.compressed_size,
            .stored = entry.compression_method == .store,
        });
    }

    return found.toOwnedSlice(gpa);
}

/// Reads one entry into memory by name. Caller owns the returned bytes.
pub fn readEntry(
    gpa: std.mem.Allocator,
    input: *Io.File.Reader,
    wanted: []const u8,
) ![]u8 {
    var name_buf: [std.math.maxInt(u16)]u8 = undefined;
    var it = try zip.Iterator.init(input);

    while (try it.next()) |entry| {
        const name = name_buf[0..entry.filename_len];
        try input.seekTo(entry.header_zip_offset + @sizeOf(zip.CentralDirectoryFileHeader));
        try input.interface.readSliceAll(name);
        if (!std.mem.eql(u8, name, wanted)) continue;

        switch (entry.compression_method) {
            .store, .deflate => {},
            else => return error.UnsupportedCompressionMethod,
        }

        // Data starts after the local header plus its own filename and extra
        // fields, whose lengths can differ from the central directory's.
        try input.seekTo(entry.file_offset);
        const local = try input.interface.takeStruct(zip.LocalFileHeader, .little);
        if (!std.mem.eql(u8, &local.signature, &zip.local_file_header_sig)) {
            return error.BadLocalHeader;
        }
        const data_at = entry.file_offset + @sizeOf(zip.LocalFileHeader) +
            @as(u64, local.filename_len) + @as(u64, local.extra_len);
        try input.seekTo(data_at);

        const out = try gpa.alloc(u8, @intCast(entry.uncompressed_size));
        errdefer gpa.free(out);

        if (entry.compression_method == .store) {
            try input.interface.readSliceAll(out);
        } else {
            var window: [64 * 1024]u8 = undefined;
            var decomp: std.compress.flate.Decompress = .init(&input.interface, .raw, &window);
            try decomp.reader.readSliceAll(out);
        }

        return out;
    }

    return error.EntryNotFound;
}

// The zip reading itself has no unit test; it is covered end to end by
// checking that reading from a container matches unzipping first.

const testing = std.testing;

test "detects a zip container by signature, not extension" {
    try testing.expect(looksLikeZip("PK\x03\x04rest"));
    try testing.expect(!looksLikeZip("PK\x05\x06")); // empty-archive record
    try testing.expect(!looksLikeZip(&[_]u8{ 0xC6, 0x1F, 0xBC, 0x03 }));
    try testing.expect(!looksLikeZip("PK"));
    try testing.expect(!looksLikeZip(""));
}

test "recognises bundle paths in each container layout" {
    try testing.expect(looksLikeBundleName("assets/index.android.bundle"));
    try testing.expect(looksLikeBundleName("base/assets/index.android.bundle"));
    try testing.expect(looksLikeBundleName("Payload/Sintonia.app/main.jsbundle"));
    try testing.expect(looksLikeBundleName("whatever/app.hbc"));
    try testing.expect(!looksLikeBundleName("res/drawable/icon.png"));
    try testing.expect(!looksLikeBundleName("AndroidManifest.xml"));
}
