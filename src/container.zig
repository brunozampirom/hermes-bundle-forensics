//! Reading a Hermes bundle straight out of an app container.
//!
//! `.apk`, `.aab` and `.ipa` are all zip files, so one code path covers all
//! three. We detect by signature rather than by extension: the extension is a
//! convention, the `PK\x03\x04` at offset 0 is the format.
//!
//! `std.zip` iterates the central directory and can decompress, but its
//! `Entry.extract` only writes to a directory. We want the bytes in memory, so
//! we reuse its iterator and do the local-header walk ourselves.

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

/// Paths that hold a Hermes bundle in the containers we care about:
///   .apk  assets/index.android.bundle
///   .aab  base/assets/index.android.bundle
///   .ipa  Payload/<App>.app/main.jsbundle
/// Matching on the tail keeps this working for split APKs and feature modules,
/// where the prefix varies.
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

/// Every entry in the container that looks like a Hermes bundle.
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

        // The central directory records where the local header is; the data
        // starts after that header plus its own (possibly different) filename
        // and extra fields.
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
