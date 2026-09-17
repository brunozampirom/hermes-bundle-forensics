//! Renders a size tree as one self-contained HTML file.
//!
//! No CDN, no bundler, no server. The page is the output, so it still opens in
//! five years and it can be attached to a build artifact or a pull request.
//!
//! Names come out of the bundle being analysed, which means they are attacker
//! controlled in the only sense that matters here: a string in someone's app
//! can contain `</script>`. Everything going into the embedded JSON is escaped
//! for that.

const std = @import("std");
const Io = std.Io;
const tree = @import("tree.zig");

fn writeJsonString(out: *Io.Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try out.writeAll("\\\""),
        '\\' => try out.writeAll("\\\\"),
        '\n' => try out.writeAll("\\n"),
        '\r' => try out.writeAll("\\r"),
        '\t' => try out.writeAll("\\t"),
        // `<` and `&` cannot end the script element once escaped, which is the
        // whole reason they are here.
        '<' => try out.writeAll("\\u003c"),
        '>' => try out.writeAll("\\u003e"),
        '&' => try out.writeAll("\\u0026"),
        else => {
            if (c < 0x20) {
                try out.print("\\u{x:0>4}", .{c});
            } else {
                try out.writeByte(c);
            }
        },
    };
}

fn writeNode(out: *Io.Writer, node: tree.Node) !void {
    try out.writeAll("{\"n\":\"");
    try writeJsonString(out, node.name);
    try out.print("\",\"b\":{d}", .{node.bytes});
    if (node.children.len > 0) {
        try out.writeAll(",\"c\":[");
        for (node.children, 0..) |c, i| {
            if (i > 0) try out.writeByte(',');
            try writeNode(out, c);
        }
        try out.writeByte(']');
    }
    try out.writeByte('}');
}

fn writeDiffNode(out: *Io.Writer, node: tree.DiffNode) !void {
    try out.writeAll("{\"n\":\"");
    try writeJsonString(out, node.name);
    try out.print("\",\"b\":{d},\"a\":{d}", .{ node.b_bytes, node.a_bytes });
    if (node.children.len > 0) {
        try out.writeAll(",\"c\":[");
        for (node.children, 0..) |c, i| {
            if (i > 0) try out.writeByte(0x2C);
            try writeDiffNode(out, c);
        }
        try out.writeByte(0x5d);
    }
    try out.writeByte(0x7d);
}

/// Tiles are sized by the second bundle, so they still partition it. What is
/// only in the first has no area and the page lists it under the map instead.
pub fn writeDiff(
    out: *Io.Writer,
    label_a: []const u8,
    label_b: []const u8,
    root: tree.DiffNode,
) !void {
    try out.writeAll(head);
    try out.writeAll("<h1 title=\"");
    try writeHtmlText(out, label_b);
    try out.writeAll("\">");
    try writeShortLabel(out, label_b);
    try out.writeAll("</h1>\n<p class=\"sub\" title=\"");
    try writeHtmlText(out, label_a);
    try out.writeAll("\">compared against ");
    try writeShortLabel(out, label_a);
    try out.print(" &middot; {d} to {d} bytes", .{ root.a_bytes, root.b_bytes });
    try out.writeAll("</p>\n");
    try out.writeAll(body);
    try out.writeAll("<script>\nconst DATA = ");
    try writeDiffNode(out, root);
    try out.writeAll(";\n");
    try out.writeAll(script);
}

pub fn write(out: *Io.Writer, label: []const u8, version: u32, root: tree.Node) !void {
    try out.writeAll(head);
    try out.writeAll("<h1 title=\"");
    try writeHtmlText(out, label);
    try out.writeAll("\">");
    try writeShortLabel(out, label);
    try out.writeAll("</h1>\n<p class=\"sub\">");
    try out.print("{d} bytes &middot; bytecode version {d}", .{ root.bytes, version });
    try out.writeAll("</p>\n");
    try out.writeAll(body);
    try out.writeAll("<script>\nconst DATA = ");
    try writeNode(out, root);
    try out.writeAll(";\n");
    try out.writeAll(script);
}

/// A label is a full path, often with a container entry after `!`, and the
/// heading only needs enough of it to tell two artifacts apart. The whole
/// thing stays in the tooltip.
fn writeShortLabel(out: *Io.Writer, label: []const u8) !void {
    const bang = std.mem.indexOfScalar(u8, label, '!');
    const left = if (bang) |i| label[0..i] else label;
    try writeHtmlText(out, basename(left));
    if (bang) |i| {
        try out.writeByte('!');
        try writeHtmlText(out, basename(label[i + 1 ..]));
    }
}

fn basename(p: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfAny(u8, p, "/\\") orelse return p;
    return p[slash + 1 ..];
}

fn writeHtmlText(out: *Io.Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '<' => try out.writeAll("&lt;"),
        '>' => try out.writeAll("&gt;"),
        '&' => try out.writeAll("&amp;"),
        '"' => try out.writeAll("&quot;"),
        else => try out.writeByte(c),
    };
}

const head =
    \\<!doctype html>
    \\<html lang="en">
    \\<head>
    \\<meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width, initial-scale=1">
    \\<title>hbcinfo</title>
    \\<style>
    \\:root { color-scheme: light dark; --bg:#fff; --fg:#111; --muted:#666; --line:#ddd; }
    \\@media (prefers-color-scheme: dark) {
    \\  :root { --bg:#111; --fg:#eee; --muted:#999; --line:#333; }
    \\}
    \\* { box-sizing: border-box; }
    \\body { margin:0; padding:16px; background:var(--bg); color:var(--fg);
    \\       font:14px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    \\h1 { font-size:15px; font-weight:600; margin:0; word-break:break-all; }
    \\/* A diff subtitle carries two file paths, and a path has nowhere to wrap. */
    \\.sub { color:var(--muted); margin:4px 0 12px; word-break:break-all; }
    \\#crumbs { margin-bottom:8px; min-height:22px; }
    \\#crumbs button { font:inherit; background:none; border:0; padding:2px 4px;
    \\                 color:var(--fg); cursor:pointer; text-decoration:underline; }
    \\#crumbs span { color:var(--muted); }
    \\#map { position:relative; width:100%; height:70vh; min-height:360px;
    \\       border:1px solid var(--line); overflow:hidden; }
    \\/* An inset shadow rather than a border, and padding only on tiles that
    \\   carry a label. Both take space a small tile does not have, and a tile
    \\   drawn larger than its share is a treemap telling a lie. */
    \\.tile { position:absolute; overflow:hidden; font-size:11px; line-height:1.25;
    \\        cursor:default; box-shadow: inset 0 0 0 1px rgba(0,0,0,.35); }
    \\.tile.lbl { padding:3px 5px; }
    \\.tile.has-kids { cursor:pointer; }
    \\/* anywhere, not break-all: break inside a word only when there is no
    \\   space to break at, so "array buffer" does not become "array buf fer". */
    \\.tile b { font-weight:600; display:block; overflow-wrap:anywhere; }
    \\.tile i { font-style:normal; opacity:.75; }
    \\#tip { position:fixed; z-index:9; max-width:min(70vw,520px); padding:6px 8px;
    \\       background:var(--bg); color:var(--fg); border:1px solid var(--line);
    \\       font-size:12px; pointer-events:none; display:none; word-break:break-all; }
    \\#removed { margin-top:12px; font-size:12px; }
    \\#removed h2 { font-size:12px; font-weight:600; margin:0 0 4px; }
    \\#removed div { color:var(--muted); word-break:break-all; }
    \\#legend { margin-top:8px; font-size:12px; color:var(--muted); }
    \\#legend span { display:inline-block; width:10px; height:10px; margin:0 4px 0 12px;
    \\               vertical-align:middle; border:1px solid rgba(0,0,0,.3); }
    \\</style>
    \\</head>
    \\<body>
    \\
;

const body =
    \\<div id="crumbs"></div>
    \\<div id="map"></div>
    \\<div id="removed"></div>
    \\<div id="tip"></div>
    \\
;

const script =
    \\const map = document.getElementById('map');
    \\const tip = document.getElementById('tip');
    \\const crumbs = document.getElementById('crumbs');
    \\let path = [DATA];
    \\
    \\const fmt = n => n.toLocaleString('en-US');
    \\const pct = (a, b) => b > 0 ? (a / b * 100).toFixed(1) + '%' : '0%';
    \\
    \\// A diff node carries the old size as well, which is the only difference
    \\// between the two pages and keeps this to one code path.
    \\const isDiff = DATA.a !== undefined;
    \\
    \\function hue(name) {
    \\  let h = 0;
    \\  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    \\  return h % 360;
    \\}
    \\
    \\// In diff mode colour carries the delta, so it cannot also carry identity.
    \\function fill(node, hasKids) {
    \\  if (!isDiff) {
    \\    const l = hasKids ? 42 : 58;
    \\    return ['hsl(' + hue(node.n) + ' 55% ' + l + '%)', l < 50 ? '#fff' : '#111'];
    \\  }
    \\  const d = node.b - node.a;
    \\  if (d === 0) return ['hsl(0 0% 62%)', '#111'];
    \\  const base = node.a > 0 ? node.a : node.b;
    \\  const share = Math.min(Math.abs(d) / base, 1);
    \\  // Saturation as well as lightness, or a two byte change looks as
    \\  // alarming as a doubling and only slightly paler.
    \\  const sat = 10 + share * 58;
    \\  const light = 74 - share * 34;
    \\  return ['hsl(' + (d > 0 ? 8 : 145) + ' ' + sat + '% ' + light + '%)',
    \\          light < 50 ? '#fff' : '#111'];
    \\}
    \\
    \\function describe(node, parent) {
    \\  const own = fmt(node.b) + ' bytes, ' + pct(node.b, parent.b) + ' of ' + parent.n;
    \\  if (!isDiff) return node.n + ' - ' + own + ', ' + pct(node.b, DATA.b) + ' of file';
    \\  const d = node.b - node.a;
    \\  const sign = d > 0 ? '+' : '';
    \\  return node.n + ' - ' + fmt(node.a) + ' to ' + fmt(node.b) +
    \\    ' bytes (' + sign + fmt(d) + '), ' + pct(node.b, parent.b) + ' of ' + parent.n;
    \\}
    \\
    \\// Squarified treemap: keep each row's tiles as close to square as possible,
    \\// which is what makes areas comparable by eye.
    \\function worst(row, sum, side) {
    \\  const mx = Math.max.apply(null, row), mn = Math.min.apply(null, row);
    \\  const s2 = sum * sum, d2 = side * side;
    \\  return Math.max(d2 * mx / s2, s2 / (d2 * mn));
    \\}
    \\
    \\function layout(items, x, y, w, h) {
    \\  const out = [];
    \\  const live = items.filter(n => n.b > 0);
    \\  let remaining = live.reduce((s, n) => s + n.b, 0);
    \\  if (remaining <= 0) return out;
    \\  let i = 0;
    \\  while (i < live.length && w > 1 && h > 1) {
    \\    const horizontal = w >= h;
    \\    const side = horizontal ? h : w;
    \\    const scale = (w * h) / remaining;
    \\    let row = [], sum = 0, best = Infinity, start = i;
    \\    while (i < live.length) {
    \\      const area = live[i].b * scale;
    \\      const cand = row.concat([area]);
    \\      const s2 = sum + area;
    \\      const r = worst(cand, s2, side);
    \\      if (row.length > 0 && r > best) break;
    \\      row = cand; sum = s2; best = r; i++;
    \\    }
    \\    const thick = sum / side;
    \\    let pos = horizontal ? y : x;
    \\    for (let k = 0; k < row.length; k++) {
    \\      const len = row[k] / thick;
    \\      out.push(horizontal
    \\        ? { node: live[start + k], x: x, y: pos, w: thick, h: len }
    \\        : { node: live[start + k], x: pos, y: y, w: len, h: thick });
    \\      pos += len;
    \\    }
    \\    if (horizontal) { x += thick; w -= thick; } else { y += thick; h -= thick; }
    \\    remaining -= sum / scale;
    \\  }
    \\  return out;
    \\}
    \\
    \\function draw() {
    \\  const node = path[path.length - 1];
    \\  const kids = (node.c || []).slice().sort((a, b) => b.b - a.b);
    \\  map.innerHTML = '';
    \\
    \\  crumbs.innerHTML = '';
    \\  path.forEach((p, i) => {
    \\    if (i > 0) crumbs.appendChild(document.createTextNode(' / '));
    \\    if (i === path.length - 1) {
    \\      const s = document.createElement('span');
    \\      s.textContent = p.n;
    \\      crumbs.appendChild(s);
    \\    } else {
    \\      const b = document.createElement('button');
    \\      b.textContent = p.n;
    \\      b.onclick = () => { path = path.slice(0, i + 1); draw(); };
    \\      crumbs.appendChild(b);
    \\    }
    \\  });
    \\
    \\  if (!kids.length) {
    \\    const p = document.createElement('p');
    \\    p.className = 'sub';
    \\    p.textContent = 'no breakdown for this section; the file gives only its size';
    \\    map.appendChild(p);
    \\    return;
    \\  }
    \\
    \\  const rects = layout(kids, 0, 0, map.clientWidth, map.clientHeight);
    \\  const total = DATA.b;
    \\  for (const r of rects) {
    \\    const el = document.createElement('div');
    \\    el.className = 'tile' + (r.node.c ? ' has-kids' : '');
    \\    el.style.left = r.x + 'px';
    \\    el.style.top = r.y + 'px';
    \\    el.style.width = r.w + 'px';
    \\    el.style.height = r.h + 'px';
    \\    const paint = fill(r.node, !!r.node.c);
    \\    el.style.background = paint[0];
    \\    el.style.color = paint[1];
    \\    if (r.w > 60 && r.h > 26) {
    \\      el.classList.add('lbl');
    \\      el.innerHTML = '<b></b><i></i>';
    \\      el.querySelector('b').textContent = r.node.n;
    \\      el.querySelector('i').textContent = fmt(r.node.b) + '  ' + pct(r.node.b, node.b);
    \\    }
    \\    el.onmousemove = e => {
    \\      tip.style.display = 'block';
    \\      tip.style.left = Math.min(e.clientX + 12, innerWidth - 540) + 'px';
    \\      tip.style.top = (e.clientY + 14) + 'px';
    \\      tip.textContent = describe(r.node, node);
    \\    };
    \\    el.onmouseleave = () => { tip.style.display = 'none'; };
    \\    if (r.node.c) el.onclick = () => { path.push(r.node); tip.style.display = 'none'; draw(); };
    \\    map.appendChild(el);
    \\  }
    \\
    \\  drawGone(kids, node);
    \\}
    \\
    \\// A node the second bundle no longer has is zero bytes, so it has no tile.
    \\// Dropping it from the page entirely would hide the thing someone removing
    \\// code most wants to see, so it goes in a list under the map.
    \\function drawGone(kids, parent) {
    \\  const box = document.getElementById('removed');
    \\  box.innerHTML = '';
    \\  if (!isDiff) return;
    \\
    \\  const gone = kids.filter(k => k.b === 0 && k.a > 0).sort((x, y) => y.a - x.a);
    \\  if (!gone.length) {
    \\    const d = document.createElement('div');
    \\    d.className = 'note';
    \\    d.textContent = 'nothing was dropped from ' + parent.n;
    \\    box.appendChild(d);
    \\    return;
    \\  }
    \\
    \\  const h = document.createElement('h2');
    \\  const total = gone.reduce((s, g) => s + g.a, 0);
    \\  h.textContent = 'gone from ' + parent.n + ': ' + gone.length + ' entries, ' +
    \\    fmt(total) + ' bytes';
    \\  box.appendChild(h);
    \\  for (const g of gone.slice(0, 40)) {
    \\    const d = document.createElement('div');
    \\    d.textContent = '-' + fmt(g.a) + '  ' + g.n;
    \\    box.appendChild(d);
    \\  }
    \\  if (gone.length > 40) {
    \\    const d = document.createElement('div');
    \\    d.textContent = 'and ' + (gone.length - 40) + ' more';
    \\    box.appendChild(d);
    \\  }
    \\}
    \\
    \\if (isDiff) {
    \\  const l = document.createElement('div');
    \\  l.id = 'legend';
    \\  l.innerHTML = 'area is the new bundle' +
    \\    '<span style="background:hsl(8 60% 55%)"></span>grew' +
    \\    '<span style="background:hsl(145 60% 55%)"></span>shrank' +
    \\    '<span style="background:hsl(0 0% 62%)"></span>unchanged';
    \\  crumbs.parentNode.insertBefore(l, crumbs);
    \\}
    \\
    \\addEventListener('resize', draw);
    \\draw();
    \\</script>
    \\</body>
    \\</html>
    \\
;
