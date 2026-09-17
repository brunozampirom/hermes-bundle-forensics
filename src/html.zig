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

pub fn write(out: *Io.Writer, label: []const u8, version: u32, root: tree.Node) !void {
    try out.writeAll(head);
    try out.writeAll("<h1>");
    try writeHtmlText(out, label);
    try out.writeAll("</h1>\n<p class=\"sub\">");
    try out.print("{d} bytes &middot; bytecode version {d}", .{ root.bytes, version });
    try out.writeAll("</p>\n");
    try out.writeAll(body);
    try out.writeAll("<script>\nconst DATA = ");
    try writeNode(out, root);
    try out.writeAll(";\n");
    try out.writeAll(script);
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
    \\.sub { color:var(--muted); margin:4px 0 12px; }
    \\#crumbs { margin-bottom:8px; min-height:22px; }
    \\#crumbs button { font:inherit; background:none; border:0; padding:2px 4px;
    \\                 color:var(--fg); cursor:pointer; text-decoration:underline; }
    \\#crumbs span { color:var(--muted); }
    \\#map { position:relative; width:100%; height:70vh; min-height:360px;
    \\       border:1px solid var(--line); overflow:hidden; }
    \\.tile { position:absolute; overflow:hidden; border:1px solid rgba(0,0,0,.35);
    \\        padding:3px 5px; font-size:11px; line-height:1.25; cursor:default; }
    \\.tile.has-kids { cursor:pointer; }
    \\.tile b { font-weight:600; display:block; word-break:break-all; }
    \\.tile i { font-style:normal; opacity:.75; }
    \\#tip { position:fixed; z-index:9; max-width:min(70vw,520px); padding:6px 8px;
    \\       background:var(--bg); color:var(--fg); border:1px solid var(--line);
    \\       font-size:12px; pointer-events:none; display:none; word-break:break-all; }
    \\</style>
    \\</head>
    \\<body>
    \\
;

const body =
    \\<div id="crumbs"></div>
    \\<div id="map"></div>
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
    \\function hue(name) {
    \\  let h = 0;
    \\  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    \\  return h % 360;
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
    \\    const l = r.node.c ? 42 : 58;
    \\    el.style.background = 'hsl(' + hue(r.node.n) + ' 55% ' + l + '%)';
    \\    el.style.color = l < 50 ? '#fff' : '#111';
    \\    if (r.w > 60 && r.h > 26) {
    \\      el.innerHTML = '<b></b><i></i>';
    \\      el.querySelector('b').textContent = r.node.n;
    \\      el.querySelector('i').textContent = fmt(r.node.b) + '  ' + pct(r.node.b, node.b);
    \\    }
    \\    el.onmousemove = e => {
    \\      tip.style.display = 'block';
    \\      tip.style.left = Math.min(e.clientX + 12, innerWidth - 540) + 'px';
    \\      tip.style.top = (e.clientY + 14) + 'px';
    \\      tip.textContent = r.node.n + ' - ' + fmt(r.node.b) + ' bytes, ' +
    \\        pct(r.node.b, node.b) + ' of ' + node.n + ', ' + pct(r.node.b, total) + ' of file';
    \\    };
    \\    el.onmouseleave = () => { tip.style.display = 'none'; };
    \\    if (r.node.c) el.onclick = () => { path.push(r.node); tip.style.display = 'none'; draw(); };
    \\    map.appendChild(el);
    \\  }
    \\}
    \\
    \\addEventListener('resize', draw);
    \\draw();
    \\</script>
    \\</body>
    \\</html>
    \\
;
