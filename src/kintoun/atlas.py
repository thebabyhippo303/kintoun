"""Self-contained zero-dependency HTML Decomp Atlas & Run Report generator (`kintoun atlas`).

Generates a single interactive `atlas.html` file that works offline and loads nothing external:
  - Project-wide function & byte-match progress bar (`done`, `near-miss`, `pending`, `quarantined`, `blocked`)
  - Pure-stdlib 2D structural PCA scatter map over per-ISA feature vectors (hover + click inspection)
  - Module / class prefix progress bars
  - Project-calibrated logistic match-probability scores (`estimated_match_prob`)
  - Instant searchable/sortable function table + detail drawer with disassembly, hints, and 1-click CLI copy
"""
from __future__ import annotations

import html
import json
import math
from pathlib import Path
from typing import Any

from kintoun import __version__
from kintoun.config import KintounConfig
from kintoun.inspect_fn import decode_target_features, score_difficulty
from kintoun.queue import WorkQueue
from kintoun.similarity import (
    extract_numeric_features,
    fit_project_difficulty_model,
    index_matched_c_functions,
    predict_match_probability,
)
from kintoun.targets import TargetContext


def _project_2d_pca(vectors: list[list[float]]) -> list[tuple[float, float]]:
    """Pure-stdlib deterministic 2D PCA projection using deflated power iteration (zero numpy)."""
    n = len(vectors)
    if n == 0:
        return []
    if n == 1:
        return [(0.5, 0.5)]
    dim = len(vectors[0])
    means = [sum(v[j] for v in vectors) / n for j in range(dim)]
    stds = [
        max(1e-6, math.sqrt(sum((v[j] - means[j]) ** 2 for v in vectors) / n))
        for j in range(dim)
    ]
    centered = [[(v[j] - means[j]) / stds[j] for j in range(dim)] for v in vectors]

    # Covariance matrix C = X^T X / n  (10x10 -> microseconds in pure Python)
    cov = [[0.0] * dim for _ in range(dim)]
    for row in centered:
        for i in range(dim):
            ri = row[i]
            for j in range(i, dim):
                cov[i][j] += ri * row[j]
    for i in range(dim):
        for j in range(i, dim):
            cov[i][j] /= n
            cov[j][i] = cov[i][j]

    def _top_eigvec(mat: list[list[float]], seed_idx: int) -> tuple[list[float], float]:
        vec = [1.0 if k == seed_idx % dim else 0.25 / (k + 1) for k in range(dim)]
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        vec = [x / norm for x in vec]
        eigval = 0.0
        for _ in range(32):
            nxt = [sum(mat[i][j] * vec[j] for j in range(dim)) for i in range(dim)]
            eigval = math.sqrt(sum(x * x for x in nxt))
            if eigval < 1e-9:
                break
            vec = [x / eigval for x in nxt]
        return vec, eigval

    v1, lam1 = _top_eigvec(cov, 0)
    cov2 = [
        [cov[i][j] - lam1 * v1[i] * v1[j] for j in range(dim)]
        for i in range(dim)
    ]
    v2, _ = _top_eigvec(cov2, 1)

    xs = [sum(row[j] * v1[j] for j in range(dim)) for row in centered]
    ys = [sum(row[j] * v2[j] for j in range(dim)) for row in centered]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    span_x = (max_x - min_x) or 1.0
    span_y = (max_y - min_y) or 1.0
    return [(round((x - min_x) / span_x, 4), round((y - min_y) / span_y, 4)) for x, y in zip(xs, ys)]


def build_atlas_data(
    ctx: TargetContext,
    cfg: KintounConfig | None = None,
    *,
    src_dir: Path | None = None,
    max_functions: int = 2000,
) -> dict[str, Any]:
    """Assemble full project telemetry, 2D structural Atlas coordinates, and match probabilities."""
    eff_src = src_dir
    if eff_src is None and cfg is not None:
        cand = cfg.root / "src"
        if cand.is_dir():
            eff_src = cand
    matched_src = index_matched_c_functions(eff_src)

    queue_rows: dict[str, dict[str, Any]] = {}
    hints_dir: Path | None = None
    if cfg is not None:
        cache_dir = cfg.resolve_path(cfg.search.cache_dir) or (cfg.root / ".kintoun" / "cache")
        kdir = cache_dir.parent
        hints_dir = kdir / "hints"
        if (kdir / "queue.sqlite3").is_file():
            wq = WorkQueue(kdir)
            with wq._connect() as conn:
                for r in conn.execute("SELECT * FROM queue").fetchall():
                    queue_rows[r["name"]] = dict(r)

    raw_items: list[tuple[str, int, int, Any, list[float], dict[str, Any]]] = []
    labeled_samples: list[tuple[list[float], int]] = []

    sorted_funcs = sorted(ctx.funcs.items(), key=lambda kv: kv[1][0])[:max_functions]
    for name, (va, size) in sorted_funcs:
        if size <= 0:
            continue
        try:
            tf = ctx.resolve_function(name)
        except Exception:
            continue
        fvec = extract_numeric_features(tf, ctx)
        qrow = queue_rows.get(name, {})
        q_status = qrow.get("status", "")
        is_done = q_status == "done" or name in matched_src
        if is_done:
            labeled_samples.append((fvec, 1))
        elif q_status in ("quarantined", "blocked") or int(qrow.get("timeouts", 0)) > 0:
            labeled_samples.append((fvec, 0))
        raw_items.append((name, va, size, tf, fvec, qrow))

    model = fit_project_difficulty_model(labeled_samples)
    coords = _project_2d_pca([it[4] for it in raw_items])

    functions_out: list[dict[str, Any]] = []
    module_stats: dict[str, dict[str, int]] = {}
    counts = {"done": 0, "near_miss": 0, "pending": 0, "claimed": 0, "quarantined": 0, "blocked": 0}
    bytes_done = 0
    bytes_total = 0

    for (name, va, size, tf, fvec, qrow), (px, py) in zip(raw_items, coords):
        dec = decode_target_features(tf, ctx)
        best_pct = float(qrow.get("best_pct", 0.0))
        diff = score_difficulty(tf, ctx, timeouts=int(qrow.get("timeouts", 0)), best_pct=best_pct)
        prob = predict_match_probability(fvec, model)

        q_status = qrow.get("status", "")
        if q_status == "done" or name in matched_src:
            status = "done"
            best_pct = 100.0
            bytes_done += size
        elif not diff["plain_c"] or q_status == "blocked":
            status = "blocked"
        elif q_status == "quarantined":
            status = "quarantined"
        elif q_status == "claimed":
            status = "claimed"
        elif best_pct >= 85.0:
            status = "near_miss"
        else:
            status = "pending"

        counts[status] = counts.get(status, 0) + 1
        bytes_total += size

        mod = name.split("__", 1)[0] if "__" in name else (name.split("_", 1)[0] if "_" in name else "global")
        m_entry = module_stats.setdefault(mod, {"total": 0, "done": 0, "bytes": 0, "done_bytes": 0})
        m_entry["total"] += 1
        m_entry["bytes"] += size
        if status == "done":
            m_entry["done"] += 1
            m_entry["done_bytes"] += size

        hint_summary = ""
        if hints_dir is not None and (hints_dir / f"{name}.json").is_file():
            try:
                hobj = json.loads((hints_dir / f"{name}.json").read_text(encoding="utf-8"))
                hint_summary = str(hobj.get("primary_class", ""))
            except Exception:
                hint_summary = ""

        disasm_preview = "\n".join(dec["disasm"].splitlines()[:28])
        functions_out.append(
            {
                "name": name,
                "addr": f"0x{va:08X}",
                "size_bytes": size,
                "module": mod,
                "status": status,
                "tier": diff["tier"],
                "difficulty": diff["score"],
                "match_prob": prob,
                "best_pct": round(best_pct, 1),
                "tags": diff["tags"],
                "callees": dec["callees"][:8],
                "x": px,
                "y": py,
                "hint_class": hint_summary,
                "disasm": disasm_preview,
            }
        )

    modules_list = [
        {
            "module": k,
            **v,
            "pct": round(100.0 * v["done"] / max(1, v["total"]), 1),
        }
        for k, v in sorted(module_stats.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))[:24]
    ]

    return {
        "version": __version__,
        "project": cfg.project_name if cfg else "kintoun-project",
        "arch": ctx.arch,
        "preset": cfg.compiler.preset if cfg else "custom",
        "total_functions": len(functions_out),
        "total_bytes": bytes_total,
        "matched_bytes": bytes_done,
        "matched_bytes_pct": round(100.0 * bytes_done / max(1, bytes_total), 2),
        "counts": counts,
        "logistic_model": {
            "trained": model["trained"],
            "sample_count": model["sample_count"],
        },
        "modules": modules_list,
        "functions": functions_out,
    }


def render_atlas_html(atlas_data: dict[str, Any]) -> str:
    """Render a self-contained dark-mode interactive HTML5 Decomp Atlas & Run Report."""
    proj = html.escape(str(atlas_data.get("project", "kintoun")))
    arch = html.escape(str(atlas_data.get("arch", "")))
    preset = html.escape(str(atlas_data.get("preset", "")))
    ver = html.escape(str(atlas_data.get("version", __version__)))
    payload_json = json.dumps(atlas_data).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kintoun Atlas - {proj}</title>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --done: #2ea043; --near: #d29922; --pending: #58a6ff; --claimed: #a371f7; --quar: #f85149; --blocked: #6e7681;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); }}
  header {{ padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }}
  .badge {{ background: var(--panel); border: 1px solid var(--border); padding: 4px 10px; border-radius: 999px; font-size: 12px; color: var(--muted); }}
  .grid {{ display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 16px; padding: 16px 24px; }}
  @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }}
  .card h2 {{ margin: 0 0 12px 0; font-size: 15px; font-weight: 600; }}
  .bar {{ height: 14px; background: #21262d; border-radius: 7px; overflow: hidden; display: flex; margin: 10px 0; }}
  .kpis {{ display: flex; gap: 16px; flex-wrap: wrap; font-size: 13px; color: var(--muted); }}
  .kpis strong {{ color: var(--text); }}
  canvas {{ width: 100%; height: 290px; background: #090d13; border-radius: 8px; border: 1px solid var(--border); cursor: crosshair; }}
  .controls {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }}
  input, select, button {{ background: #0d1117; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-size: 13px; }}
  button:hover {{ border-color: var(--pending); cursor: pointer; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 7px 8px; border-bottom: 1px solid #21262d; }}
  tr:hover {{ background: #1f2630; cursor: pointer; }}
  .pill {{ padding: 2px 7px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
  .st-done {{ background: rgba(46,160,67,0.2); color: #56d364; }}
  .st-near_miss {{ background: rgba(210,153,34,0.2); color: #e3b341; }}
  .st-pending {{ background: rgba(88,166,255,0.18); color: #79c0ff; }}
  .st-claimed {{ background: rgba(163,113,247,0.2); color: #d2a8ff; }}
  .st-quarantined {{ background: rgba(248,81,73,0.2); color: #ffa198; }}
  .st-blocked {{ background: rgba(110,118,129,0.25); color: #8b949e; }}
  pre {{ background: #090d13; border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow-x: auto; font-size: 12px; line-height: 1.45; margin: 8px 0 0 0; }}
  .mod-row {{ display: flex; align-items: center; gap: 8px; font-size: 12px; margin-bottom: 6px; }}
  .mod-name {{ width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .mod-track {{ flex: 1; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; }}
  .mod-fill {{ height: 100%; background: var(--done); }}
</style>
</head>
<body>
<header>
  <div>
    <strong style="font-size:18px;">Kintoun Decomp Atlas</strong>
    <span style="color:var(--muted); margin-left:10px;">{proj}</span>
  </div>
  <div style="display:flex; gap:8px; flex-wrap:wrap;">
    <span class="badge">arch: {arch}</span>
    <span class="badge">preset: {preset}</span>
    <span class="badge">kintoun {ver}</span>
  </div>
</header>

<div style="padding: 16px 24px 0 24px;">
  <div class="card">
    <div class="kpis" id="kpi-row"></div>
    <div class="bar" id="cov-bar"></div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>2D Structural Function Map (PCA over Per-ISA Opcode &amp; CFG Vectors)</h2>
    <canvas id="scatter" width="680" height="290"></canvas>
    <div style="font-size:12px; color:var(--muted); margin-top:6px;" id="hover-line">Click any point or table row to inspect disassembly and copy Kintoun CLI commands.</div>
  </div>
  <div class="card">
    <h2>Selected Function Inspector</h2>
    <div id="inspector" style="font-size:13px; color:var(--muted);">Select a function to view details.</div>
    <h2 style="margin-top:16px;">Top Modules by Byte Coverage</h2>
    <div id="modules"></div>
  </div>
</div>

<div style="padding: 0 24px 24px 24px;">
  <div class="card">
    <h2>Function Explorer</h2>
    <div class="controls">
      <input id="q" type="search" placeholder="Search name, addr, or callee..." style="min-width:220px;">
      <select id="st">
        <option value="">All statuses</option>
        <option value="pending">pending</option>
        <option value="near_miss">near_miss (&gt;=85%)</option>
        <option value="done">done</option>
        <option value="claimed">claimed</option>
        <option value="quarantined">quarantined</option>
        <option value="blocked">blocked</option>
      </select>
      <select id="tier">
        <option value="">All tiers</option>
        <option value="easy">easy</option>
        <option value="medium">medium</option>
        <option value="hard">hard</option>
        <option value="brutal">brutal</option>
      </select>
      <select id="sort">
        <option value="prob">Sort: Highest Match Odds</option>
        <option value="pct">Sort: Best Near-Miss %</option>
        <option value="size">Sort: Smallest Size</option>
        <option value="addr">Sort: Address</option>
      </select>
    </div>
    <div style="max-height: 420px; overflow-y: auto;">
      <table>
        <thead><tr><th>Address</th><th>Function</th><th>Status</th><th>Tier</th><th>Size</th><th>Best %</th><th>Match Odds</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<script id="atlas-data" type="application/json">{payload_json}</script>
<script>
const DATA = JSON.parse(document.getElementById('atlas-data').textContent);
const COLORS = {{ done:'#2ea043', near_miss:'#d29922', pending:'#58a6ff', claimed:'#a371f7', quarantined:'#f85149', blocked:'#6e7681' }};

function renderHeader() {{
  const c = DATA.counts || {{}};
  const tot = Math.max(1, DATA.total_functions || 1);
  document.getElementById('kpi-row').innerHTML =
    `<span>Matched: <strong>${{c.done||0}} / ${{DATA.total_functions}}</strong> (${{DATA.matched_bytes_pct}}% bytes)</span>` +
    `<span>Near-Miss (&gt;=85%): <strong>${{c.near_miss||0}}</strong></span>` +
    `<span>Pending: <strong>${{c.pending||0}}</strong></span>` +
    `<span>Quarantined: <strong>${{c.quarantined||0}}</strong></span>` +
    `<span>Blocked: <strong>${{c.blocked||0}}</strong></span>` +
    `<span>Calibration: <strong>${{DATA.logistic_model.trained ? 'project-logistic ('+DATA.logistic_model.sample_count+' fns)' : 'static-prior'}}</strong></span>`;
  const bar = document.getElementById('cov-bar');
  bar.innerHTML = ['done','near_miss','claimed','pending','quarantined','blocked'].map(k => {{
    const w = (100 * (c[k]||0) / tot).toFixed(2);
    return `<div style="width:${{w}}%; background:${{COLORS[k]}}" title="${{k}}: ${{c[k]||0}}"></div>`;
  }}).join('');
  document.getElementById('modules').innerHTML = (DATA.modules||[]).slice(0,8).map(m =>
    `<div class="mod-row"><span class="mod-name" title="${{m.module}}">${{m.module}}</span>` +
    `<div class="mod-track"><div class="mod-fill" style="width:${{m.pct}}%"></div></div>` +
    `<span style="width:76px; text-align:right; color:var(--muted);">${{m.done}}/${{m.total}} (${{m.pct}}%)</span></div>`
  ).join('');
}}

function selectFn(fn) {{
  if (!fn) return;
  const cmdCtx = `kintoun context --func ${{fn.name}}`;
  const cmdPerm = `kintoun permute src/${{fn.name}}.c --func ${{fn.name}} --governed --write`;
  const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  document.getElementById('inspector').innerHTML =
    `<div><strong style="color:var(--text); font-size:15px;">${{esc(fn.name)}}</strong> <code>${{esc(fn.addr)}}</code> ` +
    `<span class="pill st-${{fn.status}}">${{fn.status}}</span></div>` +
    `<div style="margin-top:6px;">Size: ${{fn.size_bytes}}B | Tier: ${{fn.tier}} (${{fn.difficulty}}/100) | Match Odds: ${{Math.round(fn.match_prob*100)}}% | Best: ${{fn.best_pct}}%</div>` +
    (fn.tags && fn.tags.length ? `<div style="margin-top:4px;">Tags: ${{esc(fn.tags.join(', '))}}</div>` : '') +
    (fn.hint_class ? `<div style="margin-top:4px; color:#e3b341;">Closer Hint Class: ${{esc(fn.hint_class)}}</div>` : '') +
    `<div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">` +
    `<button onclick="navigator.clipboard.writeText('${{cmdCtx}}')">Copy context cmd</button>` +
    `<button onclick="navigator.clipboard.writeText('${{cmdPerm}}')">Copy permute cmd</button></div>` +
    `<pre>${{esc(fn.disasm || '(no disassembly)')}}</pre>`;
}}

function drawScatter(rows) {{
  const cv = document.getElementById('scatter');
  const ctx = cv.getContext('2d');
  ctx.clearRect(0, 0, cv.width, cv.height);
  const pad = 22;
  rows.forEach(fn => {{
    const cx = pad + fn.x * (cv.width - pad * 2);
    const cy = pad + (1 - fn.y) * (cv.height - pad * 2);
    fn._cx = cx; fn._cy = cy;
    ctx.beginPath();
    ctx.arc(cx, cy, Math.max(3.5, Math.min(9, Math.log2(fn.size_bytes + 4))), 0, Math.PI * 2);
    ctx.fillStyle = COLORS[fn.status] || '#58a6ff';
    ctx.globalAlpha = 0.85;
    ctx.fill();
  }});
  cv.onclick = e => {{
    const r = cv.getBoundingClientRect();
    const mx = (e.clientX - r.left) * (cv.width / r.width);
    const my = (e.clientY - r.top) * (cv.height / r.height);
    let best = null, bd = 144;
    rows.forEach(fn => {{
      const d = (fn._cx - mx) ** 2 + (fn._cy - my) ** 2;
      if (d < bd) {{ bd = d; best = fn; }}
    }});
    if (best) selectFn(best);
  }};
}}

function updateTable() {{
  const q = document.getElementById('q').value.toLowerCase();
  const st = document.getElementById('st').value;
  const tier = document.getElementById('tier').value;
  const sort = document.getElementById('sort').value;
  let rows = (DATA.functions || []).filter(f =>
    (!st || f.status === st) &&
    (!tier || f.tier === tier) &&
    (!q || f.name.toLowerCase().includes(q) || f.addr.toLowerCase().includes(q) || (f.callees||[]).some(c => c.toLowerCase().includes(q)))
  );
  rows.sort((a, b) => sort === 'prob' ? b.match_prob - a.match_prob : sort === 'pct' ? b.best_pct - a.best_pct : sort === 'size' ? a.size_bytes - b.size_bytes : a.addr.localeCompare(b.addr));
  const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  rows.slice(0, 400).forEach(fn => {{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${{esc(fn.addr)}}</code></td><td><strong>${{esc(fn.name)}}</strong></td>` +
      `<td><span class="pill st-${{fn.status}}">${{fn.status}}</span></td><td>${{fn.tier}} (${{fn.difficulty}})</td>` +
      `<td>${{fn.size_bytes}}B</td><td>${{fn.best_pct}}%</td><td>${{Math.round(fn.match_prob*100)}}%</td>`;
    tr.onclick = () => selectFn(fn);
    tbody.appendChild(tr);
  }});
  drawScatter(rows);
  if (rows.length) selectFn(rows[0]);
}}

['q','st','tier','sort'].forEach(id => document.getElementById(id).addEventListener('input', updateTable));
renderHeader();
updateTable();
</script>
</body>
</html>
"""


def write_atlas_report(
    out_path: Path,
    ctx: TargetContext,
    cfg: KintounConfig | None = None,
    *,
    src_dir: Path | None = None,
) -> dict[str, Any]:
    """Build project Atlas data and write self-contained `out_path` HTML file."""
    data = build_atlas_data(ctx, cfg, src_dir=src_dir)
    html_text = render_atlas_html(data)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_text, encoding="utf-8")
    return {
        "output_html": str(out),
        "bytes_written": len(html_text.encode("utf-8")),
        "total_functions": data["total_functions"],
        "counts": data["counts"],
        "matched_bytes_pct": data["matched_bytes_pct"],
        "logistic_model": data["logistic_model"],
    }
