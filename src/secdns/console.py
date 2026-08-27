"""Status console — a tiny HTTP server for humans and health checks.

Routes:
  GET  /          HTML status page (zone, upstreams, live query stats) + a Reload button
  GET  /health    JSON liveness ({status, records, queries}) — for probes / `status`
  GET  /records   JSON dump of the served records
  POST /reload    re-read the zone file and return the new record count

Bound to localhost by default (see :class:`~secdns.config.Config`). Standard library only.
"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .resolver import Resolver

# Hexagon mark from work/secrouter/assets/logo.svg / logo-dark.svg, trimmed to just the
# glyph (no wordmark) — the page supplies its own "SECDNS" wordmark in text below.
_LOGO_LIGHT_SVG = (
    '<svg class="logo-light" viewBox="0 0 52 62" width="22" height="26" '
    'aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">'
    '<g transform="translate(4,5)">'
    '<polygon points="24,2 44,13 44,37 24,54 4,37 4,13" fill="none" stroke="#17140d" '
    'stroke-width="2" stroke-linejoin="round"/>'
    '<path d="M24 28 L24 14 M24 28 L14 38 M24 28 L34 38" stroke="#17140d" stroke-width="1.9"/>'
    '<path d="M24 14 L14 38 M24 14 L34 38 M14 38 L34 38" stroke="#17140d" stroke-width="1.4" '
    'stroke-opacity="0.4"/>'
    '<circle cx="24" cy="14" r="2.7" fill="#17140d"/>'
    '<circle cx="14" cy="38" r="2.7" fill="#17140d"/>'
    '<circle cx="34" cy="38" r="2.7" fill="#17140d"/>'
    '<circle cx="24" cy="28" r="4.4" fill="#54672f"/>'
    "</g></svg>"
)
_LOGO_DARK_SVG = (
    '<svg class="logo-dark" viewBox="0 0 52 62" width="22" height="26" '
    'aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">'
    '<g transform="translate(4,5)">'
    '<polygon points="24,2 44,13 44,37 24,54 4,37 4,13" fill="none" stroke="#f5f3ea" '
    'stroke-width="2" stroke-linejoin="round"/>'
    '<path d="M24 28 L24 14 M24 28 L14 38 M24 28 L34 38" stroke="#f5f3ea" stroke-width="1.9"/>'
    '<path d="M24 14 L14 38 M24 14 L34 38 M14 38 L34 38" stroke="#f5f3ea" stroke-width="1.4" '
    'stroke-opacity="0.4"/>'
    '<circle cx="24" cy="14" r="2.7" fill="#f5f3ea"/>'
    '<circle cx="14" cy="38" r="2.7" fill="#f5f3ea"/>'
    '<circle cx="34" cy="38" r="2.7" fill="#f5f3ea"/>'
    '<circle cx="24" cy="28" r="4.4" fill="#cdd6a6"/>'
    "</g></svg>"
)

_PAGE = (
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>secdns — {domain}</title>
<style>
  /* "Field console" theme — matches SecRouter/SecRecorder. System fonts only (air-gapped). */
  :root {{
    --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    --bg:#e7e3d8; --panel:#f3f0e8; --panel2:#fbfaf4; --fg:#211f18; --muted:#6c6552;
    --accent:#4f6a2e; --accent-ink:#f6f3ea; --accent-soft:rgba(79,106,46,.18);
    --ok:#2f5a22; --warn:#8a5a12; --bad:#8a2b1d;
    --border:#cdc6b2; --rule:#dad4c2; --shadow:2px 2px 0 rgba(33,31,24,.06);
    --pill-bg:#e2ddcd; --pill-ok-bg:#e3ebd7; --pill-ok-bd:#b9c9a8;
    --pill-bad-bg:#f0ddd7; --pill-bad-bd:#d8b3aa; --pill-warn-bg:#efe6cf; --pill-warn-bd:#d8c69a;
    --code-bg:#e2ddcd;
  }}
  :root[data-theme="dark"] {{
    --bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
    --accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
    --ok:#86b257; --warn:#cb9c3e; --bad:#d4634c;
    --border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
    --pill-bg:#2b2920; --pill-ok-bg:#26331c; --pill-ok-bd:#3f5230;
    --pill-bad-bg:#37201a; --pill-bad-bd:#5c2f25; --pill-warn-bg:#332a17; --pill-warn-bd:#544321;
    --code-bg:#2b2920;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
      --accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
      --ok:#86b257; --warn:#cb9c3e; --bad:#d4634c;
      --border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
      --pill-bg:#2b2920; --pill-ok-bg:#26331c; --pill-ok-bd:#3f5230;
      --pill-bad-bg:#37201a; --pill-bad-bd:#5c2f25; --pill-warn-bg:#332a17; --pill-warn-bd:#544321;
      --code-bg:#2b2920;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.55 var(--sans); background:var(--bg); color:var(--fg);
         background-image:linear-gradient(var(--rule) 1px, transparent 1px); background-size:100% 28px;
         background-attachment:fixed; }}
  header {{ display:flex; align-items:center; gap:12px; padding:14px 22px; background:var(--panel);
           border-bottom:1px solid var(--border); border-top:3px solid var(--accent); }}
  header h1 {{ font-size:15px; margin:0; font-weight:700; text-transform:uppercase; letter-spacing:.14em;
              display:flex; align-items:center; gap:10px; }}
  header h1 .sec {{ color:var(--accent); }}
  .logo-dark {{ display:none; }}
  :root[data-theme="dark"] .logo-light {{ display:none; }}
  :root[data-theme="dark"] .logo-dark {{ display:inline-block; }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) .logo-light {{ display:none; }}
    :root:not([data-theme="light"]) .logo-dark {{ display:inline-block; }}
  }}
  header .status {{ margin-left:auto; display:flex; gap:8px; align-items:center; }}
  main {{ max-width:820px; margin:0 auto; padding: 1.5rem 1.25rem 2rem; }}
  .sub {{ color:var(--muted); margin:0 0 1.5rem; font:12px var(--mono); }}
  .sub b {{ color:var(--fg); font-weight:600; }}
  .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(120px,1fr)); gap: .75rem;
          margin-bottom: 1.5rem; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:2px; padding:.6rem .8rem;
          box-shadow:var(--shadow); }}
  .card b {{ font-size:1.4rem; display:block; color:var(--fg); }}
  .card span {{ color:var(--muted); font:10px var(--mono); text-transform:uppercase; letter-spacing:.08em; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border);
          box-shadow:var(--shadow); }}
  th, td {{ text-align:left; padding:.5rem .7rem; border-bottom:1px solid var(--rule); font:12.5px var(--mono); }}
  th {{ color:var(--muted); font-weight:700; text-transform:uppercase; letter-spacing:.08em; font-size:10px;
       border-bottom:1px solid var(--border); }}
  tr:last-child td {{ border-bottom:none; }}
  button.btn {{ background:var(--accent); color:var(--accent-ink); border:1px solid var(--accent); border-radius:2px;
               padding:7px 14px; cursor:pointer; font:11px var(--mono); text-transform:uppercase; letter-spacing:.08em; }}
  button.btn:hover {{ filter:brightness(1.08); }}
  button.btn.ghost {{ background:var(--panel2); color:var(--fg); border-color:var(--border); }}
  .theme-toggle {{ padding:5px 11px; }}
  .row {{ display:flex; align-items:center; gap:1rem; margin-bottom:1rem; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:2px; font:10px var(--mono); text-transform:uppercase;
          letter-spacing:.06em; background:var(--pill-bg); color:var(--muted); border:1px solid var(--border); }}
  .pill.ok {{ color:var(--ok); border-color:var(--pill-ok-bd); background:var(--pill-ok-bg); }}
  .muted {{ color:var(--muted); }}
</style>
<script>
  /* Apply the saved theme before first paint (no flash). Default = follow OS. */
  (function(){{ try {{ var t = localStorage.getItem('secrouter-theme'); if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t); }} catch (e) {{}} }})();
</script>
</head>
<body>
<header>
  <span class="logo">"""
    + _LOGO_LIGHT_SVG
    + _LOGO_DARK_SVG
    + """</span>
  <h1><span class="sec">SEC</span>DNS</h1>
  <span class="status">
    <span class="pill ok">&#9679; ok</span>
    <button class="btn ghost theme-toggle" id="themeBtn" title="Toggle light / dark" onclick="toggleTheme()">&#9680;</button>
  </span>
</header>
<main>
<p class="sub">authoritative zone <b>{domain}</b> &middot; forwarding {forward} &middot; ttl {ttl}s</p>
<div class="grid">
 <div class="card"><b>{records}</b><span>records</span></div>
 <div class="card"><b>{queries}</b><span>queries</span></div>
 <div class="card"><b>{authoritative}</b><span>authoritative</span></div>
 <div class="card"><b>{forwarded}</b><span>forwarded</span></div>
 <div class="card"><b>{nxdomain}</b><span>nxdomain</span></div>
 <div class="card"><b>{refused}</b><span>refused</span></div>
</div>
<div class="row"><button class="btn ghost" onclick="reload()">Reload zone</button><span id="msg" class="sub"></span></div>
<table><thead><tr><th>name</th><th>type</th><th>value</th></tr></thead><tbody>
{rows}
</tbody></table>
</main>
<script>
function effectiveTheme(){{ var a=document.documentElement.getAttribute("data-theme"); if(a==="dark"||a==="light") return a; return (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light"; }}
function toggleTheme(){{ var t = effectiveTheme()==="dark" ? "light" : "dark"; document.documentElement.setAttribute("data-theme", t); try {{ localStorage.setItem("secrouter-theme", t); }} catch(e){{}} }}
async function reload() {{
  const m = document.getElementById('msg'); m.textContent = 'reloading…';
  const r = await fetch('/reload', {{method:'POST'}}); const j = await r.json();
  m.textContent = '✓ ' + j.records + ' records'; setTimeout(() => location.reload(), 500);
}}
</script>
</body>
</html>
"""
)


def _handler_factory(resolver: Resolver):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silence default stderr access log
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self) -> None:
            if self.path in ("/health", "/healthz"):
                self._json(200, {"status": "ok", "domain": resolver.config.domain,
                                 "records": resolver.zone.count,
                                 "queries": resolver.stats["queries"]})
            elif self.path == "/records":
                self._json(200, {"records": [
                    {"name": n, "type": t, "value": v} for n, t, v in resolver.zone.entries()
                ]})
            elif self.path == "/":
                self._send(200, self._render().encode(), "text/html; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path == "/reload":
                client_ip = self.client_address[0]
                try:
                    count = resolver.reload(
                        principal=f"console:{client_ip}", source_ip=client_ip
                    )
                except (ValueError, OSError) as exc:
                    self._json(500, {"error": str(exc)})
                    return
                self._json(200, {"status": "reloaded", "records": count})
            else:
                self._json(404, {"error": "not found"})

        def _render(self) -> str:
            def esc(value) -> str:
                return html.escape(str(value), quote=True)

            rows = "\n".join(
                f"<tr><td>{esc(n)}</td><td>{esc(t)}</td><td>{esc(v)}</td></tr>"
                for n, t, v in resolver.zone.entries()
            ) or '<tr><td colspan="3" class="muted">(empty zone)</td></tr>'
            s = resolver.stats
            return _PAGE.format(
                domain=esc(resolver.config.domain),
                forward=esc("on" if (resolver.config.forward and resolver.config.upstream) else "off"),
                ttl=esc(resolver.config.ttl), records=esc(resolver.zone.count),
                queries=esc(s["queries"]), authoritative=esc(s["authoritative"]),
                forwarded=esc(s["forwarded"]), nxdomain=esc(s["nxdomain"]), refused=esc(s["refused"]),
                rows=rows,
            )

    return Handler


class Console:
    """The admin HTTP server; ``start`` runs it in a daemon thread."""

    def __init__(self, resolver: Resolver, bind: str = "127.0.0.1", port: int = 47053) -> None:
        self.httpd = ThreadingHTTPServer((bind, port), _handler_factory(resolver))
        self.httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
