#!/usr/bin/env python3
"""Bundle worker.js + terminal.html → standaloneworker.js (paste-to-Cloudflare)."""
import json, pathlib
here=pathlib.Path(__file__).parent
worker=(here/"worker.js").read_text()
html=(here/"terminal.html").read_text()
embed="// ── EMBEDDED TERMINAL (generated — edit terminal.html, not this) ──\n"
embed+="const TERMINAL_HTML = "+json.dumps(html)+";\n\n"
worker=worker.replace(
  "return harden(await env.ASSETS.fetch(request));",
  "return harden(new Response(TERMINAL_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }));")
out=here/"standaloneworker.js"
out.write_text(embed+worker)
print("built standaloneworker.js:", out.stat().st_size//1024, "KB")
