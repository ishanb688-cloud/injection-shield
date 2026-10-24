import json
from pathlib import Path

from bs4 import BeautifulSoup
from flask import Flask, abort, jsonify, request

from shield.pipeline import inspect
from shield.output_check import check_output

BASE = Path(__file__).parent
PAGES_DIR = BASE / "attack_pages"
SECRETS = ["FAKE-TOKEN-7731-DEMO"]
MAX_HTML = 20000

app = Flask(__name__)

DEMO = json.loads((BASE / "demo_data.json").read_text(encoding="utf-8"))
RESULTS = json.loads((BASE / "test_results.json").read_text(encoding="utf-8"))
BY_PAGE = {d["page"]: d for d in DEMO}


def raw_text(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator="\n", strip=True)[:6000]


def leaked(answer):
    return any(s.lower() in answer.lower() for s in SECRETS)


@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
    )
    return resp


@app.get("/api/pages")
def pages():
    return jsonify([{"page": d["page"], "kind": d["kind"]} for d in DEMO])


@app.get("/api/page/<name>")
def page(name):
    item = BY_PAGE.get(name)
    if item is None:
        abort(404)
    html = (PAGES_DIR / name).read_text(encoding="utf-8")
    result = inspect(html)
    off = item["off"]
    off_view = {
        "answer": off["answer"],
        "runs": off["runs"],
        "leaks": off["leaks"],
        "leaked": leaked(off["answer"]),
    }
    on_view = None
    if item["on"] is not None and result["action"] != "BLOCK":
        out = check_output(item["on"]["answer"], SECRETS)
        on_view = {
            "answer": out["cleaned"],
            "output_findings": out["findings"],
            "runs": item["on"]["runs"],
            "leaks_before_output_layer": item["on"]["leaks"],
        }
    return jsonify(
        {
            "page": name,
            "kind": item["kind"],
            "raw_text": raw_text(html),
            "input": result,
            "off": off_view,
            "on": on_view,
        }
    )


@app.post("/api/inspect")
def inspect_html():
    data = request.get_json(silent=True) or {}
    html = str(data.get("html", ""))[:MAX_HTML]
    if not html.strip():
        return jsonify({"error": "Paste some page source first."}), 400
    return jsonify(inspect(html))


@app.get("/api/summary")
def summary():
    attacks = [r for r in RESULTS if r["kind"] == "attack"]
    cleans = [r for r in RESULTS if r["kind"] == "clean"]
    valid_on = [r for r in attacks if r.get("on_leaked") is not None]
    return jsonify(
        {
            "attack_pages": len(attacks),
            "clean_pages": len(cleans),
            "flagged_at_input": sum(r["input_action"] in ("BLOCK", "CLEANED") for r in attacks),
            "clean_flagged": sum(r["input_action"] != "ALLOW" for r in cleans),
            "off_runs": sum(r.get("off_runs", 0) for r in attacks),
            "off_leaks": sum(r.get("off_leaks", 0) for r in attacks),
            "on_pages": len(valid_on),
            "on_leaks": sum(1 for r in valid_on if r["on_leaked"]),
        }
    )


@app.get("/")
def index():
    return INDEX_HTML


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Injection Shield</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6672;--line:#dfe3e8;--bad:#b42318;--badbg:#fdecea;--good:#05603a;--goodbg:#e6f6ee;--warn:#8a5a00;--warnbg:#fff4d6}
@media (prefers-color-scheme:dark){:root{--bg:#0f1317;--card:#171c22;--text:#e8ecf0;--muted:#97a3b0;--line:#2a323b;--bad:#ff8a80;--badbg:#3a1a18;--good:#7ee2b0;--goodbg:#12301f;--warn:#ffd27a;--warnbg:#3a2d0c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0 0 4px;font-size:26px}
h2{font-size:16px;margin:0 0 10px}
.sub{color:var(--muted);margin:0 0 20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.stat b{display:block;font-size:22px}
.stat span{color:var(--muted);font-size:13px}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
select,button,textarea{font:inherit;color:var(--text);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px}
button{cursor:pointer;font-weight:600}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:760px){.cols{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;font-weight:700;margin:0 6px 8px 0}
.bad{background:var(--badbg);color:var(--bad)}
.good{background:var(--goodbg);color:var(--good)}
.neutral{background:var(--warnbg);color:var(--warn)}
.note{color:var(--muted);font-size:13px;margin:4px 0 8px}
.answer,pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0 0;font:13px/1.5 ui-monospace,Consolas,monospace}
.item{margin:6px 0;font-size:14px}
.item q{display:block;color:var(--muted);font-size:13px;quotes:none;margin-top:2px}
mark{background:var(--badbg);color:var(--bad);font-weight:700;padding:0 2px}
textarea{width:100%;min-height:130px;font:13px/1.5 ui-monospace,Consolas,monospace}
.foot{color:var(--muted);font-size:13px;margin-top:24px}
</style>
</head>
<body>
<div class="wrap">
<h1>Injection Shield</h1>
<p class="sub">A security layer that stops hidden instructions on web pages from hijacking AI assistants.</p>

<div class="stats" id="stats"></div>

<div class="bar">
<label for="pick"><b>Page:</b></label>
<select id="pick"></select>
<span class="note" id="kind"></span>
</div>

<div class="cols">
<div class="card"><h2>Shield OFF (unprotected assistant)</h2><div id="off"></div></div>
<div class="card"><h2>Shield ON</h2><div id="on"></div></div>
</div>

<div class="cols">
<div class="card"><h2>What the AI reads (raw page text)</h2><pre id="raw"></pre></div>
<div class="card"><h2>What the AI receives after the shield</h2><pre id="clean"></pre></div>
</div>

<div class="card">
<h2>Try your own page source</h2>
<p class="note">Runs the input layers only (hidden content and instruction language). No AI call is made. Maximum 20,000 characters. Nothing is fetched from the internet.</p>
<textarea id="mine" placeholder="Paste page source here"></textarea>
<div class="bar"><button id="go">Run shield layers</button></div>
<div id="mineout"></div>
</div>

<p class="foot">Demo notes: the shield layers run live on every request. The assistant answers are recorded from real runs of the demo assistant (a deliberately naive design that puts instructions, user data and page text in one prompt), and the leak counts show how often each page leaked. The token in this demo is fake.</p>
</div>

<script>
const SECRET = 'FAKE-TOKEN-7731-DEMO';
const $ = id => document.getElementById(id);
function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined) e.textContent=text; return e;}
function clear(n){while(n.firstChild) n.removeChild(n.firstChild);}
async function getJSON(url){const r=await fetch(url); if(!r.ok) throw new Error('Request failed'); return r.json();}

function highlight(box, text){
  const parts = text.split(SECRET);
  parts.forEach((p, i) => {
    box.appendChild(document.createTextNode(p));
    if(i < parts.length - 1) box.appendChild(el('mark', '', SECRET));
  });
}

function actionBadge(action){
  if(action === 'BLOCK') return el('span','badge good','BLOCKED before reaching the AI');
  if(action === 'CLEANED') return el('span','badge good','CLEANED: hidden content removed');
  return el('span','badge neutral','ALLOWED by input layers');
}

function renderInput(box, input){
  box.appendChild(actionBadge(input.action));
  input.hidden.forEach(f => {
    const d = el('div','item');
    d.appendChild(el('span','', '[' + f.severity.toUpperCase() + '] ' + f.reasons.join('; ')));
    d.appendChild(el('q','', f.text.slice(0, 160)));
    box.appendChild(d);
  });
  if(input.action === 'BLOCK'){
    input.after.findings.forEach(f => {
      const d = el('div','item');
      d.appendChild(el('span','', 'Instruction aimed at an AI (' + f.category + ')'));
      d.appendChild(el('q','', f.match.slice(0, 120)));
      box.appendChild(d);
    });
  }
}

function renderPage(data){
  $('kind').textContent = data.kind === 'attack' ? 'Attack page' : 'Clean page (should pass untouched)';

  const off = $('off'); clear(off);
  if(data.off.leaked) off.appendChild(el('span','badge bad','TOKEN LEAKED'));
  else off.appendChild(el('span','badge neutral','No leak in the recorded answer'));
  off.appendChild(el('div','note','Leaked in ' + data.off.leaks + ' of ' + data.off.runs + ' recorded runs'));
  const a1 = el('div','answer'); highlight(a1, data.off.answer); off.appendChild(a1);

  const on = $('on'); clear(on);
  renderInput(on, data.input);
  if(data.on){
    if(data.on.output_findings.length){
      on.appendChild(el('span','badge good','OUTPUT LAYER stopped a leak'));
      data.on.output_findings.forEach(f => {
        on.appendChild(el('div','item', '[' + f.severity.toUpperCase() + '] ' + f.type + ': ' + f.detail.slice(0, 100)));
      });
    } else {
      on.appendChild(el('span','badge good','Output checked: clean'));
    }
    on.appendChild(el('div','note','Raw answers leaked in ' + data.on.leaks_before_output_layer + ' of ' + data.on.runs + ' recorded runs before the output layer'));
    const a2 = el('div','answer'); highlight(a2, data.on.answer); on.appendChild(a2);
  } else {
    on.appendChild(el('div','note','The assistant never saw this page, so there is no answer.'));
  }

  $('raw').textContent = data.raw_text;
  $('clean').textContent = data.input.cleaned_text || '(nothing left)';
}

async function loadPage(name){
  try{ renderPage(await getJSON('/api/page/' + encodeURIComponent(name))); }
  catch(e){ $('on').textContent = 'Could not load this page.'; }
}

function stat(box, big, small){
  const d = el('div','stat'); d.appendChild(el('b','',big)); d.appendChild(el('span','',small)); box.appendChild(d);
}

async function init(){
  const s = await getJSON('/api/summary');
  const box = $('stats');
  stat(box, s.off_leaks + ' / ' + s.off_runs, 'attack runs where the token leaked (shield OFF)');
  stat(box, s.on_leaks + ' / ' + s.on_pages, 'attack pages where it leaked (shield ON)');
  stat(box, s.flagged_at_input + ' / ' + s.attack_pages, 'attacks flagged by the input layers');
  stat(box, s.clean_flagged + ' / ' + s.clean_pages, 'clean pages wrongly flagged');

  const pages = await getJSON('/api/pages');
  const pick = $('pick');
  pages.forEach(p => { const o = el('option','',p.page); o.value = p.page; pick.appendChild(o); });
  pick.addEventListener('change', () => loadPage(pick.value));
  if(pages.length) loadPage(pages[0].page);
}

$('go').addEventListener('click', async () => {
  const out = $('mineout'); clear(out);
  try{
    const r = await fetch('/api/inspect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({html: $('mine').value})});
    const data = await r.json();
    if(!r.ok){ out.appendChild(el('div','note', data.error || 'Request failed')); return; }
    renderInput(out, data);
    out.appendChild(el('div','note','Text the AI would receive after the shield:'));
    out.appendChild(el('pre','', data.cleaned_text || '(nothing left)'));
  } catch(e){ out.appendChild(el('div','note','Request failed')); }
});

init();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(port=5000)