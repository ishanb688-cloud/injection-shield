function scanPage() {
  const PATTERNS = [
    ["override", 3, /ignore\s+(all\s+)?(your\s+)?(previous|prior|earlier|above)\s+(instructions|rules|prompts?)/i],
    ["override", 3, /disregard\s+(all\s+)?(your\s+)?(previous|prior|earlier|above)\s+(instructions|rules)/i],
    ["addresses_ai", 2, /(note|message|instruction|reminder)s?\s+(to|for)\s+(the\s+)?(ai|assistant|model|llm|agent)/i],
    ["addresses_ai", 2, /\bassistant\s*:/i],
    ["addresses_ai", 2, /(requirement|rule|step)s?\s+for\s+the\s+(ai|assistant|model|agent)/i],
    ["addresses_ai", 2, /system\s+(notice|message|override|prompt)/i],
    ["secret_request", 2, /account[_\s]?token|(private\s+)?user\s+profile|private\s+profile/i],
    ["secret_request", 1, /password|secret|credentials|api[_\s]?key/i],
    ["output_control", 2, /(end|finish|conclude)\s+(your\s+)?(summary|answer|response|reply)\s+with/i],
    ["output_control", 2, /(add|append|include|print)\s+(one\s+)?(final|last|extra)\s+line/i],
    ["data_leak_link", 3, /!\[[^\]]*\]\(https?:\/\/[^)\s]*\?[^)\s]*\)/i]
  ];
  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "HEAD", "TITLE", "META", "LINK", "TEXTAREA"]);

  function score(text) {
    let total = 0;
    const cats = new Set();
    for (const [cat, pts, re] of PATTERNS) {
      if (re.test(text)) { total += pts; cats.add(cat); }
    }
    return { total, cats: Array.from(cats) };
  }
  function parse(c) {
    const m = /rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:[,\s/]+([\d.]+))?/.exec(c || "");
    return m ? { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] } : null;
  }
  function bgOf(el) {
    for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c.a > 0.5) return c;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  }
  function close(a, b) {
    return Math.hypot(a.r - b.r, a.g - b.g, a.b - b.b) < 24;
  }
  function reasonsFor(el) {
    const reasons = [];
    const st = getComputedStyle(el);
    if (el.getClientRects().length === 0) reasons.push("not displayed (display:none or a hidden parent)");
    if (st.visibility === "hidden") reasons.push("visibility:hidden");
    let opacity = 1;
    for (let e = el, i = 0; e && i < 8; e = e.parentElement, i++) {
      opacity *= parseFloat(getComputedStyle(e).opacity);
    }
    if (opacity <= 0.05) reasons.push("opacity near zero");
    const size = parseFloat(st.fontSize);
    if (size <= 3) reasons.push("tiny font (" + size + "px)");
    const fg = parse(st.color);
    if (fg && fg.a > 0.05 && close(fg, bgOf(el))) reasons.push("text color matches background");
    const rc = el.getBoundingClientRect();
    if (rc.width > 0 && rc.height > 0 && (rc.right + window.scrollX <= 0 || rc.bottom + window.scrollY <= 0)) {
      reasons.push("pushed off-screen");
    }
    return reasons;
  }

  document.querySelectorAll("[data-injection-shield]").forEach(function (e) {
    e.removeAttribute("data-injection-shield");
  });
  if (!document.getElementById("injection-shield-style")) {
    const s = document.createElement("style");
    s.id = "injection-shield-style";
    s.textContent = "[data-injection-shield=visible]{outline:2px solid #ff5a4a !important;outline-offset:2px}";
    document.documentElement.appendChild(s);
  }
  window.__injectionShieldComments = [];

  const findings = [];
  const seen = new Set();
  let nodes = 0;
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode()) && nodes < 20000) {
    nodes++;
    const text = n.nodeValue.trim();
    if (text.length < 12) continue;
    const el = n.parentElement;
    if (!el || SKIP.has(el.tagName) || seen.has(el)) continue;
    const found = score(text);
    if (found.total < 3) continue;
    seen.add(el);
    const reasons = reasonsFor(el);
    el.setAttribute("data-injection-shield", reasons.length ? "hidden" : "visible");
    findings.push({ kind: "text", hidden: reasons.length > 0, reasons: reasons, text: text.slice(0, 200), score: found.total, cats: found.cats });
  }
  const cwalker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  while ((n = cwalker.nextNode())) {
    const text = n.nodeValue.trim();
    if (text.length < 12) continue;
    const found = score(text);
    if (found.total < 3) continue;
    window.__injectionShieldComments.push(n);
    findings.push({ kind: "comment", hidden: true, reasons: ["inside an HTML comment"], text: text.slice(0, 200), score: found.total, cats: found.cats });
  }
  return { host: location.hostname, scanned: nodes, findings: findings };
}

function removeFlagged() {
  let removed = 0;
  document.querySelectorAll("[data-injection-shield=hidden]").forEach(function (e) {
    e.remove();
    removed++;
  });
  (window.__injectionShieldComments || []).forEach(function (c) {
    if (c.parentNode) { c.remove(); removed++; }
  });
  window.__injectionShieldComments = [];
  return removed;
}

const $ = function (id) { return document.getElementById(id); };
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
async function runInPage(func) {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const res = await chrome.scripting.executeScript({ target: { tabId: tabs[0].id }, func: func });
  return res[0].result;
}

function render(result) {
  const out = $("out");
  out.textContent = "";
  const list = result.findings;
  if (list.length === 0) {
    out.appendChild(el("span", "badge good", "Nothing suspicious found"));
    out.appendChild(el("div", "note", "Checked " + result.scanned + " text blocks on " + result.host + ". This is not a guarantee: the rules are simple patterns and can be reworded around."));
    $("remove").hidden = true;
    return;
  }
  const hiddenCount = list.filter(function (f) { return f.hidden; }).length;
  out.appendChild(el("span", "badge bad", hiddenCount > 0 ? "Hidden instructions found" : "Instructions aimed at an AI found"));
  out.appendChild(el("div", "note", list.length + " item(s) flagged on " + result.host + "."));
  list.forEach(function (f) {
    const item = el("div", "item");
    item.appendChild(el("b", "", (f.hidden ? "HIDDEN" : "VISIBLE") + " \u00b7 " + (f.reasons.length ? f.reasons.join("; ") : "in plain sight")));
    item.appendChild(el("q", "", f.text));
    out.appendChild(item);
  });
  $("remove").hidden = hiddenCount === 0;
}

$("scan").addEventListener("click", async function () {
  $("out").textContent = "Scanning...";
  $("remove").hidden = true;
  try {
    render(await runInPage(scanPage));
  } catch (e) {
    $("out").textContent = "Chrome does not let extensions scan this kind of page (for example chrome:// pages or the Web Store). Open an ordinary website and try again.";
  }
});

$("remove").addEventListener("click", async function () {
  try {
    const removed = await runInPage(removeFlagged);
    $("out").textContent = "";
    $("out").appendChild(el("span", "badge good", "Removed " + removed + " item(s) from this page"));
    $("out").appendChild(el("div", "note", "Reload the page to restore it. Visible items stay outlined in red so you can see them."));
    $("remove").hidden = true;
  } catch (e) {
    $("out").textContent = "Could not change this page.";
  }
});