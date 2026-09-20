// The control panel page. One self-contained document served by the same
// Worker as /mcp, so there is one deploy artifact and the page can never be
// a version behind the server it describes.

export const controlPanelHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>security-headers-mcp control panel</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #fbfbfa; --panel: #fff; --ink: #1a1a19; --muted: #5c5c57;
    --line: #e3e2de; --accent: #3d5afe; --ok: #1a6b3c; --no: #96201d; --warn: #8a5a00;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #17171a; --panel: #1f1f23; --ink: #ececea; --muted: #a6a6a0;
      --line: #33333a; --accent: #94a6ff; --ok: #64d19a; --no: #ff9b96; --warn: #e5b45c;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--ink);
    font: 16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .wrap { max-width: 56rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
  .skip {
    position: absolute; left: -9999px; top: 0; background: var(--panel);
    padding: .75rem 1rem; border: 2px solid var(--accent); border-radius: 6px;
  }
  .skip:focus { left: 1rem; top: 1rem; z-index: 10; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
  h2 { font-size: 1.05rem; margin: 0 0 .75rem; }
  h3 { font-size: .95rem; margin: 0 0 .5rem; }
  .lede { color: var(--muted); margin: 0 0 2rem; }
  section {
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    padding: 1.25rem; margin-bottom: 1.25rem;
  }
  dl.grid { display: grid; grid-template-columns: auto 1fr; gap: .4rem 1rem; margin: 0; }
  dt { color: var(--muted); }
  dd { margin: 0; }
  ul.tags { list-style: none; display: flex; flex-wrap: wrap; gap: .4rem; padding: 0; margin: 0; }
  ul.tags li { border: 1px solid var(--line); border-radius: 999px; padding: .15rem .65rem; font-size: .9rem; }
  ul.plain { margin: .25rem 0 0; padding-left: 1.1rem; }
  label { display: block; font-weight: 600; margin-bottom: .2rem; }
  .hint { color: var(--muted); font-size: .9rem; margin: 0 0 .5rem; }
  input[type=text] {
    width: 100%; padding: .6rem .7rem; font: inherit; color: inherit;
    background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
  }
  input[aria-invalid=true] { border-color: var(--no); border-width: 2px; }
  button {
    margin-top: .75rem; padding: .6rem 1.1rem; font: inherit; font-weight: 600;
    color: var(--bg); background: var(--ink); border: 0; border-radius: 8px; cursor: pointer;
  }
  button[disabled] { opacity: .6; cursor: progress; }
  :focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
  .msg { display: flex; gap: .5rem; align-items: baseline; font-weight: 600; }
  .ok { color: var(--ok); } .no { color: var(--no); } .warn { color: var(--warn); }
  .err { color: var(--no); font-size: .9rem; margin: .4rem 0 0; }
  .result { margin-top: 1.25rem; border-top: 1px solid var(--line); padding-top: 1rem; }
  .result[hidden] { display: none; }
  .result h3:focus-visible { outline-offset: 4px; }
  .sr {
    position: absolute; width: 1px; height: 1px; overflow: hidden;
    clip: rect(0 0 0 0); clip-path: inset(50%); white-space: nowrap;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; }
  footer { color: var(--muted); font-size: .85rem; }
</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<div class="wrap">
<header>
  <h1>security-headers-mcp</h1>
  <p class="lede">Setup, policy, and validation for the MCP endpoint at <code>/mcp</code>.</p>
</header>

<main id="main" tabindex="-1">
  <section aria-labelledby="status-h">
    <h2 id="status-h">Status</h2>
    <dl class="grid" id="status">
      <dt>Endpoint</dt><dd id="s-endpoint">Checking…</dd>
      <dt>Tools offered</dt><dd id="s-tools">Checking…</dd>
      <dt>Identity</dt><dd id="s-access">Checking…</dd>
      <dt>Last checked</dt><dd id="s-time">—</dd>
    </dl>
  </section>

  <section aria-labelledby="config-h">
    <h2 id="config-h">Configuration</h2>
    <h3 id="hosts-h">Hosts this server may fetch</h3>
    <p class="hint" id="hosts-note">Anything not on this list is refused before any request leaves the Worker.</p>
    <ul class="tags" id="hosts" aria-labelledby="hosts-h" aria-describedby="hosts-note"><li>Loading…</li></ul>
    <h3 id="headers-h" style="margin-top:1.25rem">Headers checked</h3>
    <ul class="tags" id="headers" aria-labelledby="headers-h"><li>Loading…</li></ul>
  </section>

  <section aria-labelledby="validate-h">
    <h2 id="validate-h">Validate a target</h2>
    <form id="form" novalidate>
      <label for="url">Target URL</label>
      <p class="hint" id="url-hint">Must be https, on an allowlisted host, default port, and carry no credentials.</p>
      <input id="url" name="url" type="text" inputmode="url" autocomplete="off"
             spellcheck="false" aria-describedby="url-hint" placeholder="https://example.com/">
      <p class="err" id="url-error" hidden></p>
      <button type="submit" id="submit">Check headers</button>
    </form>
    <p class="sr" id="progress" role="status" aria-live="polite"></p>

    <div class="result" id="result" hidden>
      <h3 id="result-h" tabindex="-1"></h3>
      <div id="result-body"></div>
    </div>
  </section>

  <footer>
    <p>The page calls the same policy code the MCP tool runs. What you see here is what an agent gets.</p>
  </footer>
</main>
</div>

<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var config = null;

  function text(el, value) { el.textContent = value; }

  function listInto(el, items, empty) {
    el.textContent = "";
    if (!items.length) {
      var li = document.createElement("li");
      li.textContent = empty;
      li.className = "warn";
      el.appendChild(li);
      return;
    }
    items.forEach(function (item) {
      var li = document.createElement("li");
      li.textContent = item;
      el.appendChild(li);
    });
  }

  function loadConfig() {
    return fetch("/api/config", { headers: { accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (c) {
        config = c;
        listInto($("hosts"), c.allowedHosts, "None configured. Every request is denied.");
        listInto($("headers"), c.checkedHeaders, "None");
        text($("s-tools"), c.tools.map(function (t) {
          return t.name + (t.readOnly ? " (read-only)" : "");
        }).join(", "));
        text($("s-access"), c.access.enforced
          ? "Cloudflare Access required"
          : "Open. No identity required.");
      });
  }

  function pingEndpoint() {
    var started = Date.now();
    return fetch("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
    }).then(function (r) {
      var ms = Date.now() - started;
      var el = $("s-endpoint");
      el.className = r.ok ? "ok" : "no";
      text(el, r.ok ? "Responding in " + ms + " ms" : "Returned HTTP " + r.status);
      text($("s-time"), new Date().toLocaleTimeString());
    }).catch(function () {
      var el = $("s-endpoint");
      el.className = "no";
      text(el, "Unreachable from this page");
    });
  }

  function fieldError(message) {
    var input = $("url"), err = $("url-error");
    text(err, message);
    err.hidden = false;
    input.setAttribute("aria-invalid", "true");
    input.setAttribute("aria-describedby", "url-hint url-error");
    input.focus();
  }

  function clearFieldError() {
    var input = $("url"), err = $("url-error");
    err.hidden = true;
    text(err, "");
    input.removeAttribute("aria-invalid");
    input.setAttribute("aria-describedby", "url-hint");
  }

  function row(dl, term, value, className) {
    var dt = document.createElement("dt");
    dt.textContent = term;
    var dd = document.createElement("dd");
    dd.textContent = value;
    if (className) { dd.className = className; }
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  function showResult(heading, build) {
    var box = $("result"), h = $("result-h"), body = $("result-body");
    text(h, heading);
    body.textContent = "";
    build(body);
    box.hidden = false;
    // Focus moves to the result so a screen reader lands on the answer.
    // The live region below only announces progress, so nothing is said twice.
    h.focus();
  }

  function renderReport(report) {
    return function (body) {
      var dl = document.createElement("dl");
      dl.className = "grid";
      row(dl, "URL", report.url);
      row(dl, "HTTP status", String(report.status));
      if (report.redirectTo) {
        row(dl, "Redirects to", report.redirectTo + " (not followed)", "warn");
      }
      row(dl, "Present", report.present.length + " of " + (report.present.length + report.missing.length));
      body.appendChild(dl);

      [["Present", report.present, "ok"], ["Missing", report.missing, "no"]].forEach(function (pair) {
        if (!pair[1].length) { return; }
        var h4 = document.createElement("h4");
        h4.textContent = pair[0];
        h4.className = pair[2];
        h4.style.margin = "1rem 0 .25rem";
        var ul = document.createElement("ul");
        ul.className = "plain";
        pair[1].forEach(function (name) {
          var li = document.createElement("li");
          li.textContent = name;
          ul.appendChild(li);
        });
        body.appendChild(h4);
        body.appendChild(ul);
      });
    };
  }

  function renderMessage(message, className) {
    return function (body) {
      var p = document.createElement("p");
      p.className = "msg " + className;
      p.textContent = message;
      body.appendChild(p);
    };
  }

  $("form").addEventListener("submit", function (event) {
    event.preventDefault();
    clearFieldError();

    var value = $("url").value.trim();
    if (!value) {
      fieldError("Enter a URL to check.");
      return;
    }

    var button = $("submit");
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    text($("progress"), "Checking " + value);

    fetch("/api/validate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: value })
    })
      .then(function (r) { return r.json(); })
      .then(function (result) {
        if (result.outcome === "invalid") {
          // Shape problems belong on the field, next to what the person typed.
          fieldError(result.reason);
          $("result").hidden = true;
          return;
        }
        if (result.outcome === "allowed") {
          showResult("Allowed", renderReport(result.report));
        } else if (result.outcome === "denied") {
          // Policy refusals are an answer, not a typo, so they get the result panel.
          showResult("Denied", renderMessage(result.reason, "no"));
        } else {
          showResult("Could not complete", renderMessage(result.reason, "warn"));
        }
      })
      .catch(function () {
        showResult("Could not complete", renderMessage("The control panel could not reach the server.", "warn"));
      })
      .then(function () {
        button.disabled = false;
        button.removeAttribute("aria-busy");
        text($("progress"), "");
      });
  });

  $("url").addEventListener("input", clearFieldError);

  loadConfig().catch(function () {
    listInto($("hosts"), [], "Configuration could not be loaded.");
  });
  pingEndpoint();
})();
</script>
</body>
</html>
`;
