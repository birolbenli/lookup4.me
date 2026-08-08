async function runLookup(endpoint, payload, render) {
  const out = document.getElementById("results");
  const btn = document.querySelector("#tool-form button[type='submit']");
  if (!out) return;
  out.innerHTML = `<p class="loading">Looking up…</p>`;
  if (btn) btn.disabled = true;

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    out.innerHTML = "";
    render(data, out);
  } catch (err) {
    out.innerHTML = `<div class="error-box">Request failed: ${escapeHtml(String(err))}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function copyText(text) {
  const value = String(text ?? "");
  if (!value) throw new Error("Nothing to copy");

  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }

  // Fallback for HTTP / older browsers
  const ta = document.createElement("textarea");
  ta.value = value;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "0";
  ta.style.width = "1px";
  ta.style.height = "1px";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, value.length);
  const ok = document.execCommand("copy");
  document.body.removeChild(ta);
  if (!ok) throw new Error("Copy failed");
}

async function pasteText() {
  if (navigator.clipboard && window.isSecureContext) {
    return await navigator.clipboard.readText();
  }
  throw new Error("Clipboard paste needs HTTPS or Ctrl+V");
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function renderError(data, root) {
  root.appendChild(
    el(`<div class="error-box">${escapeHtml(data.error || "Lookup failed")}</div>`)
  );
}

function renderChain(chain) {
  if (!chain || !chain.length) return "";
  const items = chain
    .map((step) => {
      const value = Array.isArray(step.value) ? step.value.join(", ") : step.value;
      return `<li><strong>${escapeHtml(step.type)}</strong> ${escapeHtml(step.host)} → ${escapeHtml(
        String(value)
      )}</li>`;
    })
    .join("");
  return `<ul class="chain">${items}</ul>`;
}

function renderMx(data, root) {
  if (!data.ok) return renderError(data, root);
  const rows = (data.records || [])
    .map(
      (r) => `<tr>
        <td>${escapeHtml(r.preference)}</td>
        <td class="mono">${escapeHtml(r.exchange)}</td>
        <td class="mono">${escapeHtml((r.ips || []).join(", ") || "—")}</td>
        <td>${renderChain(r.chain)}</td>
      </tr>`
    )
    .join("");
  root.appendChild(
    el(`<div>
      <p><span class="status ok">${data.count} MX record(s)</span> for <strong class="mono">${escapeHtml(
        data.domain
      )}</strong></p>
      <div class="table-wrap"><table>
        <thead><tr><th>Pref</th><th>Exchange</th><th>IP(s)</th><th>Resolution</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4">No records</td></tr>`}</tbody>
      </table></div>
    </div>`)
  );
}

function renderSpf(data, root) {
  if (!data.ok) return renderError(data, root);
  const chain = (data.chain || [])
    .map((c) => {
      const rec = (c.records || []).map((r) => `<pre>${escapeHtml(r.raw)}</pre>`).join("");
      return `<div class="block">
        <h3 class="mono">${escapeHtml(c.domain)}</h3>
        <p class="muted">via ${escapeHtml(c.via)}</p>
        ${rec || `<p class="muted">${escapeHtml(c.error || "No record")}</p>`}
      </div>`;
    })
    .join("");
  root.appendChild(
    el(`<div class="stack">
      <p><span class="status ok">SPF found</span> · DNS lookups used: ${data.dns_lookups_used}</p>
      ${chain}
    </div>`)
  );
}

function renderDkim(data, root) {
  if (!data.ok) return renderError(data, root);
  const blocks = (data.results || [])
    .map((r) => {
      const records = (r.records || [])
        .map(
          (rec) => `<pre>${escapeHtml(rec.raw)}</pre>
            <p class="muted">key type: ${escapeHtml(rec.key_type || "rsa")} · key length chars: ${
              rec.public_key_length
            }${rec.revoked ? " · <strong>revoked/empty p=</strong>" : ""}</p>`
        )
        .join("");
      const hosts = (r.host_resolutions || [])
        .map(
          (h) =>
            `<div><p class="mono">Host: ${escapeHtml(h.hostname)} → ${(h.ips || [])
              .map(escapeHtml)
              .join(", ") || "unresolved"}</p>${renderChain(h.chain)}</div>`
        )
        .join("");
      return `<div class="block">
        <h3>selector: <span class="mono">${escapeHtml(r.selector)}</span></h3>
        <p class="muted mono">${escapeHtml(r.name)}</p>
        ${
          r.cname && r.cname.length
            ? `<p class="muted">CNAME → ${r.cname.map(escapeHtml).join(", ")}</p>`
            : ""
        }
        ${records || `<p class="muted">CNAME/host only (no local TXT body)</p>`}
        ${hosts}
      </div>`;
    })
    .join("");
  root.appendChild(
    el(`<div class="stack">
      <p><span class="status ok">${data.selectors_found} selector(s) found</span>
        · checked ${data.selectors_checked} common selectors</p>
      ${blocks}
    </div>`)
  );
}

function renderDmarc(data, root) {
  if (!data.ok) return renderError(data, root);
  const d = data.dmarc;
  root.appendChild(
    el(`<div class="stack">
      <p><span class="status ok">DMARC found</span> at <span class="mono">${escapeHtml(
        data.query
      )}</span></p>
      <div class="block">
        <p><strong>Policy (p):</strong> ${escapeHtml(d.policy || "—")}</p>
        <p><strong>Subdomain (sp):</strong> ${escapeHtml(d.subdomain_policy || "—")}</p>
        <p><strong>pct:</strong> ${escapeHtml(d.percentage || "—")}</p>
        <p><strong>rua:</strong> <span class="mono">${escapeHtml(d.rua || "—")}</span></p>
        <p><strong>ruf:</strong> <span class="mono">${escapeHtml(d.ruf || "—")}</span></p>
        <p><strong>adkim / aspf:</strong> ${escapeHtml(d.adkim)} / ${escapeHtml(d.aspf)}</p>
        <pre>${escapeHtml(d.raw)}</pre>
      </div>
    </div>`)
  );
}

function renderDnsRecords(data, root, label) {
  if (!data.ok) return renderError(data, root);
  const rows = (data.records || [])
    .map(
      (r) => `<tr>
        <td class="mono">${escapeHtml(r.data)}</td>
        <td>${escapeHtml(r.ttl ?? "—")}</td>
      </tr>`
    )
    .join("");
  root.appendChild(
    el(`<div>
      <p><span class="status ok">${label || data.type}</span> for <strong class="mono">${escapeHtml(
        data.domain
      )}</strong></p>
      <div class="table-wrap"><table>
        <thead><tr><th>Data</th><th>TTL</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`)
  );
}

function renderWhois(data, root) {
  if (!data.ok) return renderError(data, root);
  root.appendChild(
    el(`<div class="block">
      <p><span class="status ok">WHOIS</span> via <span class="mono">${escapeHtml(
        data.server
      )}</span></p>
      <pre>${escapeHtml(data.raw)}</pre>
    </div>`)
  );
}

function renderSsl(data, root) {
  if (!data.ok) return renderError(data, root);
  const s = data.summary || {};
  const rows = (data.results || [])
    .map(
      (r) => `<tr>
        <td class="mono">${escapeHtml(r.domain)}</td>
        <td>${escapeHtml(r.port)}</td>
        <td class="mono">${escapeHtml(r.ip || "—")}</td>
        <td>${escapeHtml(r.issuer || "—")}</td>
        <td>${escapeHtml(r.expiry_date || "—")}</td>
        <td>${r.days_left ?? "—"}</td>
        <td><span class="status ${escapeHtml(r.status)}">${escapeHtml(r.status)}</span>${
          r.message ? `<div class="muted">${escapeHtml(r.message)}</div>` : ""
        }</td>
      </tr>`
    )
    .join("");
  root.appendChild(
    el(`<div>
      <div class="summary">
        <span class="pill">Valid: ${s.valid || 0}</span>
        <span class="pill">Expiring soon: ${s.warning || 0}</span>
        <span class="pill">Expired: ${s.expired || 0}</span>
        <span class="pill">Error: ${s.error || 0}</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr>
          <th>Domain</th><th>Port</th><th>IP</th><th>Issuer</th><th>Expiry</th><th>Days</th><th>Status</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`)
  );
}

function renderHttp(data, root) {
  if (!data.ok) return renderError(data, root);
  const rows = Object.entries(data.headers || {})
    .map(
      ([k, v]) =>
        `<tr><td class="mono">${escapeHtml(k)}</td><td class="mono">${escapeHtml(v)}</td></tr>`
    )
    .join("");
  root.appendChild(
    el(`<div class="stack">
      <p><span class="status ok">${escapeHtml(data.status_code)}</span>
        <span class="mono">${escapeHtml(data.final_url || data.url)}</span>
        ${data.note ? `<span class="muted">· ${escapeHtml(data.note)}</span>` : ""}
      </p>
      <div class="table-wrap"><table>
        <thead><tr><th>Header</th><th>Value</th></tr></thead>
        <tbody>${rows || "<tr><td colspan='2'>No headers</td></tr>"}</tbody>
      </table></div>
    </div>`)
  );
}

function renderPort(data, root) {
  if (!data.ok && !(data.attempts || []).length) return renderError(data, root);
  const attempts = (data.attempts || [])
    .map(
      (a) => `<tr>
        <td class="mono">${escapeHtml(a.ip)}</td>
        <td><span class="status ${a.ok ? "ok" : "err"}">${a.ok ? "open" : "closed"}</span></td>
        <td>${a.latency_ms ?? "—"} ms</td>
        <td class="muted">${escapeHtml(a.error || "")}</td>
      </tr>`
    )
    .join("");
  root.appendChild(
    el(`<div>
      <p><span class="status ${data.open ? "ok" : "err"}">${
        data.open ? "Open" : "Closed / unreachable"
      }</span>
        <strong class="mono">${escapeHtml(data.host)}:${escapeHtml(data.port)}</strong></p>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>Status</th><th>Latency</th><th>Detail</th></tr></thead>
        <tbody>${attempts}</tbody>
      </table></div>
    </div>`)
  );
}

function renderRdns(data, root) {
  if (!data.ok) return renderError(data, root);
  const hosts = (data.hosts || []).map((h) => `<li class="mono">${escapeHtml(h)}</li>`).join("");
  root.appendChild(
    el(`<div class="block">
      <p><span class="status ok">PTR found</span> for <strong class="mono">${escapeHtml(
        data.ip
      )}</strong></p>
      <ul>${hosts || "<li>No hosts</li>"}</ul>
    </div>`)
  );
}

function renderBlacklist(data, root) {
  if (!data.ok) return renderError(data, root);
  const rows = (data.results || [])
    .map(
      (r) => `<tr>
        <td>${escapeHtml(r.name)}</td>
        <td class="mono">${escapeHtml(r.zone)}</td>
        <td><span class="status ${r.listed ? "err" : "ok"}">${
          r.listed ? "LISTED" : "clean"
        }</span></td>
        <td class="mono">${escapeHtml((r.codes || []).join(", "))}</td>
      </tr>`
    )
    .join("");
  root.appendChild(
    el(`<div>
      <p><span class="status ${data.clean ? "ok" : "err"}">${
        data.clean ? "Not listed" : `${data.listed_count} listing(s)`
      }</span>
        IP <strong class="mono">${escapeHtml(data.ip)}</strong>
        ${data.host ? `<span class="muted">from ${escapeHtml(data.host)}</span>` : ""}
      </p>
      <div class="table-wrap"><table>
        <thead><tr><th>List</th><th>Zone</th><th>Status</th><th>Codes</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`)
  );
}

function renderSmtp(data, root) {
  if (!data.ok && !(data.attempts || []).length) return renderError(data, root);
  const attempts = (data.attempts || [])
    .map((a) => {
      const status = a.ok ? "ok" : "err";
      return `<div class="block">
        <p><span class="status ${status}">${a.ok ? "Connected" : "Failed"}</span>
          <span class="mono">${escapeHtml(a.host)} (${escapeHtml(a.ip)}:${a.port})</span>
          ${a.source ? `<span class="muted"> via ${escapeHtml(a.source)}</span>` : ""}
        </p>
        ${a.error ? `<p class="muted">${escapeHtml(a.error)}</p>` : ""}
        ${a.banner ? `<p><strong>Banner</strong></p><pre>${escapeHtml(a.banner)}</pre>` : ""}
        ${a.ehlo ? `<p><strong>EHLO</strong></p><pre>${escapeHtml(a.ehlo)}</pre>` : ""}
        <p class="muted">STARTTLS: ${
          a.starttls_supported
            ? a.starttls_ok
              ? "supported & negotiated"
              : "supported"
            : "not advertised"
        }</p>
      </div>`;
    })
    .join("");
  root.appendChild(el(`<div class="stack">${attempts}</div>`));
}

function renderIp(data, root) {
  if (!data.ok) return renderError(data, root);
  const ptr = (data.ptr || []).map((h) => `<li class="mono">${escapeHtml(h)}</li>`).join("");
  root.appendChild(
    el(`<div class="stack">
      <div class="block">
        <p><span class="status ok">IP</span></p>
        <p class="mono" style="font-size:1.4rem;font-weight:700">${escapeHtml(data.ip)}</p>
      </div>
      <div class="block">
        <h3>Reverse DNS</h3>
        ${ptr ? `<ul>${ptr}</ul>` : `<p class="muted">No PTR</p>`}
      </div>
      ${
        data.user_agent
          ? `<div class="block">
        <h3>Client</h3>
        <p><strong>User-Agent:</strong> <span class="mono">${escapeHtml(data.user_agent)}</span></p>
        <p><strong>Language:</strong> ${escapeHtml(data.language || "—")}</p>
        <p><strong>Host:</strong> ${escapeHtml(data.host_header || "—")}</p>
      </div>`
          : ""
      }
      <div class="block">
        <h3>curl</h3>
        <pre>curl ${escapeHtml(location.origin)}/ip
curl ${escapeHtml(location.origin)}/ip.json
curl ${escapeHtml(location.origin)}/ua</pre>
      </div>
    </div>`)
  );
}

function renderDeliveryFlow(flow) {
  if (!flow || !(flow.nodes || []).length) {
    return `<div class="flow-empty muted">No Received headers found — delivery path unavailable.</div>`;
  }

  const roleLabel = (role) => {
    if (role === "origin") return "From";
    if (role === "destination") return "To";
    if (role === "origin-mta") return "Sending server";
    if (role === "inbox-mta") return "Receiving server";
    return "Relay";
  };

  const nodes = flow.nodes
    .map((node) => {
      const role = escapeHtml(node.role || "relay");
      const kind = escapeHtml(node.kind || "server");
      return `<div class="flow-item role-${role}">
        <div class="flow-rail" aria-hidden="true">
          <span class="flow-dot"></span>
          <span class="flow-connector"></span>
        </div>
        <div class="flow-node kind-${kind} role-${role}">
          <div class="flow-role">${escapeHtml(roleLabel(node.role))}</div>
          <div class="flow-title" title="${escapeHtml(node.title || "")}">${escapeHtml(
            node.title || "—"
          )}</div>
          <div class="flow-sub" title="${escapeHtml(node.subtitle || "")}">${escapeHtml(
            node.subtitle || ""
          )}</div>
          ${
            node.detail
              ? `<div class="flow-time">${escapeHtml(node.detail)}</div>`
              : ""
          }
        </div>
      </div>`;
    })
    .join("");

  return `<section class="delivery-flow">
    <div class="flow-head">
      <div>
        <h2>Delivery path</h2>
        <p class="muted">Top to bottom: sender → servers → recipient</p>
      </div>
      <span class="pill">${escapeHtml(String(flow.hop_count || 0))} hop(s)</span>
    </div>
    <div class="flow-track">${nodes}</div>
  </section>`;
}

function renderEmailReport(data, root) {
  if (!data.ok) return renderError(data, root);
  const score = data.score ?? "—";
  const findings = (data.findings || [])
    .map((f) => {
      return `<article class="finding finding-${escapeHtml(f.status)}">
        <div class="finding-top">
          <span class="status ${escapeHtml(f.status)}">${escapeHtml(f.status)}</span>
          <h3>${escapeHtml(f.title)}</h3>
        </div>
        <p class="finding-summary">${escapeHtml(f.summary)}</p>
        ${f.detail ? `<pre class="finding-detail">${escapeHtml(f.detail)}</pre>` : ""}
        ${f.edu ? `<p class="finding-edu"><strong>Why it matters:</strong> ${escapeHtml(f.edu)}</p>` : ""}
        ${
          f.recommendation
            ? `<p class="finding-fix"><strong>How to improve:</strong> ${escapeHtml(
                f.recommendation
              )}</p>`
            : ""
        }
      </article>`;
    })
    .join("");

  const recs = (data.recommendations || [])
    .map((r, i) => `<li><span class="rec-num">${i + 1}</span>${escapeHtml(r)}</li>`)
    .join("");

  const chain = (data.received_chain || [])
    .map((h) => `<li><span class="muted">#${h.hop}</span> ${escapeHtml(h.value)}</li>`)
    .join("");

  const meta = data.meta || {};
  const counts = data.counts || {};

  root.appendChild(
    el(`<div class="email-report">
      ${renderDeliveryFlow(data.delivery_flow)}

      <div class="score-hero score-${escapeHtml(String(data.score_label || "").toLowerCase())}">
        <div class="score-number">${escapeHtml(score)}<span>/10</span></div>
        <div>
          <div class="score-label">${escapeHtml(data.score_label || "")}</div>
          <p class="muted">${escapeHtml(meta.subject || "No subject")} · ${escapeHtml(
            meta.from || ""
          )}</p>
          <div class="summary">
            <span class="pill">Pass ${counts.pass || 0}</span>
            <span class="pill">Warn ${counts.warn || 0}</span>
            <span class="pill">Fail ${counts.fail || 0}</span>
            <span class="pill">Info ${counts.info || 0}</span>
          </div>
        </div>
      </div>

      ${
        recs
          ? `<div class="block rec-block">
        <h3>Priority improvements</h3>
        <ol class="rec-list">${recs}</ol>
      </div>`
          : `<div class="block"><p class="status ok">No urgent improvements detected from this source.</p></div>`
      }

      <div class="findings-grid">${findings}</div>

      ${
        chain
          ? `<details class="block chain-details"><summary>Raw Received headers (${
              data.received_chain.length
            })</summary><ul class="received-list">${chain}</ul></details>`
          : ""
      }
    </div>`)
  );
}

const RENDERERS = {
  mx: renderMx,
  spf: renderSpf,
  dkim: renderDkim,
  dmarc: renderDmarc,
  headers: renderEmailReport,
  dns: (d, r) => renderDnsRecords(d, r, d.type || "DNS"),
  ns: (d, r) => renderDnsRecords(d, r, "NS"),
  caa: (d, r) => renderDnsRecords(d, r, "CAA"),
  whois: renderWhois,
  ssl: renderSsl,
  http: renderHttp,
  port: renderPort,
  rdns: renderRdns,
  blacklist: renderBlacklist,
  smtp: renderSmtp,
  ip: renderIp,
};

function syncUrl(slug, query, type) {
  let path = `/tools/${slug}`;
  if (query) path += `/${encodeURI(query).replace(/%2F/gi, "/")}`;
  if (slug === "dns" && type && type !== "A") {
    path += `?type=${encodeURIComponent(type)}`;
  }
  history.replaceState({}, "", path);
}

function currentQueryValue(panel) {
  const field = panel.dataset.field;
  const input = panel.querySelector(`[name="${field}"]`);
  return (input?.value || "").trim();
}

function submitTool(panel) {
  const slug = panel.dataset.tool;
  const field = panel.dataset.field;
  const optional = panel.dataset.optional === "1";
  const value = currentQueryValue(panel);
  if (!value && !optional) return;

  const payload = { [field]: value };
  const typeEl = document.getElementById("dns-type");
  if (typeEl) payload.type = typeEl.value;

  syncUrl(slug, value, payload.type);
  const render = RENDERERS[slug] || renderError;
  runLookup(`/api/${slug}`, payload, render);
}

let mailtestTimer = null;

async function startMailTest(panel, existingId) {
  const waiting = document.getElementById("mailtest-waiting");
  const addressEl = document.getElementById("mailtest-address");
  const statusEl = document.getElementById("mailtest-status");
  const results = document.getElementById("results");
  if (!waiting || !addressEl || !statusEl || !results) return;

  let testId = existingId;
  let address = "";

  if (!testId) {
    statusEl.textContent = "Creating test address…";
    waiting.classList.remove("hidden");
    const res = await fetch("/api/mailtest/create", { method: "POST" });
    const data = await res.json();
    if (!data.ok) {
      results.innerHTML = `<div class="error-box">${escapeHtml(data.error || "Could not create test")}</div>`;
      return;
    }
    testId = data.id;
    address = data.address;
    history.replaceState({}, "", `/tools/mailtest/${testId}`);
  } else {
    const res = await fetch(`/api/mailtest/${testId}`);
    const data = await res.json();
    if (!data.ok) {
      results.innerHTML = `<div class="error-box">${escapeHtml(data.error || "Test not found")}</div>`;
      return;
    }
    address = data.address;
    if (data.status === "received" && data.analysis) {
      waiting.classList.add("hidden");
      results.innerHTML = "";
      renderEmailReport(data.analysis, results);
      return;
    }
  }

  addressEl.textContent = address;
  waiting.classList.remove("hidden");
  statusEl.textContent = "Waiting for your message…";
  results.innerHTML = "";

  if (mailtestTimer) clearInterval(mailtestTimer);
  mailtestTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/mailtest/${testId}`);
      const data = await res.json();
      if (!data.ok) return;
      if (data.status === "received" && data.analysis) {
        clearInterval(mailtestTimer);
        mailtestTimer = null;
        statusEl.textContent = "Message received — analysis ready.";
        waiting.classList.add("hidden");
        results.innerHTML = "";
        renderEmailReport(data.analysis, results);
      } else if (data.status === "expired") {
        clearInterval(mailtestTimer);
        mailtestTimer = null;
        statusEl.textContent = "This test expired. Create a new address.";
      }
    } catch (_) {
      /* ignore transient poll errors */
    }
  }, 2500);
}

document.addEventListener("DOMContentLoaded", () => {
  const panel = document.querySelector(".panel[data-tool]");
  if (!panel) return;

  const form = document.getElementById("tool-form");
  const switcher = document.getElementById("tool-switch");
  const slug = panel.dataset.tool;

  form?.addEventListener("submit", (e) => {
    e.preventDefault();
    submitTool(panel);
  });

  const headersHint = document.getElementById("headers-hint");

  document.getElementById("headers-clear")?.addEventListener("click", () => {
    const q = document.getElementById("query");
    if (q) q.value = "";
    const out = document.getElementById("results");
    if (out) out.innerHTML = "";
    if (headersHint) headersHint.textContent = "";
  });

  document.getElementById("headers-paste")?.addEventListener("click", async () => {
    const q = document.getElementById("query");
    if (!q) return;
    try {
      const text = await pasteText();
      if (!text) {
        if (headersHint) headersHint.textContent = "Clipboard is empty.";
        return;
      }
      q.value = text;
      q.focus();
      if (headersHint) headersHint.textContent = "Pasted from clipboard.";
    } catch (_) {
      q.focus();
      if (headersHint) {
        headersHint.textContent =
          "Could not read clipboard here (HTTP). Click the box and press Ctrl+V / Cmd+V.";
      }
    }
  });

  switcher?.addEventListener("change", () => {
    const next = switcher.value;
    const value = currentQueryValue(panel);
    // Don't put huge header dumps into the URL
    const useValue = value && slug !== "headers" && value.length < 180 ? value : "";
    window.location.href = useValue ? `/tools/${next}/${encodeURI(useValue)}` : `/tools/${next}`;
  });

  if (slug === "mailtest") {
    document.getElementById("mailtest-create")?.addEventListener("click", () => {
      startMailTest(panel, "");
    });
    document.getElementById("mailtest-copy")?.addEventListener("click", async () => {
      const text = (document.getElementById("mailtest-address")?.textContent || "").trim();
      const statusEl = document.getElementById("mailtest-status");
      const btn = document.getElementById("mailtest-copy");
      if (!text) {
        if (statusEl) statusEl.textContent = "No address to copy yet.";
        return;
      }
      try {
        await copyText(text);
        if (statusEl) statusEl.textContent = "Address copied. Send your test email now…";
        if (btn) {
          const prev = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(() => {
            btn.textContent = prev || "Copy";
          }, 1500);
        }
      } catch (_) {
        // Last-resort: select the address so user can copy manually
        const addr = document.getElementById("mailtest-address");
        if (addr) {
          const range = document.createRange();
          range.selectNodeContents(addr);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        }
        if (statusEl) {
          statusEl.textContent = "Copy blocked — address selected, press Ctrl+C / Cmd+C.";
        }
      }
    });
    const existing = (panel.dataset.testId || "").trim();
    if (existing) startMailTest(panel, existing);
    return;
  }

  const auto = (panel.dataset.autoQuery || "").trim();
  if (auto || panel.dataset.optional === "1") {
    if (auto || slug === "ip") {
      submitTool(panel);
    }
  }
});
