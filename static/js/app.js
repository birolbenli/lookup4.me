function t(key, vars) {
  const fn = window.__i18nT;
  if (typeof fn === "function") return fn(key, vars);
  return key;
}

async function runLookup(endpoint, payload, render) {
  const out = document.getElementById("results");
  const btn = document.querySelector("#tool-form button[type='submit']");
  if (!out) return;
  const loadingMsg =
    endpoint.includes("/exchange") ? t("Scanning Exchange endpoints…") : t("Looking up…");
  out.innerHTML = `<p class="loading">${escapeHtml(loadingMsg)}</p>`;
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
    out.innerHTML = `<div class="error-box">${escapeHtml(t("Request failed"))}: ${escapeHtml(String(err))}</div>`;
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
  if (navigator.clipboard?.readText && window.isSecureContext) {
    return await navigator.clipboard.readText();
  }
  throw new Error("Clipboard paste needs HTTPS or Ctrl+V");
}

function armPasteCapture(targetEl, onDone) {
  const handler = (e) => {
    const text = e.clipboardData?.getData("text/plain") || e.clipboardData?.getData("text") || "";
    if (!text) return;
    e.preventDefault();
    e.stopPropagation();
    targetEl.value = text;
    targetEl.dispatchEvent(new Event("input", { bubbles: true }));
    cleanup();
    onDone?.(true, text);
  };

  const cleanup = () => {
    document.removeEventListener("paste", handler, true);
    window.clearTimeout(timer);
  };

  document.addEventListener("paste", handler, true);
  const timer = window.setTimeout(() => {
    cleanup();
    onDone?.(false, "");
  }, 20000);

  targetEl.focus();
  return cleanup;
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function renderError(data, root) {
  root.appendChild(
    el(`<div class="error-box">${escapeHtml(data.error || t("Lookup failed"))}</div>`)
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
  const geo = data.geo || {};
  const place = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
  const geoBlock = geo.ok
    ? `<div class="block">
        <h3>Geolocation</h3>
        <p class="geo-place">${escapeHtml(place || "Unknown location")}</p>
        <div class="geo-grid">
          <div><span class="muted">Country</span><strong>${escapeHtml(geo.country || "—")} ${
            geo.country_code ? `(${escapeHtml(geo.country_code)})` : ""
          }</strong></div>
          <div><span class="muted">City / Region</span><strong>${escapeHtml(
            [geo.city, geo.region].filter(Boolean).join(", ") || "—"
          )}</strong></div>
          <div><span class="muted">ISP / Org</span><strong>${escapeHtml(
            geo.isp || geo.org || "—"
          )}</strong></div>
          <div><span class="muted">ASN</span><strong class="mono">${escapeHtml(
            geo.asn != null ? String(geo.asn) : "—"
          )}</strong></div>
          <div><span class="muted">Timezone</span><strong>${escapeHtml(geo.timezone || "—")}</strong></div>
          <div><span class="muted">Coordinates</span><strong class="mono">${escapeHtml(
            geo.latitude != null && geo.longitude != null
              ? `${geo.latitude}, ${geo.longitude}`
              : "—"
          )}</strong></div>
        </div>
      </div>`
    : `<div class="block">
        <h3>Geolocation</h3>
        <p class="muted">${escapeHtml(geo.error || "Geolocation unavailable")}</p>
      </div>`;

  root.appendChild(
    el(`<div class="stack">
      <div class="block">
        <p><span class="status ok">IP</span></p>
        <p class="mono" style="font-size:1.4rem;font-weight:700">${escapeHtml(data.ip)}</p>
        ${place ? `<p class="muted">${escapeHtml(place)}</p>` : ""}
      </div>
      ${geoBlock}
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
    if (role === "origin-mta") return t("Sending server");
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

function severityClass(sev) {
  if (sev === "critical" || sev === "expired" || sev === "error") return "err";
  if (sev === "warning" || sev === "warn") return "warn";
  if (sev === "ok" || sev === "valid") return "ok";
  return "";
}

function sevLabel(sev) {
  const key = {
    critical: "Critical",
    warning: "Warning",
    info: "Info",
    ok: "OK",
    error: "Error",
    valid: "Valid",
    expired: "Expired",
  }[sev] || sev || "";
  return t(key);
}

function renderAuthCompact(title, block) {
  if (!block) return "";
  const found = !!block.found;
  const n = (block.endpoints || []).length;
  return `<div class="auth-compact ${found ? "is-bad" : "is-ok"}">
    <div class="auth-compact-title">${escapeHtml(title)}</div>
    <div class="auth-compact-status">
      <span class="status ${found ? "err" : "ok"}">${escapeHtml(found ? t("Detected") : t("Not detected"))}</span>
      ${found && n ? `<span class="muted tiny">${n} ${escapeHtml(t("endpoint(s)"))}</span>` : ""}
    </div>
    <p class="tiny muted">${escapeHtml(t(block.summary || ""))}</p>
  </div>`;
}

function renderExchangeFinding(f, { compact = false } = {}) {
  const eps = (f.endpoints || [])
    .slice(0, compact ? 4 : 8)
    .map((e) => `<li class="mono">${escapeHtml(e)}</li>`)
    .join("");
  return `<div class="finding sev-${escapeHtml(f.severity || "info")}">
    <div class="finding-head">
      <span class="status ${severityClass(f.severity)}">${escapeHtml(sevLabel(f.severity))}</span>
      <strong>${escapeHtml(t(f.title || ""))}</strong>
    </div>
    ${f.detail ? `<p>${escapeHtml(t(f.detail))}</p>` : ""}
    ${f.guidance ? `<p class="tiny"><strong>${escapeHtml(t("Fix"))}:</strong> ${escapeHtml(t(f.guidance))}</p>` : ""}
    ${eps ? `<ul class="finding-eps">${eps}</ul>` : ""}
  </div>`;
}

function dedupeHeaderItems(items) {
  const map = new Map();
  for (const r of items || []) {
    const key = `${(r.header || "").toLowerCase()}|${r.value || ""}`;
    let row = map.get(key);
    if (!row) {
      row = {
        header: r.header,
        value: r.value,
        risk: r.risk,
        note: r.note,
        hosts: new Set(),
      };
      map.set(key, row);
    }
    if (r.host) row.hosts.add(r.host);
    const rank = { critical: 0, warning: 1, info: 2 };
    if ((rank[r.risk] ?? 9) < (rank[row.risk] ?? 9)) row.risk = r.risk;
  }
  return [...map.values()].sort((a, b) => {
    const rank = { critical: 0, warning: 1, info: 2 };
    return (rank[a.risk] ?? 9) - (rank[b.risk] ?? 9) || String(a.header).localeCompare(String(b.header));
  });
}

function exchangeVdCell(e) {
  if (!e) return `<span class="muted">—</span>`;
  if (!e.reachable && e.exposure === "closed") {
    return `<span class="ex-cell-status muted">${escapeHtml(t("closed"))}</span>`;
  }
  const auth = e.auth || {};
  const bits = [];
  bits.push(
    `<span class="status ${severityClass(e.exposure === "closed" ? "ok" : e.severity)}">${escapeHtml(
      String(e.status_code ?? "—")
    )}</span>`
  );
  if (auth.ntlm) bits.push(`<span class="status err">NTLM</span>`);
  else if (auth.oauth) bits.push(`<span class="status ok">OAuth</span>`);
  else if (auth.basic) bits.push(`<span class="status warn">Basic</span>`);
  if (e.healthcheck && e.healthcheck.healthy) {
    bits.push(`<span class="status warn">HC</span>`);
  }
  const exp = e.exposure && e.exposure !== "closed" ? t(e.exposure) : "";
  return `<div class="ex-cell">
    <div class="ex-cell-badges">${bits.join("")}</div>
    ${exp ? `<div class="tiny muted">${escapeHtml(exp)}</div>` : ""}
  </div>`;
}

function renderExchange(data, root) {
  if (!data.ok) return renderError(data, root);
  const summary = data.summary || {};
  const counts = data.counts || {};
  const ssl = data.ssl || {};
  const findings = data.findings || [];
  const endpoints = data.endpoints || [];
  const hosts = data.hosts || [];
  const audit = data.auth_audit || {};
  const posture = data.posture || {};
  const hybrid = posture.hybrid || {};
  const teams = posture.teams || {};
  const headerItems = dedupeHeaderItems((data.headers_report || {}).items || []);
  const shared = data.shared_frontends || [];

  const issues = findings.filter((f) => f.severity === "critical" || f.severity === "warning");
  const notes = findings.filter((f) => f.severity === "info");
  const oks = findings.filter((f) => f.severity === "ok");

  const hostCols = hosts.length
    ? hosts
    : [...new Set(endpoints.map((e) => e.host).filter(Boolean))].map((h) => ({
        host: h,
        role: "",
        resolves: true,
        ips: [],
      }));

  const vdOrder = [];
  const vdMeta = new Map();
  for (const e of endpoints) {
    const id = e.id || e.name;
    if (!vdMeta.has(id)) {
      vdMeta.set(id, e);
      vdOrder.push(id);
    }
  }

  const byHostVd = new Map();
  for (const e of endpoints) {
    byHostVd.set(`${e.host}|${e.id || e.name}`, e);
  }

  const hostHead = hostCols
    .map((h) => {
      const short =
        h.role === "primary"
          ? t("Primary")
          : h.role === "autodiscover"
            ? "Autodiscover"
            : h.role === "download"
              ? "Download"
              : h.role || "";
      const ip = (h.ips || [])[0] || "";
      return `<th class="ex-host-col">
        <div class="ex-host-role">${escapeHtml(short)}</div>
        <div class="mono ex-host-name" title="${escapeHtml(h.host || "")}">${escapeHtml(h.host || "")}</div>
        <div class="tiny muted">${h.resolves ? escapeHtml(ip || t("DNS OK")) : escapeHtml(t("no DNS"))}</div>
      </th>`;
    })
    .join("");

  const matrixRows = vdOrder
    .map((id) => {
      const meta = vdMeta.get(id) || {};
      let path = meta.url || "";
      try {
        path = new URL(meta.url).pathname;
      } catch (_) {
        /* keep */
      }
      const cells = hostCols
        .map((h) => {
          const e = byHostVd.get(`${h.host}|${id}`);
          return `<td class="ex-host-col">${exchangeVdCell(e)}</td>`;
        })
        .join("");
      return `<tr>
        <th scope="row" class="ex-vd-col">
          <strong>${escapeHtml(meta.name || id)}</strong>
          <div class="mono tiny muted" title="${escapeHtml(path)}">${escapeHtml(path)}</div>
        </th>
        ${cells}
      </tr>`;
    })
    .join("");

  const hostHtml = hostCols
    .map((h) => {
      const ips = (h.ips || []).join(", ") || "—";
      const roleLabel =
        h.role === "primary"
          ? t("Primary")
          : h.role === "autodiscover"
            ? "Autodiscover"
            : h.role === "download"
              ? "Download"
              : h.role || "—";
      return `<tr>
        <td>${escapeHtml(roleLabel)}</td>
        <td class="mono truncate" title="${escapeHtml(h.host || "")}">${escapeHtml(h.host || "")}</td>
        <td class="mono truncate" title="${escapeHtml(ips)}">${escapeHtml(ips)}</td>
        <td><span class="status ${h.resolves ? "ok" : "warn"}">${escapeHtml(
          h.resolves ? t("DNS OK") : t("no DNS")
        )}</span></td>
      </tr>`;
    })
    .join("");

  const sharedHtml = shared.length
    ? `<p class="muted tiny">${escapeHtml(t("Same frontend IP"))}: ${shared
        .map(
          (s) =>
            `<span class="mono">${escapeHtml(s.ip)}</span> → ${(s.hosts || [])
              .map((h) => escapeHtml(h))
              .join(", ")}`
        )
        .join(" · ")}</p>`
    : "";

  const headerRows = headerItems
    .map((r) => {
      const hostList = [...(r.hosts || [])].join(", ");
      return `<tr>
        <td><span class="status ${severityClass(r.risk)}">${escapeHtml(sevLabel(r.risk))}</span></td>
        <td class="mono truncate" title="${escapeHtml(r.header || "")}">${escapeHtml(r.header || "")}</td>
        <td class="mono truncate" title="${escapeHtml(r.value || "")}">${escapeHtml(r.value || "")}</td>
        <td class="tiny muted truncate" title="${escapeHtml(hostList)}">${escapeHtml(hostList || "—")}</td>
      </tr>`;
    })
    .join("");

  const guideList = [...new Set([...(hybrid.guidance || []), ...(teams.guidance || [])])]
    .slice(0, 5)
    .map((g) => `<li>${escapeHtml(t(g))}</li>`)
    .join("");

  root.appendChild(
    el(`<div class="stack exchange-report">
      <div class="summary">
        <span class="pill score-pill">${escapeHtml(t("Score"))} ${escapeHtml(String(summary.score ?? "—"))} · ${escapeHtml(summary.grade || "")} · ${escapeHtml(t(summary.label || ""))}</span>
        <span class="pill">${escapeHtml(String(counts.ntlm || 0))} NTLM</span>
        <span class="pill">${escapeHtml(String(counts.oauth || 0))} OAuth</span>
        <span class="pill">${escapeHtml(String(counts.healthcheck_open || 0))} ${escapeHtml(t("Healthcheck open"))}</span>
        <span class="pill">${escapeHtml(String(counts.header_leaks || 0))} ${escapeHtml(t("Header leaks"))}</span>
      </div>

      <div class="block">
        <h3>${escapeHtml(t("Findings"))}</h3>
        <p class="muted tiny"><span class="mono">${escapeHtml(data.host || "")}</span>${
          data.org_domain ? ` · ${escapeHtml(t("Org domain"))}: <span class="mono">${escapeHtml(data.org_domain)}</span>` : ""
        }</p>
        <div class="findings">
          ${issues.map((f) => renderExchangeFinding(f, { compact: true })).join("") || `<p class="status ok">${escapeHtml(t("No critical issues"))}</p>`}
        </div>
        ${
          notes.length
            ? `<details class="ex-more"><summary>${escapeHtml(t("Notes"))} (${notes.length})</summary><div class="findings">${notes
                .map((f) => renderExchangeFinding(f, { compact: true }))
                .join("")}</div></details>`
            : ""
        }
        ${
          oks.length
            ? `<details class="ex-more"><summary>${escapeHtml(t("Passed checks"))} (${oks.length})</summary><div class="findings">${oks
                .map((f) => renderExchangeFinding(f, { compact: true }))
                .join("")}</div></details>`
            : ""
        }
      </div>

      <div class="block">
        <h3>${escapeHtml(t("Related hosts"))}</h3>
        ${sharedHtml}
        <div class="table-wrap"><table class="ex-table ex-table-hosts">
          <thead><tr>
            <th>${escapeHtml(t("Role"))}</th>
            <th>${escapeHtml(t("Host"))}</th>
            <th>IP</th>
            <th>DNS</th>
          </tr></thead>
          <tbody>${hostHtml}</tbody>
        </table></div>
      </div>

      <div class="block">
        <h3>${escapeHtml(t("Virtual directories"))}</h3>
        <p class="muted tiny">${escapeHtml(t("One row per VD — columns are related hostnames."))}</p>
        <div class="table-wrap"><table class="ex-table ex-matrix">
          <thead><tr>
            <th class="ex-vd-col">${escapeHtml(t("VD"))}</th>
            ${hostHead}
          </tr></thead>
          <tbody>${matrixRows || `<tr><td colspan="${hostCols.length + 1}">${escapeHtml(t("No record"))}</td></tr>`}</tbody>
        </table></div>
        <p class="muted tiny">${escapeHtml(t("Legend: NTLM/OAuth/Basic = auth challenge; HC = public healthcheck."))}</p>
      </div>

      <div class="block">
        <h3>${escapeHtml(t("Sensitive headers"))}</h3>
        <p class="muted tiny">${escapeHtml(t("Server name, version, or internal IP in headers is risky."))}</p>
        <div class="table-wrap"><table class="ex-table ex-table-headers">
          <thead><tr>
            <th>${escapeHtml(t("Risk"))}</th>
            <th>${escapeHtml(t("Header"))}</th>
            <th>${escapeHtml(t("Value"))}</th>
            <th>${escapeHtml(t("Seen on"))}</th>
          </tr></thead>
          <tbody>${headerRows || `<tr><td colspan="4">${escapeHtml(t("No sensitive headers found"))}</td></tr>`}</tbody>
        </table></div>
      </div>

      <div class="block">
        <h3>${escapeHtml(t("Authentication"))}</h3>
        <div class="auth-compact-grid">
          ${renderAuthCompact("NTLM / Negotiate", audit.ntlm)}
          ${renderAuthCompact("OAuth 2.0", audit.oauth2)}
          ${renderAuthCompact("Basic", audit.basic)}
        </div>
      </div>

      <div class="block">
        <h3>${escapeHtml(t("TLS certificate"))}</h3>
        <div class="geo-grid ex-tls">
          <div><span class="muted">${escapeHtml(t("Status"))}</span><strong class="status ${severityClass(ssl.status)}">${escapeHtml(sevLabel(ssl.status) || ssl.status || "—")}</strong></div>
          <div><span class="muted">${escapeHtml(t("Days left"))}</span><strong>${escapeHtml(String(ssl.days_left ?? "—"))}</strong></div>
          <div><span class="muted">${escapeHtml(t("Expires"))}</span><strong class="mono">${escapeHtml(String(ssl.expiry_date || "—"))}</strong></div>
          <div><span class="muted">${escapeHtml(t("Issuer"))}</span><strong class="truncate" title="${escapeHtml(String(ssl.issuer || "—"))}">${escapeHtml(String(ssl.issuer || "—"))}</strong></div>
        </div>
      </div>

      <div class="block">
        <h3>${escapeHtml(t("Hybrid & Teams"))}</h3>
        <p>${escapeHtml(t(hybrid.summary || teams.summary || ""))}</p>
        ${guideList ? `<ul class="guide-list">${guideList}</ul>` : ""}
        <p class="muted tiny">${escapeHtml(t(teams.ews_status || ""))}${
          teams.ntlm_on_ews ? ` · ${escapeHtml(t("NTLM on EWS"))}` : ""
        }${teams.oauth_on_ews ? ` · ${escapeHtml(t("OAuth on EWS"))}` : ""}</p>
      </div>
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
  exchange: renderExchange,
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
    statusEl.textContent = t("Creating test address…");
    waiting.classList.remove("hidden");
    const res = await fetch("/api/mailtest/create", { method: "POST" });
    const data = await res.json();
    if (!data.ok) {
      results.innerHTML = `<div class="error-box">${escapeHtml(data.error || t("Could not create test"))}</div>`;
      return;
    }
    testId = data.id;
    address = data.address;
    history.replaceState({}, "", `/tools/mailtest/${testId}`);
  } else {
    const res = await fetch(`/api/mailtest/${testId}`);
    const data = await res.json();
    if (!data.ok) {
      results.innerHTML = `<div class="error-box">${escapeHtml(data.error || t("Test not found"))}</div>`;
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
  statusEl.textContent = t("Waiting for your message…");
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
        statusEl.textContent = t("Message received — analyzing…");
        waiting.classList.add("hidden");
        results.innerHTML = "";
        renderEmailReport(data.analysis, results);
      } else if (data.status === "expired") {
        clearInterval(mailtestTimer);
        mailtestTimer = null;
        statusEl.textContent = t("This test expired. Create a new address.");
      }
    } catch (_) {
      /* ignore transient poll errors */
    }
  }, 2500);
}

let visitorMapInstance = null;

function closeVisitorModal() {
  const modal = document.getElementById("visitor-modal");
  if (!modal) return;
  modal.hidden = true;
  document.body.classList.remove("modal-open");
}

async function openVisitorModal() {
  const modal = document.getElementById("visitor-modal");
  const status = document.getElementById("visitor-map-status");
  const list = document.getElementById("visitor-list");
  const stats = document.getElementById("visitor-stats");
  const mapEl = document.getElementById("visitor-map");
  if (!modal || !mapEl) return;

  modal.hidden = false;
  document.body.classList.add("modal-open");
  if (status) status.textContent = t("Loading map…");

  try {
    const res = await fetch("/api/visitors/geo");
    const data = await res.json();
    if (!data.ok) throw new Error("bad response");

    const countries = data.countries || [];
    const values = {};
    countries.forEach((c) => {
      if (c.code) values[c.code] = c.count;
    });

    if (stats) {
      stats.innerHTML = `
        <span class="pill">${escapeHtml(String(data.queries || 0))} ${escapeHtml(t("queries"))}</span>
        <span class="pill">${escapeHtml(String(data.total || 0))} ${escapeHtml(t("visitors"))}</span>
        <span class="pill">${escapeHtml(String(countries.length))} ${escapeHtml(t("countries"))}</span>
      `;
    }

    if (list) {
      if (!countries.length) {
        list.innerHTML = "";
      } else {
        list.innerHTML = countries
          .slice(0, 12)
          .map(
            (c) =>
              `<li><span>${escapeHtml(c.name || c.code)}</span><span class="count">${escapeHtml(
                String(c.count)
              )}</span></li>`
          )
          .join("");
      }
    }

    if (visitorMapInstance && typeof visitorMapInstance.destroy === "function") {
      visitorMapInstance.destroy();
      visitorMapInstance = null;
    }
    mapEl.innerHTML = "";

    if (typeof jsVectorMap !== "function") {
      if (status) {
        status.textContent = countries.length ? t("Top countries") : t("No visitor data yet.");
      }
      return;
    }

    try {
      visitorMapInstance = new jsVectorMap({
        selector: "#visitor-map",
        map: "world",
        backgroundColor: "transparent",
        zoomOnScroll: false,
        regionStyle: {
          initial: {
            fill: "#d7e3dc",
            stroke: "#ffffff",
            strokeWidth: 0.4,
          },
          hover: {
            fill: "#0f6a4f",
          },
        },
        series: {
          regions: [
            {
              values,
              scale: ["#b9d5c6", "#0f6a4f"],
              normalizeFunction: "polynomial",
            },
          ],
        },
        onRegionTooltipShow(event, tooltip, code) {
          const hit = countries.find((c) => c.code === code);
          const label = hit ? `${hit.name}: ${hit.count}` : `${code}: 0`;
          if (tooltip && typeof tooltip.text === "function") tooltip.text(label);
        },
      });
    } catch (mapErr) {
      console.warn("visitor map render failed", mapErr);
      mapEl.innerHTML = `<p class="muted" style="padding:1rem">${escapeHtml(
        countries.length ? t("Top countries") : t("No visitor data yet.")
      )}</p>`;
    }

    if (status) {
      status.textContent = countries.length ? t("Top countries") : t("No visitor data yet.");
    }
  } catch (_) {
    if (status) status.textContent = t("Could not load visitor map.");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const openMapBtn = document.getElementById("open-visitor-map");
  const visitorModal = document.getElementById("visitor-modal");
  openMapBtn?.addEventListener("click", () => openVisitorModal());
  visitorModal?.querySelectorAll("[data-close-modal]").forEach((el) => {
    el.addEventListener("click", () => closeVisitorModal());
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeVisitorModal();
  });

  const navToggle = document.getElementById("nav-toggle");
  const siteNav = document.getElementById("site-nav");
  if (navToggle && siteNav) {
    navToggle.addEventListener("click", () => {
      const open = !siteNav.classList.contains("open");
      siteNav.classList.toggle("open", open);
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      document.body.classList.toggle("nav-open", open);
    });
    siteNav.querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", () => {
        siteNav.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
        document.body.classList.remove("nav-open");
      });
    });
  }

  const feedbackForm = document.getElementById("feedback-form");
  if (feedbackForm) {
    feedbackForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const status = document.getElementById("feedback-status");
      const btn = document.getElementById("feedback-submit");
      const payload = {
        kind: feedbackForm.kind.value,
        title: feedbackForm.title.value.trim(),
        message: feedbackForm.message.value.trim(),
        contact_email: feedbackForm.contact_email.value.trim(),
        page_url: feedbackForm.page_url.value.trim(),
        website: feedbackForm.website.value,
      };
      if (status) {
        status.className = "hint";
        status.textContent = t("Sending…");
      }
      if (btn) btn.disabled = true;
      try {
        const res = await fetch("/api/feedback", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.ok) {
          if (status) {
            status.className = "hint ok";
            status.textContent = data.message || t("Thanks — your report was sent.");
          }
          feedbackForm.reset();
        } else if (status) {
          status.className = "hint err";
          status.textContent = data.error || t("Could not send report.");
        }
      } catch (err) {
        if (status) {
          status.className = "hint err";
          status.textContent = t("Network error — please try again.");
        }
      } finally {
        if (btn) btn.disabled = false;
      }
    });
  }

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
    const pasteBtn = document.getElementById("headers-paste");
    if (!q) return;

    if (!window.isSecureContext) {
      if (headersHint) {
        headersHint.textContent = t("One-click paste needs HTTPS. Open {url}", {
          url: "https://tools.birolbenli.com/tools/headers",
        });
      }
      return;
    }

    if (pasteBtn) pasteBtn.disabled = true;
    try {
      const text = await navigator.clipboard.readText();
      if (!text) {
        if (headersHint) headersHint.textContent = t("Clipboard is empty.");
        return;
      }
      q.value = text;
      q.focus();
      if (headersHint) headersHint.textContent = t("Pasted from clipboard.");
    } catch (err) {
      if (headersHint) {
        headersHint.textContent = t(
          "Clipboard permission denied. Allow clipboard access for this site, then try Paste again."
        );
      }
    } finally {
      if (pasteBtn) pasteBtn.disabled = false;
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
        if (statusEl) statusEl.textContent = t("No address to copy yet.");
        return;
      }
      try {
        await copyText(text);
        if (statusEl) statusEl.textContent = t("Address copied. Send your test email now…");
        if (btn) {
          const prev = btn.textContent;
          btn.textContent = t("Copied");
          setTimeout(() => {
            btn.textContent = prev || t("Copy");
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
          statusEl.textContent = t("Copy blocked — address selected, press Ctrl+C / Cmd+C.");
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
