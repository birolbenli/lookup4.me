async function runLookup(endpoint, payload, render) {
  const out = document.getElementById("results");
  const btn = document.querySelector("form button[type='submit']");
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
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
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

function bindDomainForm(formId, endpoint, field, render) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const value = form.querySelector(`[name="${field}"]`).value.trim();
    runLookup(endpoint, { [field]: value }, render);
  });
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
      const rec = (c.records || [])
        .map((r) => `<pre>${escapeHtml(r.raw)}</pre>`)
        .join("");
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
          a.starttls_supported ? (a.starttls_ok ? "supported & negotiated" : "supported") : "not advertised"
        }</p>
      </div>`;
    })
    .join("");
  root.appendChild(el(`<div class="stack">${attempts}</div>`));
}

document.addEventListener("DOMContentLoaded", () => {
  bindDomainForm("mx-form", "/api/mx", "domain", renderMx);
  bindDomainForm("spf-form", "/api/spf", "domain", renderSpf);
  bindDomainForm("dkim-form", "/api/dkim", "domain", renderDkim);
  bindDomainForm("dmarc-form", "/api/dmarc", "domain", renderDmarc);
  bindDomainForm("rdns-form", "/api/rdns", "ip", renderRdns);
  bindDomainForm("smtp-form", "/api/smtp", "host", renderSmtp);

  const sslForm = document.getElementById("ssl-form");
  if (sslForm) {
    sslForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const domains = sslForm.querySelector('[name="domains"]').value;
      runLookup("/api/ssl", { domains }, renderSsl);
    });
  }
});
