(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  function esc(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  async function api(path, opts = {}) {
    const res = await fetch(`/admin/api${path}`, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    let data = {};
    try {
      data = await res.json();
    } catch (_) {
      data = {};
    }
    if (res.status === 401) {
      showAuth();
      throw new Error(data.error || "Unauthorized");
    }
    if (!res.ok || data.ok === false) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }

  function showAuth() {
    $("#auth-screen").classList.remove("hidden");
    $("#app-screen").classList.add("hidden");
  }

  function showApp() {
    $("#auth-screen").classList.add("hidden");
    $("#app-screen").classList.remove("hidden");
  }

  function setAuthError(msg) {
    const el = $("#auth-error");
    if (!msg) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    el.hidden = false;
    el.textContent = msg;
  }

  async function initAuth() {
    const setupComplete = document.body.dataset.setupComplete === "1";
    if (!setupComplete) {
      $("#setup-panel").classList.remove("hidden");
      $("#login-panel").classList.add("hidden");
      $("#auth-lead").textContent = "First-time setup: link an authenticator app.";
      try {
        // Wait for optional setup token + button; begin on Activate also retries.
        $("#qr-box").innerHTML =
          "<p class='muted tiny'>Enter setup token (if configured), then authenticator code and press Activate.</p>";
      } catch (err) {
        setAuthError(String(err.message || err));
      }
    } else {
      $("#setup-panel").classList.add("hidden");
      $("#login-panel").classList.remove("hidden");
      // Probe session
      try {
        await api("/overview");
        showApp();
        loadAll();
        return;
      } catch (_) {
        showAuth();
      }
    }
  }

  $("#btn-confirm-setup")?.addEventListener("click", async () => {
    setAuthError("");
    try {
      const token = $("#setup-token").value;
      const begin = await api("/setup/begin", {
        method: "POST",
        body: JSON.stringify({ setup_token: token }),
      });
      $("#setup-secret").textContent = begin.secret || "";
      $("#qr-box").innerHTML =
        begin.qr_svg || `<p class="mono tiny">${esc(begin.otpauth_url || "")}</p>`;
      if (!$("#setup-code").value) {
        setAuthError("Scan the QR, then enter the 6-digit code and press Activate again.");
        return;
      }
      await api("/setup/confirm", {
        method: "POST",
        body: JSON.stringify({
          code: $("#setup-code").value,
          setup_token: token,
        }),
      });
      document.body.dataset.setupComplete = "1";
      $("#setup-panel").classList.add("hidden");
      $("#login-panel").classList.remove("hidden");
      $("#auth-lead").textContent = "Authenticator linked. Sign in with a new code.";
      showApp();
      loadAll();
    } catch (err) {
      setAuthError(String(err.message || err));
    }
  });

  $("#btn-login")?.addEventListener("click", async () => {
    setAuthError("");
    try {
      await api("/login", {
        method: "POST",
        body: JSON.stringify({ code: $("#login-code").value }),
      });
      showApp();
      loadAll();
    } catch (err) {
      setAuthError(String(err.message || err));
    }
  });

  $("#login-code")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-login")?.click();
  });
  $("#setup-code")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-confirm-setup")?.click();
  });

  $("#btn-logout")?.addEventListener("click", async () => {
    try {
      await api("/logout", { method: "POST", body: "{}" });
    } catch (_) {
      /* ignore */
    }
    showAuth();
    $("#login-panel").classList.remove("hidden");
    $("#setup-panel").classList.add("hidden");
  });

  // Tabs
  $$(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      $$(".tab").forEach((t) => t.classList.remove("active"));
      $(`#tab-${btn.dataset.tab}`)?.classList.add("active");
      $("#admin-nav")?.classList.remove("open");
    });
  });
  $("#nav-toggle")?.addEventListener("click", () => {
    $("#admin-nav")?.classList.toggle("open");
  });

  async function setList(ip, listType) {
    await api("/lists", {
      method: "POST",
      body: JSON.stringify({ ip, list_type: listType, note: "" }),
    });
    await Promise.all([loadLists(), loadTopIps(), loadVisitors()]);
  }

  async function removeList(ip, listType) {
    await api("/lists", {
      method: "DELETE",
      body: JSON.stringify({ ip, list_type: listType }),
    });
    await loadLists();
  }

  function listBadge(listed) {
    if (listed === "whitelist") return '<span class="pill wl">allow</span>';
    if (listed === "blacklist") return '<span class="pill bl">block</span>';
    return "";
  }

  function ipActions(ip, listed) {
    return `<div class="row-actions">
      ${listed !== "whitelist" ? `<button type="button" class="btn btn-sm btn-ok" data-wl="${esc(ip)}">Allow</button>` : ""}
      ${listed !== "blacklist" ? `<button type="button" class="btn btn-sm btn-danger" data-bl="${esc(ip)}">Block</button>` : ""}
      ${listed ? `<button type="button" class="btn btn-sm btn-ghost" data-rm="${esc(ip)}" data-rm-type="${esc(listed)}">Remove</button>` : ""}
    </div>`;
  }

  function bindIpActions(root) {
    root.querySelectorAll("[data-wl]").forEach((b) =>
      b.addEventListener("click", () => setList(b.dataset.wl, "whitelist"))
    );
    root.querySelectorAll("[data-bl]").forEach((b) =>
      b.addEventListener("click", () => setList(b.dataset.bl, "blacklist"))
    );
    root.querySelectorAll("[data-rm]").forEach((b) =>
      b.addEventListener("click", () => removeList(b.dataset.rm, b.dataset.rmType))
    );
  }

  async function loadOverview() {
    const data = await api("/overview");
    const s = data.stats || {};
    $("#overview-stats").innerHTML = [
      ["Queries today", s.queries_today],
      ["Visits today", s.visits_today],
      ["Unique IPs today", s.unique_ips_today],
      ["Queries total", s.queries_total],
      ["Visits total", s.visits_total],
      ["Whitelist", s.whitelist],
      ["Blacklist", s.blacklist],
    ]
      .map(
        ([label, val]) =>
          `<div class="stat-card"><span class="muted">${esc(label)}</span><strong>${esc(val ?? 0)}</strong></div>`
      )
      .join("");
  }

  async function loadTopIps() {
    const data = await api("/top-ips");
    const tb = $("#table-top-ips tbody");
    tb.innerHTML = (data.items || [])
      .map((r) => {
        const tools = (r.tool_breakdown || [])
          .map((t) => `${esc(t.tool)}:${t.count}`)
          .join(" · ");
        return `<tr>
          <td class="mono">${esc(r.ip)} ${listBadge(r.listed)}</td>
          <td>${esc(r.hits)}</td>
          <td class="tiny">${esc(tools) || "—"}</td>
          <td class="tiny">${esc((r.last_seen || "").replace("T", " ").slice(0, 19))}</td>
          <td class="tiny">${esc(r.country_code || "—")} · ${esc(r.os || "")} / ${esc(r.browser || "")}</td>
          <td>${ipActions(r.ip, r.listed)}</td>
        </tr>`;
      })
      .join("");
    bindIpActions(tb);
  }

  async function loadLists() {
    const data = await api("/lists");
    const render = (el, type) => {
      const items = (data.items || []).filter((x) => x.list_type === type);
      el.innerHTML = items.length
        ? items
            .map(
              (x) => `<li>
            <div><code class="mono">${esc(x.ip)}</code><div class="tiny muted">${esc(x.note || "")}</div></div>
            <button type="button" class="btn btn-sm btn-ghost" data-rm="${esc(x.ip)}" data-rm-type="${esc(type)}">Remove</button>
          </li>`
            )
            .join("")
        : `<li class="muted">Empty</li>`;
      bindIpActions(el);
    };
    render($("#list-whitelist"), "whitelist");
    render($("#list-blacklist"), "blacklist");
  }

  $("#list-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    await api("/lists", {
      method: "POST",
      body: JSON.stringify({
        ip: fd.get("ip"),
        list_type: fd.get("list_type"),
        note: fd.get("note"),
      }),
    });
    e.target.reset();
    await loadLists();
  });

  async function loadQueries() {
    const tool = $("#filter-tool")?.value.trim() || "";
    const ip = $("#filter-ip")?.value.trim() || "";
    const qs = new URLSearchParams();
    if (tool) qs.set("tool", tool);
    if (ip) qs.set("ip", ip);
    const data = await api(`/queries?${qs}`);
    const tb = $("#table-queries tbody");
    tb.innerHTML = (data.items || [])
      .map(
        (r) => `<tr>
        <td class="tiny">${esc((r.ts || "").replace("T", " ").slice(0, 19))}</td>
        <td class="mono">${esc(r.ip)}</td>
        <td><span class="pill">${esc(r.tool)}</span></td>
        <td class="mono truncate" title="${esc(r.query)}">${esc(r.query || "—")}</td>
        <td class="tiny">${esc(r.os || "")} / ${esc(r.browser || "")}</td>
      </tr>`
      )
      .join("");
  }
  $("#btn-reload-queries")?.addEventListener("click", () => loadQueries());

  let chartTools;
  let chartDays;

  async function loadTools() {
    const data = await api("/tool-stats");
    const byTool = data.by_tool || [];
    const tb = $("#table-tool-counts tbody");
    tb.innerHTML = byTool
      .map((r) => `<tr><td>${esc(r.tool)}</td><td>${esc(r.count)}</td></tr>`)
      .join("");

    const labels = byTool.map((r) => r.tool);
    const values = byTool.map((r) => r.count);
    const ctx1 = $("#chart-tools");
    if (ctx1 && window.Chart) {
      chartTools?.destroy();
      chartTools = new Chart(ctx1, {
        type: "bar",
        data: {
          labels,
          datasets: [
            {
              label: "Queries (14d)",
              data: values,
              backgroundColor: "rgba(15,106,79,0.55)",
              borderRadius: 6,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }

    // Stack-ish day chart: total per day
    const dayMap = {};
    for (const row of data.by_day || []) {
      dayMap[row.day] = (dayMap[row.day] || 0) + row.count;
    }
    const days = Object.keys(dayMap).sort();
    const ctx2 = $("#chart-days");
    if (ctx2 && window.Chart) {
      chartDays?.destroy();
      chartDays = new Chart(ctx2, {
        type: "line",
        data: {
          labels: days,
          datasets: [
            {
              label: "Queries / day",
              data: days.map((d) => dayMap[d]),
              borderColor: "#0f6a4f",
              backgroundColor: "rgba(15,106,79,0.12)",
              fill: true,
              tension: 0.25,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }
  }

  async function loadMail() {
    const data = await api("/mail");
    const tb = $("#table-mail tbody");
    tb.innerHTML = (data.items || [])
      .map((r) => {
        const from = r.envelope_from || r.from_header || "—";
        return `<tr>
          <td class="tiny">${esc((r.created_at || "").replace("T", " ").slice(0, 19))}</td>
          <td class="mono tiny">${esc(r.address)}</td>
          <td><span class="pill">${esc(r.status)}</span></td>
          <td class="mono">${esc(r.peer_ip || "—")}</td>
          <td class="tiny truncate" title="${esc(from)}">${esc(from)}<div class="muted">${esc(r.subject || "")}</div></td>
          <td>${r.score != null ? esc(r.score) : "—"}</td>
        </tr>`;
      })
      .join("");
  }

  let mapInstance;

  async function loadVisitors() {
    const data = await api("/visitors");
    const countries = data.countries || [];
    $("#visitor-countries").innerHTML = countries
      .slice(0, 8)
      .map(
        (c) =>
          `<div class="stat-card"><span class="muted">${esc(c.name || c.code)}</span><strong>${esc(c.count)}</strong><div class="tiny muted">${esc(c.ips)} IPs</div></div>`
      )
      .join("");

    const values = {};
    countries.forEach((c) => {
      if (c.code) values[c.code] = c.count;
    });
    if (window.jsVectorMap) {
      try {
        mapInstance?.destroy?.();
      } catch (_) {
        /* ignore */
      }
      $("#admin-map").innerHTML = "";
      mapInstance = new jsVectorMap({
        selector: "#admin-map",
        map: "world",
        series: {
          regions: [
            {
              attribute: "fill",
              values,
              scale: ["#d7e8df", "#0f6a4f"],
            },
          ],
        },
      });
    }

    const tb = $("#table-visitors tbody");
    tb.innerHTML = (data.top || [])
      .map((r) => {
        return `<tr>
          <td class="mono">${esc(r.ip)}</td>
          <td>${esc(r.hits)}</td>
          <td>${esc(r.country_code || "—")}</td>
          <td class="tiny">${esc(r.city || "—")}<div class="muted">${esc(r.isp || "")}</div></td>
          <td class="tiny">${esc(r.os || "")} / ${esc(r.browser || "")}<div class="muted">${esc(r.device || "")}</div></td>
          <td class="tiny">${esc((r.last_seen || "").replace("T", " ").slice(0, 19))}</td>
          <td>${ipActions(r.ip, null)}</td>
        </tr>`;
      })
      .join("");
    bindIpActions(tb);

    const vt = $("#table-visits tbody");
    vt.innerHTML = (data.recent || [])
      .map(
        (r) => `<tr>
        <td class="tiny">${esc((r.ts || "").replace("T", " ").slice(0, 19))}</td>
        <td class="mono">${esc(r.ip)}</td>
        <td class="mono tiny truncate">${esc(r.path || "/")}</td>
        <td class="tiny">${esc(r.os || "")}</td>
        <td class="tiny">${esc(r.browser || "")}</td>
        <td class="tiny">${esc(r.country_code || "—")} ${esc(r.city || "")}</td>
      </tr>`
      )
      .join("");
  }

  async function loadAll() {
    await Promise.all([
      loadOverview(),
      loadTopIps(),
      loadLists(),
      loadQueries(),
      loadTools(),
      loadMail(),
      loadVisitors(),
    ]);
  }

  initAuth();
})();
