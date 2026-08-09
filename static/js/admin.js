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

  function cellSortValue(td, type) {
    const raw = (td?.dataset?.sortValue ?? td?.textContent ?? "").trim();
    if (type === "number") {
      const n = parseFloat(String(raw).replace(/[^\d.-]/g, ""));
      return Number.isFinite(n) ? n : 0;
    }
    if (type === "date") {
      const t = Date.parse(raw.replace(" ", "T"));
      return Number.isFinite(t) ? t : 0;
    }
    return raw.toLowerCase();
  }

  function sortTable(table, col, type, dir) {
    const tbody = table.querySelector("tbody");
    if (!tbody) return;
    const rows = [...tbody.querySelectorAll("tr")];
    rows.sort((a, b) => {
      const av = cellSortValue(a.children[col], type);
      const bv = cellSortValue(b.children[col], type);
      if (av < bv) return dir === "asc" ? -1 : 1;
      if (av > bv) return dir === "asc" ? 1 : -1;
      return 0;
    });
    rows.forEach((r) => tbody.appendChild(r));
  }

  function bindSortableTables(root = document) {
    root.querySelectorAll("table.sortable").forEach((table) => {
      if (table.dataset.sortBound === "1") return;
      table.dataset.sortBound = "1";
      table.querySelectorAll("th[data-sort]").forEach((th) => {
        th.addEventListener("click", () => {
          const col = Number(th.dataset.col || 0);
          const type = th.dataset.sort || "string";
          const next =
            th.classList.contains("sort-asc")
              ? "desc"
              : th.classList.contains("sort-desc")
                ? "asc"
                : type === "number" || type === "date"
                  ? "desc"
                  : "asc";
          table.querySelectorAll("th").forEach((h) => {
            h.classList.remove("sort-asc", "sort-desc");
          });
          th.classList.add(next === "asc" ? "sort-asc" : "sort-desc");
          sortTable(table, col, type, next);
        });
      });
    });
  }

  function setInboxBadge(n) {
    const badge = $("#nav-inbox-badge");
    if (!badge) return;
    const count = Number(n) || 0;
    badge.textContent = String(count);
    badge.classList.toggle("hidden", count <= 0);
  }

  function gaugeColor(pct) {
    if (pct >= 85) return "#b42318";
    if (pct >= 65) return "#b86a00";
    return "#0c5c45";
  }

  function makeGauge(canvas, pct) {
    if (!canvas || !window.Chart) return null;
    const value = Math.max(0, Math.min(100, Number(pct) || 0));
    return new Chart(canvas, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [value, 100 - value],
            backgroundColor: [gaugeColor(value), "#e4ebe6"],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        cutout: "72%",
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      },
    });
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

  function showPanel(name) {
    ["password-panel", "setup-panel", "otp-panel"].forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.toggle("hidden", id !== name);
    });
  }

  function renderSetupQr(setup) {
    const box = $("#qr-box");
    const secret = setup?.secret || "";
    $("#setup-secret").textContent = secret;
    if (setup?.qr_svg) {
      box.innerHTML = setup.qr_svg;
    } else if (setup?.qr_img) {
      box.innerHTML = `<img src="${esc(setup.qr_img)}" width="220" height="220" alt="QR code">`;
    } else if (setup?.otpauth_url) {
      box.innerHTML = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(
        setup.otpauth_url
      )}" width="220" height="220" alt="QR code">`;
    } else {
      box.innerHTML = "<p class='muted'>Could not generate QR — enter the secret manually.</p>";
    }
  }

  async function initAuth() {
    showPanel("password-panel");
    $("#auth-lead").textContent = "1) Sign in with username and password.";
    try {
      await api("/overview");
      showApp();
      loadAll();
    } catch (_) {
      showAuth();
      showPanel("password-panel");
    }
  }

  $("#btn-password-login")?.addEventListener("click", async () => {
    setAuthError("");
    try {
      const data = await api("/login", {
        method: "POST",
        body: JSON.stringify({
          username: $("#login-user").value,
          password: $("#login-pass").value,
        }),
      });
      if (data.need_setup) {
        $("#auth-lead").textContent = "2) Finish authenticator setup.";
        showPanel("setup-panel");
        renderSetupQr(data.setup || {});
        // Refresh QR from server (preauth cookie now set)
        try {
          const setup = await api("/setup");
          renderSetupQr(setup);
        } catch (_) {
          /* keep embedded setup */
        }
        $("#setup-code")?.focus();
        return;
      }
      if (data.need_otp) {
        $("#auth-lead").textContent = "2) Enter your authenticator code.";
        showPanel("otp-panel");
        $("#login-otp")?.focus();
        return;
      }
      showApp();
      loadAll();
    } catch (err) {
      setAuthError(String(err.message || err));
    }
  });

  $("#btn-confirm-setup")?.addEventListener("click", async () => {
    setAuthError("");
    try {
      await api("/setup/confirm", {
        method: "POST",
        body: JSON.stringify({ code: $("#setup-code").value }),
      });
      document.body.dataset.setupComplete = "1";
      showApp();
      loadAll();
    } catch (err) {
      setAuthError(String(err.message || err));
    }
  });

  $("#btn-otp-login")?.addEventListener("click", async () => {
    setAuthError("");
    try {
      await api("/login/otp", {
        method: "POST",
        body: JSON.stringify({ otp: $("#login-otp").value }),
      });
      showApp();
      loadAll();
    } catch (err) {
      setAuthError(String(err.message || err));
    }
  });

  $("#login-pass")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-password-login")?.click();
  });
  $("#setup-code")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-confirm-setup")?.click();
  });
  $("#login-otp")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-otp-login")?.click();
  });

  $("#btn-logout")?.addEventListener("click", async () => {
    try {
      await api("/logout", { method: "POST", body: "{}" });
    } catch (_) {
      /* ignore */
    }
    showAuth();
    showPanel("password-panel");
    $("#auth-lead").textContent = "1) Sign in with username and password.";
    $("#login-pass").value = "";
    $("#login-otp").value = "";
    $("#setup-code").value = "";
  });

  // Tabs
  $$(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      $$(".tab").forEach((t) => t.classList.remove("active"));
      $(`#tab-${btn.dataset.tab}`)?.classList.add("active");
      $("#admin-nav")?.classList.remove("open");
      if (btn.dataset.tab === "account") loadAccount();
      if (btn.dataset.tab === "inbox") loadInbox();
      if (btn.dataset.tab === "overview") {
        loadOverview();
        loadSystem();
      }
    });
  });
  $("#nav-toggle")?.addEventListener("click", () => {
    $("#admin-nav")?.classList.toggle("open");
  });
  bindSortableTables();

  function setAccountMsg(ok, err) {
    const okEl = $("#account-ok");
    const errEl = $("#account-error");
    if (okEl) {
      okEl.hidden = !ok;
      okEl.textContent = ok || "";
    }
    if (errEl) {
      errEl.hidden = !err;
      errEl.textContent = err || "";
    }
  }

  function renderAccountQr(setup) {
    const box = $("#acct-qr-box");
    const secretEl = $("#acct-setup-secret");
    if (!box) return;
    if (secretEl) secretEl.textContent = setup?.secret || "";
    if (setup?.qr_svg) {
      box.innerHTML = setup.qr_svg;
    } else if (setup?.qr_img) {
      box.innerHTML = `<img src="${esc(setup.qr_img)}" width="220" height="220" alt="QR code">`;
    } else if (setup?.otpauth_url) {
      box.innerHTML = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(
        setup.otpauth_url
      )}" width="220" height="220" alt="QR code">`;
    } else {
      box.innerHTML = "<p class='muted'>Could not generate QR — enter the secret manually.</p>";
    }
  }

  async function loadAccount() {
    setAccountMsg("", "");
    const data = await api("/profile");
    $("#acct-username").value = data.username || "";
    $("#account-meta").textContent =
      data.password_source === "database"
        ? "Password is stored in the admin database (overrides .env)."
        : "Password currently comes from server .env — changing it here moves it into the database.";
    const totpOn = !!data.totp_active;
    $("#acct-totp-status").textContent = totpOn
      ? "Authenticator is active."
      : "Authenticator is not active — scan a new QR below after reset.";
    $("#acct-pass-otp-wrap")?.classList.toggle("hidden", !totpOn);
    $("#acct-totp-otp-wrap")?.classList.toggle("hidden", !totpOn);
  }

  $("#btn-save-username")?.addEventListener("click", async () => {
    setAccountMsg("", "");
    try {
      const data = await api("/profile/username", {
        method: "POST",
        body: JSON.stringify({
          username: $("#acct-username").value,
          current_password: $("#acct-user-pass").value,
        }),
      });
      $("#acct-user-pass").value = "";
      $("#login-user").value = data.username || $("#acct-username").value;
      setAccountMsg("Username updated.", "");
      await loadAccount();
    } catch (err) {
      setAccountMsg("", String(err.message || err));
    }
  });

  $("#btn-save-password")?.addEventListener("click", async () => {
    setAccountMsg("", "");
    try {
      await api("/profile/password", {
        method: "POST",
        body: JSON.stringify({
          current_password: $("#acct-pass-current").value,
          new_password: $("#acct-pass-new").value,
          confirm_password: $("#acct-pass-confirm").value,
          otp: $("#acct-pass-otp")?.value || "",
        }),
      });
      $("#acct-pass-current").value = "";
      $("#acct-pass-new").value = "";
      $("#acct-pass-confirm").value = "";
      if ($("#acct-pass-otp")) $("#acct-pass-otp").value = "";
      setAccountMsg("Password updated. Use the new password next login.", "");
      await loadAccount();
    } catch (err) {
      setAccountMsg("", String(err.message || err));
    }
  });

  $("#btn-totp-reset")?.addEventListener("click", async () => {
    setAccountMsg("", "");
    if (!confirm("Remove the current authenticator and show a new QR?")) return;
    try {
      const data = await api("/profile/totp/reset", {
        method: "POST",
        body: JSON.stringify({
          current_password: $("#acct-totp-pass").value,
          otp: $("#acct-totp-otp")?.value || "",
        }),
      });
      $("#acct-totp-pass").value = "";
      if ($("#acct-totp-otp")) $("#acct-totp-otp").value = "";
      $("#acct-totp-enroll")?.classList.remove("hidden");
      renderAccountQr(data);
      setAccountMsg("Old authenticator removed. Scan the new QR and activate it.", "");
      await loadAccount();
    } catch (err) {
      setAccountMsg("", String(err.message || err));
    }
  });

  $("#btn-totp-confirm")?.addEventListener("click", async () => {
    setAccountMsg("", "");
    try {
      await api("/profile/totp/confirm", {
        method: "POST",
        body: JSON.stringify({ code: $("#acct-totp-confirm").value }),
      });
      $("#acct-totp-confirm").value = "";
      $("#acct-totp-enroll")?.classList.add("hidden");
      setAccountMsg("New authenticator activated.", "");
      document.body.dataset.setupComplete = "1";
      await loadAccount();
    } catch (err) {
      setAccountMsg("", String(err.message || err));
    }
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
    setInboxBadge(s.inbox_unread);
    $("#overview-stats").innerHTML = [
      ["Queries today", s.queries_today],
      ["Visits today", s.visits_today],
      ["Unique IPs today", s.unique_ips_today],
      ["Inbox unread", s.inbox_unread],
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

  let chartCpu;
  let chartMem;
  let chartDisk;

  async function loadSystem() {
    const data = await api("/system");
    const cpu = data.cpu_percent ?? 0;
    const mem = data.memory || {};
    const disk = data.disk || {};
    $("#system-host").textContent = data.hostname || "—";
    $("#sys-cpu").textContent = `${cpu}%`;
    $("#sys-mem").textContent = `${mem.percent ?? 0}%`;
    $("#sys-disk").textContent = `${disk.percent ?? 0}%`;
    $("#system-detail").textContent =
      `Load ${((data.loadavg || []).join(" / ")) || "—"} · ` +
      `RAM ${mem.used_human || "—"} / ${mem.total_human || "—"} (${mem.source || "—"}) · ` +
      `Disk ${disk.used_human || "—"} / ${disk.total_human || "—"} free ${disk.free_human || "—"}`;

    chartCpu?.destroy();
    chartMem?.destroy();
    chartDisk?.destroy();
    chartCpu = makeGauge($("#chart-cpu"), cpu);
    chartMem = makeGauge($("#chart-mem"), mem.percent);
    chartDisk = makeGauge($("#chart-disk"), disk.percent);
  }
  $("#btn-refresh-system")?.addEventListener("click", () => loadSystem());

  let inboxItems = [];

  function kindPill(kind) {
    return `<span class="pill ${esc(kind || "")}">${esc(kind || "—")}</span>`;
  }

  async function openInboxItem(id) {
    const data = await api(`/inbox/${id}`);
    const item = data.item || {};
    setInboxBadge(data.unread);
    const box = $("#inbox-detail");
    box.innerHTML = `
      <div class="panel-card-head">
        <h3>${esc(item.title || "Untitled")}</h3>
        ${kindPill(item.kind)}
      </div>
      <p class="tiny muted">${esc((item.created_at || "").replace("T", " ").slice(0, 19))} UTC</p>
      <p class="tiny"><span class="muted">Contact:</span> ${esc(item.contact_email || "—")}</p>
      <p class="tiny"><span class="muted">IP:</span> <span class="mono">${esc(item.ip || "—")}</span></p>
      <p class="tiny"><span class="muted">Page:</span> ${
        item.page_url
          ? `<a href="${esc(item.page_url)}" target="_blank" rel="noopener">${esc(item.page_url)}</a>`
          : "—"
      }</p>
      <div class="msg-body">${esc(item.message || "")}</div>
      <div class="inbox-actions">
        <button type="button" class="btn btn-sm btn-ghost" id="btn-inbox-unread">Mark unread</button>
        <button type="button" class="btn btn-sm btn-danger" id="btn-inbox-delete">Delete</button>
      </div>`;
    $("#btn-inbox-unread")?.addEventListener("click", async () => {
      const res = await api(`/inbox/${id}/read`, {
        method: "POST",
        body: JSON.stringify({ is_read: false }),
      });
      setInboxBadge(res.unread);
      await loadInbox(false);
    });
    $("#btn-inbox-delete")?.addEventListener("click", async () => {
      if (!confirm("Delete this message?")) return;
      const res = await api(`/inbox/${id}`, { method: "DELETE" });
      setInboxBadge(res.unread);
      $("#inbox-detail").innerHTML = `<p class="muted">Select a message.</p>`;
      await loadInbox(false);
    });
    // refresh list read state
    await loadInbox(false, id);
  }

  async function loadInbox(resetDetail = true, keepId = null) {
    const unreadOnly = !!$("#inbox-unread-only")?.checked;
    const qs = unreadOnly ? "?unread=1" : "";
    const data = await api(`/inbox${qs}`);
    inboxItems = data.items || [];
    setInboxBadge(data.unread);
    const tb = $("#table-inbox tbody");
    tb.innerHTML = inboxItems.length
      ? inboxItems
          .map((r) => {
            const when = (r.created_at || "").replace("T", " ").slice(0, 19);
            const from = r.contact_email || r.ip || "—";
            return `<tr class="${r.is_read ? "" : "unread"}" data-id="${esc(r.id)}">
              <td class="tiny" data-sort-value="${esc(r.created_at || "")}">${esc(when)}</td>
              <td>${kindPill(r.kind)}</td>
              <td>${esc(r.title)}</td>
              <td class="tiny truncate" title="${esc(from)}">${esc(from)}</td>
              <td><button type="button" class="btn btn-sm btn-ghost" data-open="${esc(r.id)}">Open</button></td>
            </tr>`;
          })
          .join("")
      : `<tr><td colspan="5" class="muted">No messages yet.</td></tr>`;
    tb.querySelectorAll("[data-open]").forEach((btn) => {
      btn.addEventListener("click", () => openInboxItem(btn.dataset.open));
    });
    tb.querySelectorAll("tr[data-id]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("button")) return;
        openInboxItem(tr.dataset.id);
      });
    });
    if (resetDetail && !keepId) {
      $("#inbox-detail").innerHTML = `<p class="muted">Select a message.</p>`;
    }
  }
  $("#inbox-unread-only")?.addEventListener("change", () => loadInbox());

  async function loadTopIps() {
    const data = await api("/top-ips");
    const tb = $("#table-top-ips tbody");
    tb.innerHTML = (data.items || [])
      .map((r) => {
        const tools = (r.tool_breakdown || [])
          .map((t) => `${esc(t.tool)}:${t.count}`)
          .join(" · ");
        const last = (r.last_seen || "").replace("T", " ").slice(0, 19);
        return `<tr>
          <td class="mono" data-sort-value="${esc(r.ip)}">${esc(r.ip)} ${listBadge(r.listed)}</td>
          <td data-sort-value="${esc(r.hits)}">${esc(r.hits)}</td>
          <td class="tiny">${esc(tools) || "—"}</td>
          <td class="tiny" data-sort-value="${esc(r.last_seen || "")}">${esc(last)}</td>
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
        const path = r.report_path || (r.id ? `/tools/mailtest/${r.id}` : "");
        const reportCell =
          r.status === "received" && path
            ? `<a href="${esc(path)}" target="_blank" rel="noopener">Open</a>`
            : path
              ? `<a class="muted" href="${esc(path)}" target="_blank" rel="noopener">Page</a>`
              : "—";
        return `<tr>
          <td class="tiny" data-sort-value="${esc(r.created_at || "")}">${esc((r.created_at || "").replace("T", " ").slice(0, 19))}</td>
          <td class="mono tiny">${esc(r.address)}</td>
          <td><span class="pill">${esc(r.status)}</span></td>
          <td class="tiny" data-sort-value="${esc(r.expires_at || "")}">${esc((r.expires_at || "").replace("T", " ").slice(0, 19) || "—")}</td>
          <td class="mono">${esc(r.peer_ip || "—")}</td>
          <td class="tiny truncate" title="${esc(from)}">${esc(from)}<div class="muted">${esc(r.subject || "")}</div></td>
          <td data-sort-value="${esc(r.score ?? "")}">${r.score != null ? esc(r.score) : "—"}</td>
          <td>${reportCell}</td>
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
          <td data-sort-value="${esc(r.hits)}">${esc(r.hits)}</td>
          <td>${esc(r.country_code || "—")}</td>
          <td class="tiny">${esc(r.city || "—")}<div class="muted">${esc(r.isp || "")}</div></td>
          <td class="tiny">${esc(r.os || "")} / ${esc(r.browser || "")}<div class="muted">${esc(r.device || "")}</div></td>
          <td class="tiny" data-sort-value="${esc(r.last_seen || "")}">${esc((r.last_seen || "").replace("T", " ").slice(0, 19))}</td>
          <td>${ipActions(r.ip, null)}</td>
        </tr>`;
      })
      .join("");
    bindIpActions(tb);

    const vt = $("#table-visits tbody");
    vt.innerHTML = (data.recent || [])
      .map(
        (r) => `<tr>
        <td class="tiny" data-sort-value="${esc(r.ts || "")}">${esc((r.ts || "").replace("T", " ").slice(0, 19))}</td>
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
      loadSystem(),
      loadInbox(false),
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
