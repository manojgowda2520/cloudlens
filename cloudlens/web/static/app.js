// cloudlens UI glue. No third-party scripts: everything the page needs is here.
(function () {
  const csrf = document.querySelector('meta[name="csrf"]').content;

  function toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.style.display = "block";
    clearTimeout(t._h);
    t._h = setTimeout(() => (t.style.display = "none"), 5000);
  }
  window.cl = { toast };

  async function post(url, body) {
    const resp = await fetch(url, { method: "POST", headers: { "X-CSRF-Token": csrf }, body });
    if (!resp.ok) {
      toast(await resp.text());
      return null;
    }
    const go = resp.headers.get("X-Redirect");
    if (go) {
      if (go.split("#")[0] === location.pathname) location.reload();
      else location.href = go;
    }
    return resp;
  }
  window.cl.post = post;

  // <form data-post> and <button data-post="/url" data-confirm="...">
  document.addEventListener("submit", async (e) => {
    const f = e.target;
    if (!f.matches("form[data-post]")) return;
    e.preventDefault();
    if (f.dataset.scan !== undefined && f.modules) {
      const mods = [...f.querySelectorAll(".mod:checked")].map((x) => x.value);
      if (mods.length) f.modules.value = mods.join(",");
    }
    const resp = await post(f.action, new FormData(f));
    if (resp && resp.status === 204 && !resp.headers.get("X-Redirect") && f.dataset.reload !== undefined) location.reload();
    if (resp && f.dataset.done) toast(f.dataset.done);
  });
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-post-url]");
    if (!b) return;
    e.preventDefault();
    if (b.dataset.confirm && !confirm(b.dataset.confirm)) return;
    const body = new FormData();
    for (const [k, v] of Object.entries(b.dataset)) if (k.startsWith("f")) body.append(k.slice(1).toLowerCase(), v);
    const resp = await post(b.dataset.postUrl, body);
    if (resp && b.dataset.reload !== undefined && !resp.headers.get("X-Redirect")) location.reload();
  });
  // Inputs that save on change: <input data-save="/accounts/x" data-field="enabled">
  document.addEventListener("change", async (e) => {
    const el = e.target;
    if (el.matches("select[data-autosubmit]")) return el.form.submit();
    if (!el.dataset.save) return;
    const body = new FormData();
    body.append("field", el.dataset.field);
    body.append(el.name, el.type === "checkbox" ? (el.checked ? "1" : "0") : el.value);
    const resp = await post(el.dataset.save, body);
    if (resp) toast("Saved");
  });

  // Scan status pill in the header, polled while a scan runs.
  const pill = document.getElementById("scan-pill");
  async function pollScan() {
    const s = await (await fetch("/scan/status")).json();
    if (!pill) return;
    if (s.running) {
      pill.hidden = false;
      pill.textContent = `Scanning: ${s.phase} ${s.total ? s.done + "/" + s.total : ""}`;
      const bar = document.getElementById("scan-progress");
      if (bar) bar.style.width = (s.total ? (100 * s.done) / s.total : 5) + "%";
      const log = document.getElementById("scan-log");
      if (log) log.textContent = s.log.join("\n");
      setTimeout(pollScan, 2000);
    } else if (!pill.hidden) {
      location.reload();
    }
  }
  if (pill && pill.dataset.running === "1") pollScan();
  window.cl.pollScan = () => { if (pill) { pill.hidden = false; pollScan(); } };

  // SSO sign-in: open the verification page, then poll until approved.
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-login]");
    if (!b) return;
    e.preventDefault();
    const pid = b.dataset.login;
    const box = document.getElementById("login-" + pid);
    const resp = await post(`/portals/${pid}/login`, new FormData());
    if (!resp) return;
    const info = await resp.json();
    window.open(info.url, "_blank", "noopener");
    box.hidden = false;
    box.innerHTML = `Approve the sign-in in the tab that just opened. Code: <b class="mono">${info.code}</b>
      <a href="${info.url}" target="_blank" rel="noopener">reopen</a> · waiting…`;
    let interval = info.interval || 5;
    const tick = async () => {
      const r = await post(`/portals/${pid}/poll`, new FormData());
      if (!r) return;
      const s = await r.json();
      if (s.state === "pending") { interval = s.interval || interval; setTimeout(tick, interval * 1000); }
      else if (s.state === "done") { box.textContent = s.message; setTimeout(() => location.reload(), 1200); }
      else { box.textContent = s.message || "Sign-in did not complete."; }
    };
    setTimeout(tick, interval * 1000);
  });
})();
