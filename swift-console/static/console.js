/* Swift Console: one hand-written file. Pages are server-rendered; this only
   wires interactions (uploads with progress, dialogs, metadata editors,
   trash, sharing). No frameworks. */
(function () {
  "use strict";

  var $ = function (s, el) { return (el || document).querySelector(s); };
  var $$ = function (s, el) { return Array.prototype.slice.call((el || document).querySelectorAll(s)); };
  var body = document.body;
  var PAGE = body.dataset.page || "";
  var BUCKET = body.dataset.bucket || "";
  var PREFIX = body.dataset.prefix || "";

  var GIB = 1024 * 1024 * 1024;
  var SEG = 64 * 1024 * 1024;

  // Strings the server cannot render because JS builds the element. Keyed the
  // same way as the server table so the two stay recognisably one system.
  var ZH = document.documentElement.lang === "zh-CN";
  function T(en, zh) { return ZH ? zh : en; }

  function encPath(p) {
    return p.split("/").map(encodeURIComponent).join("/");
  }
  function fmtBytes(n) {
    if (n < 1024) return Math.round(n) + " B";
    var u = ["KiB", "MiB", "GiB", "TiB"], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return (n >= 10 ? n.toFixed(1) : n.toFixed(2)) + " " + u[i];
  }

  function api(method, url, bodyObj) {
    var opts = { method: method, headers: {} };
    if (bodyObj !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(bodyObj);
    }
    return fetch(url, opts).then(function (r) {
      if (r.status === 401) { location.href = "/login"; throw new Error("signed out"); }
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || T(method + " failed (" + r.status + ")", method + " 请求失败（" + r.status + "）"));
        return j;
      });
    });
  }

  // ------------------------------------------------------------- theme
  // The server already rendered the correct data-theme; this only handles
  // switching without a reload. Everything is var()-driven, so one attribute
  // change re-themes the whole document in a single style recalculation.
  function syncDeployFrame() {
    var f = document.querySelector(".frame-wrap iframe");
    if (!f) return;
    try {
      var d = f.contentDocument;
      if (!d) return;
      var t = document.documentElement.getAttribute("data-theme");
      if (t) d.documentElement.setAttribute("data-theme", t);
      else d.documentElement.removeAttribute("data-theme");
      // The Deploy pane keeps its own language in localStorage and re-renders
      // when its (now hidden) buttons are pressed. Drive that mechanism rather
      // than fight it, so the console's choice wins everywhere.
      var lang = document.documentElement.lang === "zh-CN" ? "zh" : "en";
      var w = f.contentWindow;
      if (w && w.localStorage) w.localStorage.setItem("swift-deploy-language", lang);
      var btn = d.querySelector('[data-language="' + lang + '"]');
      if (btn && btn.getAttribute("aria-pressed") !== "true") btn.click();
    } catch (e) { /* cross-origin one day: nothing to do */ }
  }

  function applyTheme(t) {
    if (t !== "light" && t !== "dark") return;
    var root = document.documentElement;
    root.setAttribute("data-theme", t);
    document.cookie = "sc_theme=" + t +
      "; Path=/; SameSite=Lax; Max-Age=31536000";
    $$(".theme-seg .seg-b").forEach(function (b) {
      var on = b.value === t;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    syncDeployFrame();
    // Canvas paints resolved hexes; force a redraw after the token arm flips.
    try {
      if (window.CHART && typeof window.CHART.onThemeChange === "function") {
        window.CHART.onThemeChange();
      }
    } catch (e) { /* charts not mounted yet */ }
  }

  // Bind by action, not by class: the language switch is a sibling form that
  // must submit natively (its text is server-rendered), only theme is a
  // client-side CSS swap.
  var themeForm = document.querySelector('form[action="/theme"]');
  if (themeForm) themeForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    applyTheme((ev.submitter && ev.submitter.value) || "dark");
  });
  var deployFrame = document.querySelector(".frame-wrap iframe");
  if (deployFrame) deployFrame.addEventListener("load", syncDeployFrame);

  function setErr(id, msg) {
    var el = $(id);
    if (el) el.textContent = msg || "";
  }

  function openDlg(id) { var d = $(id); if (d && !d.open) d.showModal(); return d; }
  function closeDlg(id) { var d = $(id); if (d && d.open) d.close(); }

  // Copy buttons (share/public links).
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest(".act-copy");
    if (!b) return;
    var inp = document.getElementById(b.dataset.copy);
    if (!inp) return;
    inp.select();
    var done = function () { b.textContent = T("Copied", "已复制"); setTimeout(function () { b.textContent = T("Copy", "复制"); }, 1200); };
    if (navigator.clipboard) navigator.clipboard.writeText(inp.value).then(done, done);
    else { document.execCommand("copy"); done(); }
  });

  // ------------------------------------------------------------ new bucket

  function wireNewBucket(openBtnSel) {
    var btn = $(openBtnSel);
    if (btn) btn.addEventListener("click", function () {
      setErr("#nb-err", "");
      var i = $("#nb-name"); if (i) i.value = "";
      openDlg("#dlg-new-bucket");
      if (i) i.focus();
    });
  }
  wireNewBucket("#new-bucket-btn");
  wireNewBucket("#side-new-bucket");
  var nbCreate = $("#nb-create");
  if (nbCreate) nbCreate.addEventListener("click", function (ev) {
    ev.preventDefault();
    var name = ($("#nb-name").value || "").trim();
    if (!name) { setErr("#nb-err", T("Name is required.", "名称不能为空。")); return; }
    api("POST", "/files/api/buckets", { name: name })
      .then(function () { location.href = "/files/b/" + encodeURIComponent(name); })
      .catch(function (e) { setErr("#nb-err", e.message); });
  });

  // ------------------------------------------------------------ bucket settings

  var bsBucket = null;
  function metaRow(container, k, v) {
    var row = document.createElement("div");
    row.className = "meta-row";
    var mk = document.createElement("input");
    mk.className = "mk"; mk.placeholder = T("key", "键"); mk.spellcheck = false; mk.value = k || "";
    var mv = document.createElement("input");
    mv.className = "mv"; mv.placeholder = T("value", "值"); mv.spellcheck = false; mv.value = v || "";
    var del = document.createElement("button");
    del.className = "ibtn danger meta-del"; del.type = "button"; del.title = T("Remove", "移除");
    del.innerHTML = '<svg class="ic" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.6 4.6l6.8 6.8"/><path d="M11.4 4.6l-6.8 6.8"/></svg>';
    del.addEventListener("click", function () { row.remove(); });
    row.appendChild(mk); row.appendChild(mv); row.appendChild(del);
    container.appendChild(row);
  }
  // Delegate removal for server-rendered meta rows (account page).
  document.addEventListener("click", function (ev) {
    var d = ev.target.closest(".meta-del");
    if (d) { ev.preventDefault(); d.closest(".meta-row").remove(); }
  });

  function readMetaRows(container) {
    var set = {}, seen = {};
    $$(".meta-row", container).forEach(function (row) {
      var k = $(".mk", row).value.trim();
      var v = $(".mv", row).value;
      if (k) { set[k] = v; seen[k.toLowerCase()] = true; }
    });
    return { set: set, seen: seen };
  }

  function openBucketSettings(bucket) {
    bsBucket = bucket;
    setErr("#bs-err", "");
    $("#bs-title").textContent = T("Bucket settings: ", "存储桶设置：") + bucket;
    var metaBox = $("#bs-meta"); metaBox.innerHTML = "";
    $("#bs-stats").textContent = T("Loading…", "加载中…");
    openDlg("#dlg-bucket-settings");
    api("GET", "/files/api/bucket/" + encodeURIComponent(bucket) + "/meta")
      .then(function (m) {
        $("#bs-read").value = m.read_acl || "";
        $("#bs-write").value = m.write_acl || "";
        ($("#bs-" + (m.public ? "public" : "private")) || {}).checked = true;
        $("#bs-quota-bytes").value = m.quota_bytes || "";
        $("#bs-quota-count").value = m.quota_count || "";
        Object.keys(m.meta || {}).sort().forEach(function (k) { metaRow(metaBox, k, m.meta[k]); });
        window.__bsOrigMeta = m.meta || {};
        $("#bs-stats").textContent =
          (m.object_count || "0") + T(" objects · ", " 个对象 · ") + fmtBytes(parseInt(m.bytes_used || "0", 10)) +
          (m.policy ? T(" · policy ", " · 策略 ") + m.policy : "");
      })
      .catch(function (e) { setErr("#bs-err", e.message); });
  }

  document.addEventListener("click", function (ev) {
    var b = ev.target.closest(".act-bucket-settings, #bucket-settings-btn");
    if (b) openBucketSettings(b.dataset.bucket);
  });
  var bsPublic = $("#bs-public"), bsPrivate = $("#bs-private");
  if (bsPublic) bsPublic.addEventListener("change", function () {
    if (bsPublic.checked) $("#bs-read").value = ".r:*,.rlistings";
  });
  if (bsPrivate) bsPrivate.addEventListener("change", function () {
    if (bsPrivate.checked && $("#bs-read").value.indexOf(".r:*") !== -1) $("#bs-read").value = "";
  });
  var bsCancel = $("#bs-cancel");
  if (bsCancel) bsCancel.addEventListener("click", function () { closeDlg("#dlg-bucket-settings"); });
  var bsSave = $("#bs-save");
  if (bsSave) bsSave.addEventListener("click", function () {
    var rows = readMetaRows($("#bs-meta"));
    var remove = Object.keys(window.__bsOrigMeta || {}).filter(function (k) { return !rows.seen[k.toLowerCase()]; });
    api("POST", "/files/api/bucket/" + encodeURIComponent(bsBucket) + "/meta", {
      set: rows.set,
      remove: remove,
      read_acl: $("#bs-read").value.trim(),
      write_acl: $("#bs-write").value.trim(),
      quota_bytes: $("#bs-quota-bytes").value.trim(),
      quota_count: $("#bs-quota-count").value.trim()
    })
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#bs-err", e.message); });
  });

  document.addEventListener("click", function (ev) {
    var b = ev.target.closest(".act-bucket-delete");
    if (!b) return;
    var name = b.dataset.bucket;
    if (!confirm(T("Delete bucket \"" + name + "\"? Only empty buckets are removed; you will be asked before a force delete.",
      "确定删除存储桶“" + name + "”？只有空桶会直接删除；强制删除前还会再确认一次。"))) return;
    api("DELETE", "/files/api/bucket/" + encodeURIComponent(name))
      .then(function () { location.reload(); })
      .catch(function (e) {
        if (String(e.message).indexOf("not empty") !== -1) {
          var typed = prompt(T("Bucket \"" + name + "\" is not empty. Deleting it removes every object inside.\nType the bucket name to confirm force delete:",
            "存储桶“" + name + "”不是空的。删除它会连同里面的所有对象一起删掉。\n输入存储桶名称以确认强制删除："));
          if (typed === name) {
            api("DELETE", "/files/api/bucket/" + encodeURIComponent(name) + "?force=1")
              .then(function () { location.reload(); })
              .catch(function (e2) { alert(e2.message); });
          }
        } else {
          alert(e.message);
        }
      });
  });

  // ------------------------------------------------------- list pagination
  // Client-side pages over the server-rendered rows so the existing filter
  // still searches the full loaded set. Page size persists in localStorage.
  function bindListPager(opts) {
    var table = $(opts.table);
    var nav = $(opts.pager);
    if (!table || !nav) return null;
    var tbody = table.tBodies[0];
    if (!tbody) return null;
    var PER_KEY = "sc_list_per";
    var perChoices = [25, 50, 100, 200];
    function readPer() {
      var n = parseInt(localStorage.getItem(PER_KEY) || "", 10);
      return perChoices.indexOf(n) >= 0 ? n : 50;
    }
    function readPage() {
      try {
        var u = new URL(location.href);
        var p = parseInt(u.searchParams.get("page") || "1", 10);
        return isFinite(p) && p > 0 ? p : 1;
      } catch (e) { return 1; }
    }
    function writePage(p) {
      try {
        var u = new URL(location.href);
        if (p <= 1) u.searchParams.delete("page");
        else u.searchParams.set("page", String(p));
        history.replaceState(null, "", u.pathname + u.search + u.hash);
      } catch (e) { /* ignore */ }
    }
    var state = { page: readPage(), per: readPer(), q: "" };
    function allRows() {
      return Array.prototype.slice.call(tbody.querySelectorAll("tr"));
    }
    function matchRow(tr) {
      if (opts.systemSelector && tr.matches(opts.systemSelector)) return true;
      if (!state.q) return true;
      var name = (tr.dataset.name || tr.dataset.bucket || "").toLowerCase();
      if (!name && opts.nameFromRow) name = opts.nameFromRow(tr);
      return name.indexOf(state.q) !== -1;
    }
    function render() {
      var rows = allRows();
      var sys = [];
      var matched = [];
      rows.forEach(function (tr) {
        if (opts.systemSelector && tr.matches(opts.systemSelector)) sys.push(tr);
        else if (matchRow(tr)) matched.push(tr);
        else tr.style.display = "none";
      });
      var total = matched.length;
      var pages = Math.max(1, Math.ceil(total / state.per) || 1);
      if (state.page > pages) state.page = pages;
      if (state.page < 1) state.page = 1;
      var start = (state.page - 1) * state.per;
      var end = Math.min(start + state.per, total);
      matched.forEach(function (tr, i) {
        tr.style.display = (i >= start && i < end) ? "" : "none";
      });
      // System rows (trash / *_segments) stay visible under the current page.
      sys.forEach(function (tr) { tr.style.display = ""; });
      writePage(state.page);
      var showPager = total > perChoices[0] || state.per !== 50 || state.page > 1;
      if (!showPager && total <= state.per) {
        nav.hidden = true;
        nav.innerHTML = "";
        return;
      }
      nav.hidden = false;
      var rangeTxt = T("{a}–{b} of {n}", "第 {a}–{b} 条，共 {n} 条")
        .replace("{a}", total ? String(start + 1) : "0")
        .replace("{b}", String(end))
        .replace("{n}", String(total));
      var pageTxt = T("Page {p} / {m}", "第 {p} / {m} 页")
        .replace("{p}", String(state.page))
        .replace("{m}", String(pages));
      var perOpts = perChoices.map(function (n) {
        return "<option value=\"" + n + "\"" + (n === state.per ? " selected" : "") + ">" + n + "</option>";
      }).join("");
      // Compact page buttons: window around current.
      var buttons = [];
      var i, lo = Math.max(1, state.page - 2), hi = Math.min(pages, state.page + 2);
      if (lo > 1) {
        buttons.push(1);
        if (lo > 2) buttons.push("…");
      }
      for (i = lo; i <= hi; i++) buttons.push(i);
      if (hi < pages) {
        if (hi < pages - 1) buttons.push("…");
        buttons.push(pages);
      }
      var nums = buttons.map(function (b) {
        if (b === "…") return "<span class=\"pager-gap\">…</span>";
        return "<button type=\"button\" class=\"pager-num" + (b === state.page ? " active" : "") +
          "\" data-page=\"" + b + "\">" + b + "</button>";
      }).join("");
      nav.innerHTML =
        "<div class=\"pager-meta\">" +
          "<span class=\"pager-range\">" + rangeTxt + "</span>" +
          "<label class=\"pager-per\">" + T("Per page", "每页") +
          " <select class=\"pager-per-sel\">" + perOpts + "</select></label>" +
        "</div>" +
        "<div class=\"pager-nav\">" +
          "<button type=\"button\" class=\"pager-btn\" data-nav=\"prev\"" +
            (state.page <= 1 ? " disabled" : "") + ">" + T("Previous", "上一页") + "</button>" +
          "<span class=\"pager-pages\">" + nums + "</span>" +
          "<span class=\"pager-page\">" + pageTxt + "</span>" +
          "<button type=\"button\" class=\"pager-btn\" data-nav=\"next\"" +
            (state.page >= pages ? " disabled" : "") + ">" + T("Next", "下一页") + "</button>" +
        "</div>";
      var sel = $(".pager-per-sel", nav);
      if (sel) sel.addEventListener("change", function () {
        state.per = parseInt(sel.value, 10) || 50;
        try { localStorage.setItem(PER_KEY, String(state.per)); } catch (e) { /* ignore */ }
        state.page = 1;
        render();
      });
      nav.querySelectorAll("[data-nav]").forEach(function (b) {
        b.addEventListener("click", function () {
          if (b.dataset.nav === "prev" && state.page > 1) { state.page--; render(); }
          if (b.dataset.nav === "next" && state.page < pages) { state.page++; render(); }
        });
      });
      nav.querySelectorAll(".pager-num").forEach(function (b) {
        b.addEventListener("click", function () {
          state.page = parseInt(b.dataset.page, 10) || 1;
          render();
        });
      });
    }
    function setQuery(q) {
      state.q = (q || "").toLowerCase();
      state.page = 1;
      render();
    }
    render();
    return { setQuery: setQuery, render: render };
  }

  if (PAGE === "buckets") {
    bindListPager({
      table: "#bucket-table",
      pager: "#bucket-pager",
      systemSelector: "tr.muted-row",
      nameFromRow: function (tr) {
        return ((tr.dataset.bucket || "") + " " + (tr.textContent || "")).toLowerCase();
      }
    });
  }

  // ------------------------------------------------------------ objects page

  var objPager = null;
  if (PAGE === "objects") {
    objPager = bindListPager({
      table: "#obj-table",
      pager: "#obj-pager"
    });
  }

  var filter = $("#filter");
  if (filter) filter.addEventListener("input", function () {
    if (objPager) {
      objPager.setQuery(filter.value);
      return;
    }
    var q = filter.value.toLowerCase();
    $$("#obj-table tbody tr").forEach(function (tr) {
      var name = (tr.dataset.name || "").toLowerCase();
      tr.style.display = name.indexOf(q) === -1 ? "none" : "";
    });
  });

  var nfBtn = $("#new-folder-btn");
  if (nfBtn) nfBtn.addEventListener("click", function () {
    setErr("#nf-err", "");
    $("#nf-name").value = "";
    openDlg("#dlg-new-folder");
    $("#nf-name").focus();
  });
  var nfCreate = $("#nf-create");
  if (nfCreate) nfCreate.addEventListener("click", function (ev) {
    ev.preventDefault();
    var name = ($("#nf-name").value || "").trim().replace(/\/+$/, "");
    if (!name) { setErr("#nf-err", T("Folder name is required.", "文件夹名称不能为空。")); return; }
    api("POST", "/files/api/folder", { bucket: BUCKET, prefix: PREFIX + name })
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#nf-err", e.message); });
  });

  // Object / folder deletion and trash.
  document.addEventListener("click", function (ev) {
    var t;
    if ((t = ev.target.closest(".act-obj-delete"))) {
      var name = t.dataset.name;
      if (!confirm(T("Permanently delete \"" + name + "\"?", "永久删除“" + name + "”？"))) return;
      api("DELETE", "/files/api/obj/" + encodeURIComponent(BUCKET) + "/" + encPath(name))
        .then(function () { location.reload(); })
        .catch(function (e) { alert(e.message); });
    } else if ((t = ev.target.closest(".act-obj-trash"))) {
      api("POST", "/files/api/trash", { bucket: BUCKET, path: t.dataset.name })
        .then(function () { location.reload(); })
        .catch(function (e) { alert(e.message); });
    } else if ((t = ev.target.closest(".act-folder-delete"))) {
      var prefix = t.dataset.prefix;
      api("GET", "/files/api/bucket/" + encodeURIComponent(BUCKET) + "/count?prefix=" + encodeURIComponent(prefix))
        .then(function (c) {
          if (!confirm(T("Permanently delete " + c.count + " object" + (c.count === 1 ? "" : "s") +
            " (" + c.human + ") under \"" + prefix + "\"?",
            "永久删除“" + prefix + "”下的 " + c.count + " 个对象（" + c.human + "）？"))) return;
          api("POST", "/files/api/delete-folder", { bucket: BUCKET, prefix: prefix })
            .then(function () { location.reload(); })
            .catch(function (e) { alert(e.message); });
        })
        .catch(function (e) { alert(e.message); });
    } else if ((t = ev.target.closest(".act-folder-trash"))) {
      var pfx = t.dataset.prefix;
      api("GET", "/files/api/bucket/" + encodeURIComponent(BUCKET) + "/count?prefix=" + encodeURIComponent(pfx))
        .then(function (c) {
          if (!confirm(T("Move " + c.count + " object" + (c.count === 1 ? "" : "s") + " under \"" + pfx + "\" to trash?",
            "把“" + pfx + "”下的 " + c.count + " 个对象移入回收站？"))) return;
          api("POST", "/files/api/trash", { bucket: BUCKET, prefix: pfx })
            .then(function () { location.reload(); })
            .catch(function (e) { alert(e.message); });
        })
        .catch(function (e) { alert(e.message); });
    }
  });

  // ------------------------------------------------------------ upload (plain + SLO)

  var upBtn = $("#upload-btn");
  var upInput = $("#up-input");
  var upStart = $("#up-start");
  var upClose = $("#up-close");
  var uploading = false;

  if (upBtn) upBtn.addEventListener("click", function () {
    $("#up-list").innerHTML = "";
    if (upInput) upInput.value = "";
    openDlg("#dlg-upload");
  });
  if (upClose) upClose.addEventListener("click", function () {
    if (uploading && !confirm(T("Uploads are still running. Close anyway?", "还有上传在进行中。仍要关闭吗？"))) return;
    closeDlg("#dlg-upload");
    if (!uploading) location.reload();
  });

  function xhrPut(url, blob, ctype, onprogress) {
    return new Promise(function (resolve, reject) {
      var x = new XMLHttpRequest();
      x.open("PUT", url);
      x.setRequestHeader("Content-Type", ctype || "application/octet-stream");
      if (x.upload && onprogress) x.upload.onprogress = function (e) { onprogress(e.loaded); };
      x.onload = function () {
        if (x.status < 300) {
          var j = {};
          try { j = JSON.parse(x.responseText); } catch (e) { /* empty */ }
          resolve(j);
        } else {
          var msg = T("upload failed (" + x.status + ")", "上传失败（" + x.status + "）");
          try { msg = JSON.parse(x.responseText).error || msg; } catch (e) { /* keep */ }
          reject(new Error(msg));
        }
      };
      x.onerror = function () { reject(new Error(T("network error", "网络错误"))); };
      x.send(blob);
    });
  }

  function uploadRow(file) {
    var item = document.createElement("div");
    item.className = "up-item";
    item.innerHTML =
      '<div class="up-name"><span></span><span class="up-status"></span></div>' +
      '<div class="up-bar"><i></i></div>';
    $(".up-name span", item).textContent = file.name;
    $("#up-list").appendChild(item);
    return {
      status: function (txt, bad) {
        var s = $(".up-status", item);
        s.textContent = txt;
        s.className = "up-status" + (bad ? " bad" : "");
      },
      progress: function (frac) { $(".up-bar i", item).style.width = Math.min(100, frac * 100) + "%"; }
    };
  }

  function uploadPlain(file, row) {
    var url = "/files/api/obj/" + encodeURIComponent(BUCKET) + "/" + encPath(PREFIX + file.name);
    return xhrPut(url, file, file.type, function (loaded) {
      row.progress(loaded / (file.size || 1));
      row.status(fmtBytes(loaded) + T(" of ", " / ") + fmtBytes(file.size));
    }).then(function () { row.progress(1); row.status(T("Done", "完成")); });
  }

  function uploadSlo(file, row) {
    var segBucket = BUCKET + "_segments";
    var objPath = PREFIX + file.name;
    var nSegs = Math.ceil(file.size / SEG);
    var manifest = [];
    var sent = 0;
    row.status(T("Preparing segmented upload…", "正在准备分段上传…"));
    return api("POST", "/files/api/buckets", { name: segBucket }).catch(function () { /* exists */ })
      .then(function () {
        var p = Promise.resolve();
        var idx;
        var doSeg = function (i) {
          return function () {
            var start = i * SEG;
            var end = Math.min(file.size, start + SEG);
            var blob = file.slice(start, end);
            var segName = objPath + "/" + String(i + 1).padStart(8, "0");
            var url = "/files/api/obj/" + encodeURIComponent(segBucket) + "/" + encPath(segName);
            row.status(T("Segment " + (i + 1) + " of " + nSegs, "第 " + (i + 1) + " / " + nSegs + " 段"));
            return xhrPut(url, blob, "application/octet-stream", function (loaded) {
              row.progress((sent + loaded) / file.size);
            }).then(function (j) {
              sent += (end - start);
              row.progress(sent / file.size);
              manifest.push({ path: "/" + segBucket + "/" + segName, etag: j.etag, size_bytes: end - start });
            });
          };
        };
        for (idx = 0; idx < nSegs; idx++) p = p.then(doSeg(idx));
        return p;
      })
      .then(function () {
        row.status(T("Writing manifest…", "正在写入清单…"));
        var url = "/files/api/obj/" + encodeURIComponent(BUCKET) + "/" + encPath(objPath) + "?multipart-manifest=put";
        return fetch(url, {
          method: "PUT",
          headers: { "Content-Type": file.type || "application/octet-stream" },
          body: JSON.stringify(manifest)
        }).then(function (r) {
          if (!r.ok) return r.json().catch(function () { return {}; }).then(function (j) {
            throw new Error(j.error || T("manifest failed (" + r.status + ")", "清单写入失败（" + r.status + "）"));
          });
        });
      })
      .then(function () { row.progress(1); row.status(T("Done (SLO, " + nSegs + " segments)", "完成（SLO，" + nSegs + " 段）")); });
  }

  if (upStart) upStart.addEventListener("click", function () {
    var files = upInput.files;
    if (!files || !files.length) return;
    uploading = true;
    upStart.disabled = true;
    var chain = Promise.resolve();
    Array.prototype.forEach.call(files, function (file) {
      var row = uploadRow(file);
      chain = chain.then(function () {
        if (file.size > GIB) {
          row.status(T("Skipped: files larger than 1 GiB are not supported on this cluster.",
            "已跳过：本集群不支持大于 1 GiB 的文件。"), true);
          return;
        }
        var fn = file.size > SEG ? uploadSlo : uploadPlain;
        return fn(file, row).catch(function (e) { row.status(e.message, true); });
      });
    });
    chain.then(function () {
      uploading = false;
      upStart.disabled = false;
      upStart.textContent = T("Upload more", "继续上传");
    });
  });

  // ------------------------------------------------------------ details dialog

  var dtName = null;
  function kvRow(dl, k, v) {
    var div = document.createElement("div");
    var dt = document.createElement("dt"); dt.textContent = k;
    var dd = document.createElement("dd"); dd.textContent = v;
    div.appendChild(dt); div.appendChild(dd); dl.appendChild(div);
  }
  function toLocalInput(unixSecs) {
    var d = new Date(unixSecs * 1000);
    var p = function (n) { return String(n).padStart(2, "0"); };
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
      "T" + p(d.getHours()) + ":" + p(d.getMinutes());
  }

  document.addEventListener("click", function (ev) {
    var b = ev.target.closest(".act-details");
    if (!b) return;
    dtName = b.dataset.name;
    setErr("#dt-err", "");
    $("#dt-title").textContent = dtName.split("/").pop();
    var dl = $("#dt-kv"); dl.innerHTML = "";
    var metaBox = $("#dt-meta"); metaBox.innerHTML = "";
    $("#dt-slo-wrap").hidden = true;
    $("#dt-public-sec").hidden = true;
    openDlg("#dlg-details");
    api("GET", "/files/api/objmeta/" + encodeURIComponent(BUCKET) + "/" + encPath(dtName))
      .then(function (m) {
        kvRow(dl, T("Path", "路径"), BUCKET + "/" + dtName);
        kvRow(dl, T("Size", "大小"), fmtBytes(parseInt(m.bytes || "0", 10)) + (m.is_slo ? T(" (static large object)", "（分段大对象）") : ""));
        kvRow(dl, "ETag", m.etag || "-");
        kvRow(dl, T("Modified", "修改时间"), m.last_modified || "-");
        $("#dt-ctype").value = m.content_type || "";
        Object.keys(m.meta || {}).sort().forEach(function (k) { metaRow(metaBox, k, m.meta[k]); });
        window.__dtOrigMeta = m.meta || {};
        $("#dt-expire").value = m.delete_at ? toLocalInput(parseInt(m.delete_at, 10)) : "";
        $("#dt-slo-wrap").hidden = !m.is_slo;
        if (m.is_slo) $("#dt-slo-segments").checked = true;
      })
      .catch(function (e) { setErr("#dt-err", e.message); });
    // Public link if the bucket is public.
    api("GET", "/files/api/bucket/" + encodeURIComponent(BUCKET) + "/meta").then(function (bm) {
      if (bm.public) {
        api("GET", "/files/api/whoami").then(function (w) {
          $("#dt-public-sec").hidden = false;
          $("#dt-public-url").value = w.storage_url + "/" + encodeURIComponent(BUCKET) + "/" + encPath(dtName);
        });
      }
    }).catch(function () { /* quiet */ });
  });
  var dtClose = $("#dt-close");
  if (dtClose) dtClose.addEventListener("click", function () { closeDlg("#dlg-details"); });
  var dtExpClear = $("#dt-expire-clear");
  if (dtExpClear) dtExpClear.addEventListener("click", function () { $("#dt-expire").value = ""; });
  var dtSave = $("#dt-save");
  if (dtSave) dtSave.addEventListener("click", function () {
    var rows = readMetaRows($("#dt-meta"));
    var remove = Object.keys(window.__dtOrigMeta || {}).filter(function (k) { return !rows.seen[k.toLowerCase()]; });
    var exp = $("#dt-expire").value;
    var deleteAt = exp ? String(Math.floor(new Date(exp).getTime() / 1000)) : "";
    api("POST", "/files/api/objmeta/" + encodeURIComponent(BUCKET) + "/" + encPath(dtName), {
      set: rows.set,
      remove: remove,
      content_type: $("#dt-ctype").value.trim(),
      delete_at: deleteAt
    })
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#dt-err", e.message); });
  });
  var dtDelete = $("#dt-delete");
  if (dtDelete) dtDelete.addEventListener("click", function () {
    if (!confirm(T("Permanently delete \"" + dtName + "\"?", "永久删除“" + dtName + "”？"))) return;
    var withSegs = !$("#dt-slo-wrap").hidden && $("#dt-slo-segments").checked;
    api("DELETE", "/files/api/obj/" + encodeURIComponent(BUCKET) + "/" + encPath(dtName) +
      (withSegs ? "?with_segments=1" : ""))
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#dt-err", e.message); });
  });

  // ------------------------------------------------------------ share dialog

  var shName = null;
  var shExpiry = $("#sh-expiry");
  if (shExpiry) shExpiry.addEventListener("change", function () {
    $("#sh-custom-wrap").hidden = shExpiry.value !== "custom";
  });
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest(".act-share");
    if (!b) return;
    shName = b.dataset.name;
    setErr("#sh-err", "");
    $("#sh-title").textContent = T("Share: ", "分享：") + shName.split("/").pop();
    $("#sh-result-wrap").hidden = true;
    $("#sh-public-sec").hidden = true;
    openDlg("#dlg-share");
    api("GET", "/files/api/bucket/" + encodeURIComponent(BUCKET) + "/meta").then(function (bm) {
      if (bm.public) {
        api("GET", "/files/api/whoami").then(function (w) {
          $("#sh-public-sec").hidden = false;
          $("#sh-public-url").value = w.storage_url + "/" + encodeURIComponent(BUCKET) + "/" + encPath(shName);
        });
      }
    }).catch(function () { /* quiet */ });
  });
  var shGen = $("#sh-generate");
  if (shGen) shGen.addEventListener("click", function () {
    var v = shExpiry.value;
    var secs = v === "custom" ? parseInt($("#sh-custom").value, 10) : parseInt(v, 10);
    if (!secs || secs < 60) { setErr("#sh-err", T("Expiry must be at least 60 seconds.", "有效期至少 60 秒。")); return; }
    api("POST", "/files/api/tempurl", { bucket: BUCKET, path: shName, expiry_secs: secs })
      .then(function (r) {
        $("#sh-result-wrap").hidden = false;
        $("#sh-url").value = r.url;
        setErr("#sh-err", "");
      })
      .catch(function (e) { setErr("#sh-err", e.message); });
  });
  var shClose = $("#sh-close");
  if (shClose) shClose.addEventListener("click", function () { closeDlg("#dlg-share"); });

  // ------------------------------------------------------------ trash page

  document.addEventListener("click", function (ev) {
    var t;
    if ((t = ev.target.closest(".act-trash-restore"))) {
      var payload = t.dataset.path ? { path: t.dataset.path } : { prefix: t.dataset.prefix };
      t.disabled = true;
      api("POST", "/files/api/trash/restore", payload)
        .then(function () { location.reload(); })
        .catch(function (e) { t.disabled = false; alert(e.message); });
    } else if ((t = ev.target.closest(".act-trash-delete"))) {
      var what = t.dataset.path || t.dataset.prefix;
      if (!confirm(T("Permanently delete \"" + what + "\" from trash?", "从回收站永久删除“" + what + "”？"))) return;
      var payload2 = t.dataset.path ? { path: t.dataset.path } : { prefix: t.dataset.prefix };
      api("POST", "/files/api/trash/delete", payload2)
        .then(function () { location.reload(); })
        .catch(function (e) { alert(e.message); });
    }
  });
  var emptyTrash = $("#empty-trash-btn");
  if (emptyTrash) emptyTrash.addEventListener("click", function () {
    if (!confirm(T("Permanently delete everything in the trash?", "永久删除回收站中的全部内容？"))) return;
    api("POST", "/files/api/trash/empty", {})
      .then(function () { location.reload(); })
      .catch(function (e) { alert(e.message); });
  });

  // ------------------------------------------------------------ account page

  var aqSave = $("#aq-save");
  if (aqSave) aqSave.addEventListener("click", function () {
    api("POST", "/files/api/account", { quota_bytes: $("#aq-bytes").value.trim() })
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#aq-err", e.message); });
  });
  var tkSet = $("#tk-set");
  if (tkSet) tkSet.addEventListener("click", function () {
    api("POST", "/files/api/tempurl-key", { key: $("#tk-key").value.trim() })
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#tk-err", e.message); });
  });
  var tkExpSave = $("#tk-expiry-save");
  if (tkExpSave) tkExpSave.addEventListener("click", function () {
    var secs = parseInt($("#tk-expiry").value, 10);
    if (!secs || secs < 60) { setErr("#tk-err", T("Default expiry must be at least 60 seconds.", "默认有效期至少 60 秒。")); return; }
    api("POST", "/files/api/tempurl-key", { default_expiry_secs: secs })
      .then(function () { setErr("#tk-err", ""); tkExpSave.textContent = T("Saved", "已保存"); setTimeout(function () { tkExpSave.textContent = T("Save default", "保存默认值"); }, 1200); })
      .catch(function (e) { setErr("#tk-err", e.message); });
  });
  var amAdd = $("#am-add");
  if (amAdd) amAdd.addEventListener("click", function () { metaRow($("#am-meta")); });
  var amSave = $("#am-save");
  if (amSave) amSave.addEventListener("click", function () {
    // Read original keys from the server-rendered rows at load time.
    if (!window.__amOrig) window.__amOrig = {};
    var rows = readMetaRows($("#am-meta"));
    var remove = Object.keys(window.__amOrig).filter(function (k) { return !rows.seen[k.toLowerCase()]; });
    api("POST", "/files/api/account", { set: rows.set, remove: remove })
      .then(function () { location.reload(); })
      .catch(function (e) { setErr("#am-err", e.message); });
  });
  if (PAGE === "account") {
    window.__amOrig = {};
    $$("#am-meta .meta-row .mk").forEach(function (i) {
      if (i.value) window.__amOrig[i.value.toLowerCase()] = true;
    });
  }

  // Dialog "Add row" buttons.
  var bsMetaAdd = $("#bs-meta-add");
  if (bsMetaAdd) bsMetaAdd.addEventListener("click", function () { metaRow($("#bs-meta")); });
  var dtMetaAdd = $("#dt-meta-add");
  if (dtMetaAdd) dtMetaAdd.addEventListener("click", function () { metaRow($("#dt-meta")); });

  // ------------------------------------------------------------- Search
  if (PAGE === "search") {
    var sxResults = $("#sx-results"), sxStatus = $("#sx-status");
    function setStatus(t) { if (sxStatus) sxStatus.innerHTML = t; }
    function val(id) { var e = $(id); return e ? e.value.trim() : ""; }

    function renderResults(d) {
      sxResults.innerHTML = "";
      if (d.needs_index) {
        sxResults.innerHTML = '<div class="empty">' +
          T("No index yet — click Reindex to build one for this account.",
            "还没有索引 —— 点重建索引给这个账户建一个。") + '</div>';
        return;
      }
      var results = d.results || [];
      var head = document.createElement("p");
      head.className = "statline";
      head.textContent = T("Showing " + results.length + " of " + d.total + " match" + (d.total === 1 ? "" : "es")
        + (d.total > results.length ? " (refine to narrow)" : ""),
        "显示 " + d.total + " 条匹配中的 " + results.length + " 条"
        + (d.total > results.length ? "（缩小条件可以看得更准）" : ""));
      sxResults.appendChild(head);
      if (!results.length) {
        var none = document.createElement("div"); none.className = "empty"; none.textContent = T("No objects match.", "没有匹配的对象。");
        sxResults.appendChild(none); return;
      }
      var wrap = document.createElement("div"); wrap.className = "tbl-wrap";
      var tbl = document.createElement("table"); tbl.className = "tbl";
      tbl.innerHTML = "<thead><tr><th>" + T("Object", "对象") + "</th><th class='num'>" + T("Size", "大小") +
        "</th><th>" + T("Type", "类型") + "</th><th>" + T("Modified", "修改时间") +
        "</th><th>" + T("Metadata", "元数据") + "</th></tr></thead>";
      var tb = document.createElement("tbody");
      results.forEach(function (r) {
        var tr = document.createElement("tr");
        var oc = document.createElement("td");
        var cont = document.createElement("a");
        cont.className = "plain-link"; cont.href = "/files/b/" + encodeURIComponent(r.container);
        cont.textContent = r.container;
        var slash = document.createTextNode(" / ");
        var dl = document.createElement("a");
        dl.href = "/files/download/" + encodeURIComponent(r.container) + "/" + encPath(r.name);
        dl.textContent = r.name; dl.className = "cell-link";
        oc.appendChild(cont); oc.appendChild(slash); oc.appendChild(dl);
        var sz = document.createElement("td"); sz.className = "num"; sz.textContent = fmtBytes(r.bytes);
        var ct = document.createElement("td"); ct.className = "ctype"; ct.textContent = r.content_type || "—";
        var wh = document.createElement("td"); wh.className = "when"; wh.textContent = (r.last_modified || "").replace("T", " ").replace(/\.\d+$/, "");
        var mt = document.createElement("td"); mt.className = "ctype";
        var keys = Object.keys(r.meta || {});
        mt.textContent = keys.length ? keys.map(function (k) { return k + "=" + r.meta[k]; }).join(", ") : "—";
        tr.appendChild(oc); tr.appendChild(sz); tr.appendChild(ct); tr.appendChild(wh); tr.appendChild(mt);
        tb.appendChild(tr);
      });
      tbl.appendChild(tb); wrap.appendChild(tbl); sxResults.appendChild(wrap);
    }

    function runSearch() {
      var p = new URLSearchParams();
      p.set("q", val("#sx-q")); p.set("container", val("#sx-container"));
      p.set("ctype", val("#sx-ctype")); p.set("metakey", val("#sx-metakey"));
      p.set("metaval", val("#sx-metaval"));
      if (val("#sx-min")) p.set("min", val("#sx-min"));
      if (val("#sx-max")) p.set("max", val("#sx-max"));
      api("GET", "/files/api/search?" + p.toString())
        .then(renderResults)
        .catch(function (e) { sxResults.innerHTML = '<div class="err on">' + e.message + "</div>"; });
    }

    var sxReindex = $("#sx-reindex");
    if (sxReindex) sxReindex.addEventListener("click", function () {
      var deep = $("#sx-deep") && $("#sx-deep").checked;
      sxReindex.disabled = true; setStatus(T("Indexing…", "正在建立索引…"));
      api("POST", "/files/api/search/reindex?deep=" + (deep ? "1" : "0"))
        .then(function (d) {
          sxReindex.disabled = false;
          setStatus(T("Indexed " + d.count + " object" + (d.count === 1 ? "" : "s"), "已索引 " + d.count + " 个对象")
            + (d.deep ? T(" &middot; includes custom metadata", " · 含自定义元数据") : "")
            + (d.truncated ? T(" &middot; truncated", " · 已截断") : ""));
          runSearch();
        })
        .catch(function (e) { sxReindex.disabled = false; setStatus(T("Reindex failed: ", "重建索引失败：") + e.message); });
    });
    var sxRun = $("#sx-run");
    if (sxRun) sxRun.addEventListener("click", runSearch);
    ["#sx-q", "#sx-ctype", "#sx-metakey", "#sx-metaval"].forEach(function (id) {
      var e = $(id);
      if (e) e.addEventListener("keydown", function (ev) { if (ev.key === "Enter") runSearch(); });
    });
    // If an index already exists, show everything on load.
    if (sxStatus && sxStatus.dataset.indexed === "1") runSearch();
  }

  // ------------------------------------------------------------- Tenants & Users
  if (PAGE === "users") {
    var duAccount = $("#du-account"), duUser = $("#du-user"), duKey = $("#du-key");
    var duAdmin = $("#du-admin"), duReseller = $("#du-reseller"), duGroups = $("#du-groups");
    function openUser(mode, data) {
      setErr("#du-err", "");
      $("#du-busy").hidden = true;
      var edit = mode === "edit";
      $("#du-title").textContent = edit ? T("Edit user", "编辑用户") : T("Add user", "添加用户");
      duAccount.value = edit ? data.account : "";
      duUser.value = edit ? data.user : "";
      duAccount.readOnly = edit; duUser.readOnly = edit;
      duKey.value = "";
      duKey.placeholder = edit ? T("leave blank to keep current key", "留空表示保持当前密钥") : T("secret key", "用户密钥");
      $("#du-key-hint").textContent = edit
        ? T("Leave blank to keep the current key. No spaces.", "留空表示保持当前密钥。不能有空格。")
        : T("The user signs in with this key. No spaces.", "用户用这个密钥登录。不能有空格。");
      duAdmin.checked = edit ? data.admin : false;
      duReseller.checked = edit ? data.reseller : false;
      duGroups.value = edit ? data.groups : "";
      openDlg("#dlg-user");
    }
    var addUserBtn = $("#add-user-btn");
    if (addUserBtn) addUserBtn.addEventListener("click", function () { openUser("add"); });
    document.addEventListener("click", function (ev) {
      var e = ev.target.closest(".u-edit");
      if (e) {
        var tr = e.closest("tr");
        openUser("edit", {
          account: tr.getAttribute("data-account"), user: tr.getAttribute("data-user"),
          admin: tr.getAttribute("data-admin") === "true", reseller: tr.getAttribute("data-reseller") === "true",
          groups: tr.getAttribute("data-groups") || "",
        });
        return;
      }
      var d = ev.target.closest(".u-del");
      if (d) {
        var tr2 = d.closest("tr");
        var acc = tr2.getAttribute("data-account"), usr = tr2.getAttribute("data-user");
        if (!confirm(T("Delete user " + acc + ":" + usr + "? This restarts each proxy in turn.",
          "删除用户 " + acc + ":" + usr + "？这会逐台重启代理节点。"))) return;
        d.disabled = true;
        api("POST", "/files/api/users/delete", { account: acc, user: usr })
          .then(function () { location.reload(); })
          .catch(function (er) { d.disabled = false; alert(er.message); });
      }
    });
    var duSave = $("#du-save");
    if (duSave) duSave.addEventListener("click", function (ev) {
      ev.preventDefault();
      var body = {
        account: duAccount.value.trim(), user: duUser.value.trim(), key: duKey.value,
        admin: duAdmin.checked, reseller: duReseller.checked,
        groups: duGroups.value.trim() ? duGroups.value.trim().split(/\s+/) : [],
      };
      if (!body.account || !body.user) { setErr("#du-err", T("Tenant and user are required.", "租户和用户不能为空。")); return; }
      setErr("#du-err", "");
      duSave.disabled = true; $("#du-busy").hidden = false;
      api("POST", "/files/api/users", body)
        .then(function () { location.reload(); })
        .catch(function (er) { duSave.disabled = false; $("#du-busy").hidden = true; setErr("#du-err", er.message); });
    });
  }

  // ------------------------------------------------------------- Monitor
  // Native, white-labeled dashboards. Everything is drawn from neutral JSON
  // served by /monitor/api/*; the client never learns the backend.
  // ------------------------------------------------------------- charts
  // Canvas + HTML mounts with a shared floating tip. SVG is not used for charts.
  var SVGNS = "http://www.w3.org/2000/svg"; // icons only elsewhere

  function fmtNum(v) {
    if (v == null || isNaN(v)) return "–";
    var a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(1) + "G";
    if (a >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (a >= 1000) return (v / 1000).toFixed(1) + "k";
    if (v === Math.round(v)) return String(v);
    return v.toFixed(a < 10 ? 2 : 1);
  }
  function fmtDur(v) {
    if (v == null || isNaN(v)) return "–";
    if (v >= 1) return v.toFixed(2) + "s";
    if (v >= 0.001) return Math.round(v * 1000) + "ms";
    return Math.round(v * 1e6) + "µs";
  }
  function fmtVal(unit, v) {
    if (v == null || isNaN(v)) return "–";
    switch (unit) {
      case "reqs": case "pers": return fmtNum(v) + "/s";
      case "sec": return fmtDur(v);
      case "ratio": return (v * 100).toFixed(v < 0.1 ? 2 : 1) + "%";
      case "pct": return Math.round(v * 100) + "%";
      case "bytess": return fmtBytes(v) + "/s";
      default: return fmtNum(v);
    }
  }
  function pad2(n) { return (n < 10 ? "0" : "") + n; }
  function hhmm(t) { var d = new Date(t * 1000); return pad2(d.getHours()) + ":" + pad2(d.getMinutes()); }
  function hhmmss(t) { var d = new Date(t * 1000); return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds()); }
  function svg(name, attrs) {
    var e = document.createElementNS(SVGNS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  // Canvas cannot paint `light-dark(...)` or raw `var(--x)`. Keep a mirror of
  // the CSS token table and pick the arm from data-theme / prefers-color-scheme.
  // A live probe is a last resort only — probes often resolve the light arm.
  var THEME_TOKENS = {
    light: {
      ink: "#212723", mut: "#5f6a63", faint: "#8b958d",
      line: "#dfe5e0", "line-soft": "#e9eeea", "line-strong": "#d0d8d2",
      "accent-ink": "#1d7a50",
      chart: ["#3a9d6e", "#3f78a8", "#b0813a", "#3f8f86", "#b3564a", "#6b7280"]
    },
    dark: {
      ink: "#e2e7e3", mut: "#9ba69f", faint: "#848f88",
      line: "#2f372f", "line-soft": "#262d27", "line-strong": "#3d463e",
      "accent-ink": "#5cd6a1",
      chart: ["#5cbf92", "#74a8cf", "#cba566", "#63b5aa", "#d5867c", "#98a29b"]
    }
  };
  function themeName() {
    var t = document.documentElement.getAttribute("data-theme");
    if (t === "dark" || t === "light") return t;
    try {
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) return "dark";
    } catch (e) { /* ignore */ }
    return "light";
  }
  var _colorCache = {};
  function tokenColor(name, fallback) {
    var tok = THEME_TOKENS[themeName()];
    var bare = String(name || "").replace(/^--/, "");
    if (bare.indexOf("chart-") === 0) {
      var idx = parseInt(bare.slice(6), 10) - 1;
      if (idx >= 0 && idx < tok.chart.length) return tok.chart[idx];
    }
    if (tok[bare]) return tok[bare];
    return fallback;
  }
  function seriesColor(i) {
    var n = (i % 6) + 1;
    var key = "ser:" + themeName() + ":" + n;
    if (_colorCache[key]) return _colorCache[key];
    _colorCache[key] = tokenColor("--chart-" + n, THEME_TOKENS.dark.chart[n - 1]);
    return _colorCache[key];
  }
  function cssVar(name, fallback) {
    var key = "var:" + themeName() + ":" + name;
    if (_colorCache[key]) return _colorCache[key];
    var c = tokenColor(name, fallback);
    _colorCache[key] = c || fallback;
    return _colorCache[key];
  }
  try {
    new MutationObserver(function () { _colorCache = {}; }).observe(document.documentElement, {
      attributes: true, attributeFilter: ["data-theme", "class", "style"]
    });
  } catch (e) { /* older engines */ }
  var CANVAS_FONT = "11px ui-sans-serif, system-ui, -apple-system, sans-serif";
  function roundRect(ctx, x, y, w, h, r) {
    if (w < 1) w = 1;
    if (h < 1) { ctx.fillRect(x, y, w, Math.max(h, 1)); return; }
    r = Math.min(r, w / 2, h / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
    ctx.fill();
  }

  var tipEl = null;
  // Modal <dialog> paints in the top layer; a tip on <body> sits underneath and
  // looks "missing". Always host the tip inside the open dialog when present.
  function tipHost() {
    var open = document.querySelector("dialog[open]");
    return open || document.body;
  }
  function tipEnsure() {
    if (!tipEl) {
      tipEl = document.createElement("div");
      tipEl.className = "ix-tip";
      tipEl.hidden = true;
    }
    var host = tipHost();
    if (tipEl.parentNode !== host) host.appendChild(tipEl);
    return tipEl;
  }
  function tipShow(clientX, clientY, html) {
    var el = tipEnsure();
    el.innerHTML = html;
    el.hidden = false;
    var pad = 12, tw = el.offsetWidth, th = el.offsetHeight;
    var x = clientX + pad, y = clientY + pad;
    if (x + tw > window.innerWidth - 8) x = clientX - tw - pad;
    if (y + th > window.innerHeight - 8) y = clientY - th - pad;
    el.style.left = Math.max(4, x) + "px";
    el.style.top = Math.max(4, y) + "px";
  }
  function tipHide() { if (tipEl) tipEl.hidden = true; }
  document.addEventListener("close", function (ev) {
    if (ev.target && ev.target.tagName === "DIALOG") tipHide();
  }, true);
  window.ixTipShow = tipShow;
  window.ixTipHide = tipHide;
  function bindTip(el, textFn) {
    el.addEventListener("mousemove", function (ev) {
      var t = typeof textFn === "function" ? textFn(ev) : textFn;
      if (t) tipShow(ev.clientX, ev.clientY, t);
      else tipHide();
    });
    el.addEventListener("mouseleave", tipHide);
  }

  function lineChart(body, resp, unit, opts) {
    opts = opts || {};
    var series = (resp.series || []).filter(function (s) { return s.points && s.points.length; });
    var legend = [];
    if (!series.length) { body.innerHTML = '<div class="mon-empty">' + T("No data in range", "该区间内没有数据") + '</div>'; return legend; }
    var W = Math.max(body.clientWidth || 600, 260), H = opts.h || 172;
    var dpr = window.devicePixelRatio || 1;
    var padR = 12, padT = 10, padB = 22;
    var minT = Infinity, maxT = -Infinity, minV = Infinity, maxV = -Infinity;
    series.forEach(function (s) {
      s.points.forEach(function (p) {
        if (p[0] < minT) minT = p[0]; if (p[0] > maxT) maxT = p[0];
        if (p[1] != null) { if (p[1] < minV) minV = p[1]; if (p[1] > maxV) maxV = p[1]; }
      });
    });
    if (!isFinite(minT)) { body.innerHTML = '<div class="mon-empty">' + T("No data in range", "该区间内没有数据") + '</div>'; return legend; }
    if (unit === "ratio" || unit === "pct") minV = 0;
    if (minV === Infinity) { minV = 0; maxV = 1; }
    if (maxV === minV) maxV = minV + (minV === 0 ? 1 : Math.abs(minV) * 0.2);
    maxV += (maxV - minV) * 0.08;
    var tickLabels = [];
    for (var ti = 0; ti <= 4; ti++) tickLabels.push(fmtVal(unit, minV + (maxV - minV) * (ti / 4)));
    var widest = tickLabels.reduce(function (m, s) { return Math.max(m, s.length); }, 0);
    var padL = Math.min(Math.max(34, Math.ceil(widest * 5.9) + 12), Math.round(W * 0.34));
    var x = function (t) { return padL + (maxT === minT ? 0 : (t - minT) / (maxT - minT)) * (W - padL - padR); };
    var y = function (v) { return padT + (1 - (v - minV) / (maxV - minV)) * (H - padT - padB); };

    var wrap = document.createElement("div");
    wrap.className = "ix-canvas-wrap";
    var canvas = document.createElement("canvas");
    canvas.className = "mon-canvas";
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = W + "px";
    canvas.style.height = H + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    // Match former SVG theme: faint axis labels, soft grid — never raw CSS vars.
    var axisC = cssVar("--faint", "#848f88");
    var gridC = cssVar("--line-soft", "#262d27");
    var i, gy, yv;
    ctx.strokeStyle = gridC; ctx.lineWidth = 1;
    ctx.font = CANVAS_FONT;
    ctx.fillStyle = axisC; ctx.textAlign = "end"; ctx.textBaseline = "middle";
    for (i = 0; i <= 4; i++) {
      yv = minV + (maxV - minV) * (i / 4); gy = y(yv);
      ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(W - padR, gy); ctx.stroke();
      ctx.fillStyle = axisC;
      ctx.fillText(tickLabels[i], padL - 6, gy);
    }
    ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
    for (i = 0; i <= 3; i++) {
      var tt = minT + (maxT - minT) * (i / 3), gx = x(tt);
      ctx.textAlign = i === 0 ? "start" : (i === 3 ? "end" : "center");
      ctx.fillStyle = axisC;
      ctx.fillText(hhmm(tt), gx, H - 6);
    }
    series.forEach(function (ser, si) {
      var col = seriesColor(si), last = null;
      ctx.strokeStyle = col; ctx.lineWidth = 1.6; ctx.lineJoin = "round"; ctx.lineCap = "round";
      ctx.beginPath();
      var pen = false;
      ser.points.forEach(function (p) {
        if (p[1] == null) { pen = false; return; }
        var px = x(p[0]), py = y(p[1]);
        if (!pen) { ctx.moveTo(px, py); pen = true; }
        else ctx.lineTo(px, py);
        last = p[1];
      });
      ctx.stroke();
      legend.push({ name: ser.name, cls: "mon-s" + ((si % 6) + 1), last: last, unit: unit, key: ser.key || null, color: col });
    });

    var overlay = document.createElement("canvas");
    overlay.className = "mon-canvas-overlay";
    overlay.width = canvas.width; overlay.height = canvas.height;
    overlay.style.width = W + "px"; overlay.style.height = H + "px";
    var octx = overlay.getContext("2d");
    octx.scale(dpr, dpr);

    function nearest(mx) {
      var bestT = null, hits = [];
      series.forEach(function (ser, si) {
        var bp = null, bd = Infinity;
        ser.points.forEach(function (p) {
          if (p[1] == null) return;
          var d = Math.abs(x(p[0]) - mx);
          if (d < bd) { bd = d; bp = p; }
        });
        if (bp && bd < 28) hits.push({ ser: ser, si: si, p: bp, d: bd });
      });
      if (!hits.length) return null;
      hits.sort(function (a, b) { return a.d - b.d; });
      bestT = hits[0].p[0];
      return hits.filter(function (h) { return Math.abs(h.p[0] - bestT) < 1e-9 || Math.abs(x(h.p[0]) - x(bestT)) < 2; });
    }

    overlay.addEventListener("mousemove", function (ev) {
      var rect = overlay.getBoundingClientRect();
      var mx = (ev.clientX - rect.left) * (W / rect.width);
      var hits = nearest(mx);
      octx.clearRect(0, 0, W, H);
      if (!hits) { tipHide(); return; }
      var tx = x(hits[0].p[0]);
      octx.strokeStyle = cssVar("--ink", "#e2e7e3"); octx.globalAlpha = 0.35; octx.lineWidth = 1;
      octx.beginPath(); octx.moveTo(tx, padT); octx.lineTo(tx, H - padB); octx.stroke();
      octx.globalAlpha = 1;
      var lines = ["<b>" + hhmmss(hits[0].p[0]) + "</b>"];
      hits.forEach(function (h) {
        octx.fillStyle = seriesColor(h.si);
        octx.beginPath(); octx.arc(x(h.p[0]), y(h.p[1]), 3.5, 0, Math.PI * 2); octx.fill();
        lines.push('<span style="color:' + seriesColor(h.si) + '">●</span> ' +
          h.ser.name + ": <b>" + fmtVal(unit, h.p[1]) + "</b>");
      });
      tipShow(ev.clientX, ev.clientY, lines.join("<br>"));
    });
    overlay.addEventListener("mouseleave", function () { octx.clearRect(0, 0, W, H); tipHide(); });

    wrap.appendChild(canvas); wrap.appendChild(overlay);
    body.innerHTML = ""; body.appendChild(wrap);
    return legend;
  }

  function barsChart(host, data) {
    host.innerHTML = "";
    if (data.moved != null && data.total != null) {
      var box = document.createElement("div");
      box.className = "ix-budget";
      var track = document.createElement("div");
      track.className = "ix-budget-track";
      var fill = document.createElement("div");
      fill.className = "ix-budget-moved";
      fill.style.width = Math.max(2, 100 * data.moved / Math.max(data.total, 1)) + "%";
      track.appendChild(fill);
      if (data.floor != null) {
        var floor = document.createElement("div");
        floor.className = "ix-budget-floor";
        floor.style.left = Math.min(100, 100 * data.floor / Math.max(data.total, 1)) + "%";
        floor.title = data.floorLabel || "";
        track.appendChild(floor);
      }
      box.appendChild(track);
      var meta = document.createElement("div");
      meta.className = "ix-budget-meta";
      meta.innerHTML = "<span>" + (data.movedLabel || "") + "</span><span>" + (data.totalLabel || "") + "</span>";
      box.appendChild(meta);
      host.appendChild(box);
      return;
    }
    if (data.groups) {
      var wrap = document.createElement("div");
      wrap.className = "rs-devchart";
      data.groups.forEach(function (g) {
        var grp = document.createElement("div");
        grp.className = "rs-devgroup";
        var head = document.createElement("div");
        head.className = "rs-devnode";
        head.textContent = g.node + " · " + (g.zone || "");
        grp.appendChild(head);
        var maxP = 1;
        (g.devices || []).forEach(function (d) {
          maxP = Math.max(maxP, d.before || 0, d.after || 0, d.ideal || 0);
        });
        (g.devices || []).forEach(function (d) {
          var row = document.createElement("div");
          row.className = "rs-devrow";
          var lab = document.createElement("span"); lab.className = "rs-devlab"; lab.textContent = d.device;
          var bars = document.createElement("div"); bars.className = "rs-devbars";
          var b1 = document.createElement("div"); b1.className = "rs-bar before";
          b1.style.width = Math.max(2, 100 * (d.before || 0) / maxP) + "%";
          var b2 = document.createElement("div"); b2.className = "rs-bar after";
          b2.style.width = Math.max(2, 100 * (d.after || 0) / maxP) + "%";
          bars.appendChild(b1); bars.appendChild(b2);
          var tail = document.createElement("span"); tail.className = "rs-devtail";
          var delta = (d.delta || 0);
          tail.textContent = (delta > 0 ? "+" : "") + delta + " · " + (d.balance || "") + " · " + (d.state || "");
          row.appendChild(lab); row.appendChild(bars); row.appendChild(tail);
          bindTip(row, d.tip || d.device);
          grp.appendChild(row);
        });
        wrap.appendChild(grp);
      });
      host.appendChild(wrap);
      return;
    }
    var wrap = document.createElement("div");
    wrap.className = "ix-canvas-wrap";
    var items = data.items || [];
    var W = Math.max(host.clientWidth || 600, 280);
    var dpr = window.devicePixelRatio || 1;
    var n = Math.max(items.length, 1);
    var max = 0;
    items.forEach(function (it) { if (it.value > max) max = it.value; });
    if (max <= 0) max = 1;
    var axisC = cssVar("--faint", "#848f88");
    var ink = cssVar("--ink", "#e2e7e3");
    var mut = cssVar("--mut", "#9ba69f");
    var gridC = cssVar("--line-soft", "#262d27");
    // Long category labels need angle + taller bottom; short ones stay flat.
    var longest = 0;
    items.forEach(function (it) {
      var L = String(it.label || "").length;
      if (L > longest) longest = L;
    });
    var angled = n >= 6 || longest > 8 || (n * 72 > W);
    var padL = 48, padR = 14, padT = 22, padB = angled ? 64 : 36;
    var H = data.h || (angled ? 260 : 220);
    var track = W - padL - padR;
    var gap = Math.max(4, Math.min(14, track / (n * 6)));
    var bw = Math.max(8, (track - gap * (n - 1)) / n);
    var showVals = bw >= 36 && n <= 10;
    var canvas = document.createElement("canvas");
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.font = CANVAS_FONT;
    ctx.strokeStyle = gridC; ctx.lineWidth = 1;
    for (var gi = 0; gi <= 3; gi++) {
      var gv = max * (gi / 3), gy = padT + (1 - gi / 3) * (H - padT - padB);
      ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(W - padR, gy); ctx.stroke();
      ctx.fillStyle = axisC;
      ctx.textAlign = "end"; ctx.textBaseline = "middle";
      ctx.fillText(fmtNum(gv), padL - 8, gy);
    }
    var hit = [];
    items.forEach(function (it, i) {
      var x0 = padL + i * (bw + gap);
      var bh = (it.value / max) * (H - padT - padB);
      var y0 = H - padB - bh;
      var col = seriesColor(it.colorIndex != null ? it.colorIndex : i);
      ctx.globalAlpha = it.dim ? 0.4 : 0.92;
      ctx.fillStyle = col;
      roundRect(ctx, x0, y0, bw, Math.max(bh, 2), Math.min(4, bw / 2));
      ctx.globalAlpha = 1;
      var lab = String(it.label || "");
      var maxChars = angled ? 14 : Math.max(4, Math.floor(bw / 7));
      if (lab.length > maxChars) lab = lab.slice(0, maxChars - 1) + "…";
      var cx = x0 + bw / 2;
      ctx.fillStyle = mut;
      if (angled) {
        ctx.save();
        ctx.translate(cx, H - padB + 10);
        ctx.rotate(-Math.PI / 4);
        ctx.textAlign = "right"; ctx.textBaseline = "middle";
        ctx.fillText(lab, 0, 0);
        ctx.restore();
      } else {
        ctx.textAlign = "center"; ctx.textBaseline = "top";
        ctx.fillText(lab, cx, H - padB + 8);
      }
      if (showVals && it.display) {
        ctx.textAlign = "center"; ctx.textBaseline = "bottom";
        ctx.fillStyle = ink;
        ctx.fillText(it.display, cx, y0 - 4);
      }
      hit.push({
        x0: x0, x1: x0 + bw, y0: Math.min(y0, H - padB) - 12, y1: H - padB + (angled ? 40 : 16),
        tip: it.tip || ((it.label || "") + ": " + (it.display || it.value))
      });
    });
    wrap.appendChild(canvas);
    host.appendChild(wrap);
    canvas.addEventListener("mousemove", function (ev) {
      var rect = canvas.getBoundingClientRect();
      var mx = (ev.clientX - rect.left) * (W / rect.width);
      var my = (ev.clientY - rect.top) * (H / rect.height);
      for (var i = 0; i < hit.length; i++) {
        var h = hit[i];
        if (mx >= h.x0 && mx <= h.x1 && my >= h.y0 && my <= h.y1) {
          tipShow(ev.clientX, ev.clientY, h.tip); return;
        }
      }
      tipHide();
    });
    canvas.addEventListener("mouseleave", tipHide);
  }

    function hbarChart(host, data) {
    host.innerHTML = "";
    var box = document.createElement("div");
    box.className = "ix-hbar";
    var items = data.items || [];
    var max = data.limit || 0;
    items.forEach(function (it) { if (it.value > max) max = it.value; if (it.ideal > max) max = it.ideal; });
    max = max * 1.08 || 1;
    items.forEach(function (it, i) {
      var row = document.createElement("div");
      row.className = "ix-hbar-row" + (it.dim ? " pe-dim" : "") + (it.tone ? " " + it.tone : "");
      var lab = document.createElement("span"); lab.className = "ix-hbar-l"; lab.textContent = it.label;
      lab.title = it.label || "";
      var track = document.createElement("div"); track.className = "ix-hbar-track";
      if (data.limit != null) {
        var lim = document.createElement("div");
        lim.className = "ix-hbar-limit";
        lim.style.left = (100 * data.limit / max) + "%";
        track.appendChild(lim);
      }
      if (it.ideal != null) {
        var ideal = document.createElement("div");
        ideal.className = "ix-hbar-ideal";
        ideal.style.left = Math.min(100, 100 * it.ideal / max) + "%";
        track.appendChild(ideal);
      }
      var bar = document.createElement("div");
      bar.className = "ix-hbar-fill" + (it.ok === false ? " warn" : "");
      // Prefer CSS series class so light-dark() resolves in the stylesheet;
      // inline colour is a canvas-safe hex from the theme token table.
      var ci = it.colorIndex != null ? it.colorIndex : i;
      bar.classList.add("mon-s" + ((ci % 6) + 1));
      bar.style.background = seriesColor(ci);
      bar.style.width = Math.max(2, 100 * it.value / max) + "%";
      track.appendChild(bar);
      var val = document.createElement("span"); val.className = "ix-hbar-v";
      val.textContent = it.display || fmtNum(it.value);
      row.appendChild(lab); row.appendChild(track); row.appendChild(val);
      var tip = it.tip || (it.label + ": " + (it.display || it.value));
      if (data.limitLabel && data.limit != null) tip += " · " + data.limitLabel;
      bindTip(row, tip);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function scatterChart(host, data) {
    // { points:[{label,x,y,r,state,pick,tip}], targetY?, xLabel?, yLabel? }
    host.innerHTML = "";
    var pts = data.points || [];
    if (!pts.length) return;
    var W = Math.max(host.clientWidth || 640, 300), H = data.h || 280;
    var dpr = window.devicePixelRatio || 1;
    var padL = 48, padR = 24, padT = 20, padB = 36;
    var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    pts.forEach(function (p) {
      if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
    });
    if (data.targetY != null) { if (data.targetY < minY) minY = data.targetY; if (data.targetY > maxY) maxY = data.targetY; }
    if (maxX === minX) maxX = minX + 1;
    if (maxY === minY) maxY = minY + 1;
    minX -= (maxX - minX) * 0.08; maxX += (maxX - minX) * 0.08;
    minY -= (maxY - minY) * 0.1; maxY += (maxY - minY) * 0.1;
    var X = function (v) { return padL + (v - minX) / (maxX - minX) * (W - padL - padR); };
    var Y = function (v) { return padT + (1 - (v - minY) / (maxY - minY)) * (H - padT - padB); };
    var wrap = document.createElement("div"); wrap.className = "ix-canvas-wrap";
    var canvas = document.createElement("canvas");
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    var axisC = cssVar("--faint", "#848f88");
    var mut = cssVar("--mut", "#9ba69f");
    var ink = cssVar("--ink", "#e2e7e3");
    var accent = cssVar("--accent-ink", "#5cd6a1");
    ctx.strokeStyle = cssVar("--line-soft", "#262d27"); ctx.fillStyle = axisC; ctx.font = CANVAS_FONT;
    for (var i = 0; i <= 3; i++) {
      var yy = minY + (maxY - minY) * (i / 3), gy = Y(yy);
      ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(W - padR, gy); ctx.stroke();
      ctx.fillStyle = axisC;
      ctx.textAlign = "end"; ctx.textBaseline = "middle"; ctx.fillText(fmtNum(yy), padL - 6, gy);
      var xx = minX + (maxX - minX) * (i / 3), gx = X(xx);
      ctx.textAlign = i === 0 ? "start" : (i === 3 ? "end" : "center");
      ctx.textBaseline = "alphabetic"; ctx.fillText(fmtNum(xx), gx, H - 10);
    }
    if (data.targetY != null) {
      var ty = Y(data.targetY);
      ctx.setLineDash([4, 3]); ctx.strokeStyle = accent;
      ctx.beginPath(); ctx.moveTo(padL, ty); ctx.lineTo(W - padR, ty); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = accent;
      ctx.textAlign = "start"; ctx.fillText(data.targetLabel || ("target " + fmtNum(data.targetY)), padL + 4, ty - 6);
    }
    var maxR = 0;
    pts.forEach(function (p) { if ((p.r || 0) > maxR) maxR = p.r; });
    var hit = [];
    pts.forEach(function (p, i) {
      var cx = X(p.x), cy = Y(p.y);
      var r = maxR > 0 ? 5 + 16 * Math.sqrt((p.r || 0) / maxR) : 8;
      var col = p.state === "ok" ? seriesColor(0) : (p.state === "miss" ? seriesColor(2) : mut);
      if (p.pick) {
        ctx.strokeStyle = accent; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(cx, cy, r + 4, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.globalAlpha = p.state === "out" ? 0.35 : 0.7;
      ctx.fillStyle = col; ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1;
      ctx.fillStyle = ink;
      ctx.font = (p.pick ? "600 " : "") + CANVAS_FONT;
      ctx.textAlign = cx > W - padR - 40 ? "end" : "start";
      ctx.fillText(p.label, cx + (cx > W - padR - 40 ? -r - 5 : r + 5), cy + 3);
      hit.push({ cx: cx, cy: cy, r: r + 6, tip: p.tip || p.label });
    });
    wrap.appendChild(canvas); host.appendChild(wrap);
    canvas.addEventListener("mousemove", function (ev) {
      var rect = canvas.getBoundingClientRect();
      var mx = (ev.clientX - rect.left) * (W / rect.width);
      var my = (ev.clientY - rect.top) * (H / rect.height);
      for (var i = 0; i < hit.length; i++) {
        var h = hit[i], dx = mx - h.cx, dy = my - h.cy;
        if (dx * dx + dy * dy <= h.r * h.r) { tipShow(ev.clientX, ev.clientY, h.tip); return; }
      }
      tipHide();
    });
    canvas.addEventListener("mouseleave", tipHide);
  }

  function flowChart(host, data) {
    // Sankey-style ribbons: sources left → destinations right. Width = slots.
    // Falls back to ranked rows only when endpoint lists are missing.
    host.innerHTML = "";
    var box = document.createElement("div");
    box.className = "ix-flow-wrap";
    var sources = data.sources || [];
    var dests = data.dests || [];
    var ribbons = data.ribbons || [];
    if (!ribbons.length) {
      host.appendChild(box);
      return;
    }

    if (sources.length && dests.length) {
      var total = 0;
      sources.forEach(function (s) { total += s.sum || 0; });
      if (!total) ribbons.forEach(function (r) { total += r.slots || 0; });
      var W = Math.max(host.clientWidth || 720, 560);
      var labW = Math.min(200, Math.max(140, Math.floor(W * 0.22)));
      var colW = 10;
      var rowGap = 8;
      var innerH = Math.max(sources.length, dests.length) * 34 + 20;
      var H = innerH + 16;
      var x1 = labW, x2 = W - labW;
      var sy = {}, dy = {};
      function pack(list, yMap) {
        var scale = (innerH - rowGap * Math.max(list.length - 1, 0)) / Math.max(total, 1);
        var y = 10;
        list.forEach(function (e) {
          var h = Math.max((e.sum || 0) * scale, 4);
          yMap[e.id] = { y: y, h: h, off: 0, sum: e.sum || 0, label: e.label || String(e.id) };
          y += h + rowGap;
        });
      }
      pack(sources, sy);
      pack(dests, dy);

      var s = svg("svg", {
        viewBox: "0 0 " + W + " " + H,
        width: "100%",
        class: "rs-flow",
        "aria-label": data.title || "flow"
      });
      function endpoint(list, yMap, isSrc) {
        list.forEach(function (e) {
          var m = yMap[e.id];
          if (!m) return;
          s.appendChild(svg("rect", {
            x: isSrc ? x1 - colW : x2, y: m.y, width: colW, height: m.h, rx: 2,
            class: isSrc ? "rs-fl-src" : "rs-fl-dst"
          }));
          var lab = svg("text", {
            x: isSrc ? x1 - colW - 8 : x2 + colW + 8,
            y: m.y + m.h / 2,
            "text-anchor": isSrc ? "end" : "start",
            "dominant-baseline": "central",
            class: "rs-fl-lab"
          });
          lab.textContent = m.label;
          s.appendChild(lab);
        });
      }
      endpoint(sources, sy, true);
      endpoint(dests, dy, false);

      function sliceH(slots, sum, h) {
        return Math.max(h * (slots || 0) / Math.max(sum, 1), 2);
      }
      ribbons.forEach(function (r) {
        var sm = sy[r.from], dm = dy[r.to];
        if (!sm || !dm) return;
        var sh = sliceH(r.slots, sm.sum, sm.h);
        var dh = sliceH(r.slots, dm.sum, dm.h);
        var ys = sm.y + sm.off + sh / 2;
        var yd = dm.y + dm.off + dh / 2;
        sm.off += sh; dm.off += dh;
        var mid = (x1 + x2) / 2;
        var path = svg("path", {
          d: "M" + x1 + " " + ys + " C" + mid + " " + ys + " " + mid + " " + yd + " " + x2 + " " + yd,
          class: "rs-fl-rib",
          "stroke-width": Math.max((sh + dh) / 2, 1.6),
          fill: "none"
        });
        var tip = r.tip || (sm.label + " → " + dm.label + " · " + (r.bytes || r.slots || ""));
        path.style.cursor = "crosshair";
        path.addEventListener("mousemove", function (ev) {
          tipShow(ev.clientX, ev.clientY, tip);
        });
        path.addEventListener("mouseleave", tipHide);
        s.appendChild(path);
      });
      box.appendChild(s);
    } else {
      // Ranked row fallback when only ribbon pairs are present.
      var nameMap = {};
      sources.forEach(function (s) { nameMap[s.id] = s.label; });
      dests.forEach(function (d) { nameMap[d.id] = d.label; });
      var maxSlots = 1;
      ribbons.forEach(function (r) { if (r.slots > maxSlots) maxSlots = r.slots; });
      var list = document.createElement("div");
      list.className = "ix-flow";
      ribbons.forEach(function (r, i) {
        var row = document.createElement("div");
        row.className = "ix-flow-row";
        var fromLabel = nameMap[r.from] || ("dev " + r.from);
        var toLabel = nameMap[r.to] || ("dev " + r.to);
        var a = document.createElement("span"); a.className = "ix-flow-a"; a.textContent = fromLabel;
        var mid = document.createElement("div"); mid.className = "ix-flow-mid";
        var band = document.createElement("div");
        band.className = "ix-flow-band";
        band.style.height = Math.max(4, Math.min(28, (r.slots || 1) / maxSlots * 22)) + "px";
        band.style.background = seriesColor(i);
        mid.appendChild(band);
        var b = document.createElement("span"); b.className = "ix-flow-b"; b.textContent = toLabel;
        var meta = document.createElement("span"); meta.className = "ix-flow-m";
        meta.textContent = (r.bytes || r.slots || "") + "";
        row.appendChild(a); row.appendChild(mid); row.appendChild(b); row.appendChild(meta);
        bindTip(row, r.tip || (fromLabel + " → " + toLabel));
        list.appendChild(row);
      });
      box.appendChild(list);
    }

    if (data.hint || data.note) {
      var n = document.createElement("p");
      n.className = "lab-b";
      n.textContent = data.hint || data.note;
      box.appendChild(n);
    }
    host.appendChild(box);
  }

  function gridChart(host, data) {
    // { cols, cells:[{cls,tip,label?}], caption? }
    host.innerHTML = "";
    var g = document.createElement("div");
    g.className = "ix-grid";
    g.style.gridTemplateColumns = "repeat(" + (data.cols || 16) + ", minmax(0, 1fr))";
    (data.cells || []).forEach(function (c) {
      var cell = document.createElement("button");
      cell.type = "button";
      cell.className = "ix-grid-c " + (c.cls || "");
      if (c.label) cell.textContent = c.label;
      bindTip(cell, c.tip || c.label || "");
      if (c.href) cell.addEventListener("click", function () { location.href = c.href; });
      g.appendChild(cell);
    });
    host.appendChild(g);
    if (data.legend && data.legend.length) {
      var leg = document.createElement("div"); leg.className = "ix-grid-leg";
      data.legend.forEach(function (item) {
        var i = document.createElement("span"); i.className = "ix-grid-leg-i";
        var sw = document.createElement("i"); sw.className = item.cls || "";
        i.appendChild(sw);
        i.appendChild(document.createTextNode(item.label || ""));
        leg.appendChild(i);
      });
      host.appendChild(leg);
    }
    if (data.caption) {
      var cap = document.createElement("p"); cap.className = "lab-b"; cap.textContent = data.caption;
      host.appendChild(cap);
    }
  }

  function timelineChart(host, data) {
    if (data.variant === "chaos") {
      chaosTimelineChart(host, data);
      return;
    }
    if (data.variant === "pass") {
      passTimelineChart(host, data);
      return;
    }
    host.innerHTML = "";
    var lanes = data.lanes || [], events = data.events || [];
    if (!lanes.length) return;
    var bands = data.bands || data.offline || [];
    var minT = Infinity, maxT = -Infinity;
    events.forEach(function (e) { if (e.t < minT) minT = e.t; if (e.t > maxT) maxT = e.t; });
    (bands || []).forEach(function (b) {
      if (b.from < minT) minT = b.from; if (b.to > maxT) maxT = b.to;
    });
    if (!isFinite(minT)) return;
    if (maxT - minT < 120) { var mid = (maxT + minT) / 2; minT = mid - 60; maxT = mid + 60; }
    var span = maxT - minT; minT -= span * 0.04; maxT += span * 0.04; span = maxT - minT;
    var box = document.createElement("div"); box.className = "ix-tl";
    var axis = document.createElement("div"); axis.className = "ix-tl-axis";
    for (var ti = 0; ti <= 3; ti++) {
      var t = minT + span * (ti / 3);
      var tick = document.createElement("span");
      tick.style.left = (100 * (t - minT) / span) + "%";
      tick.textContent = hhmm(t);
      axis.appendChild(tick);
    }
    box.appendChild(axis);
    lanes.forEach(function (lane) {
      var row = document.createElement("div");
      row.className = "ix-tl-row" + (lane.role === "client" ? " client" : "");
      var lab = document.createElement("span"); lab.className = "ix-tl-l"; lab.textContent = lane.label;
      var track = document.createElement("div"); track.className = "ix-tl-track";
      (bands || []).forEach(function (b) {
        if (b.node !== lane.id && b.lane !== lane.id) return;
        var band = document.createElement("div");
        band.className = "ix-tl-band";
        band.style.left = (100 * (b.from - minT) / span) + "%";
        band.style.width = Math.max(0.3, 100 * (b.to - b.from) / span) + "%";
        bindTip(band, b.tip || lane.label);
        track.appendChild(band);
      });
      if (data.delete_ts != null) {
        var rule = document.createElement("div");
        rule.className = "ix-tl-rule";
        rule.style.left = (100 * (data.delete_ts - minT) / span) + "%";
        track.appendChild(rule);
      }
      events.forEach(function (e) {
        if (e.lane !== lane.id) return;
        var mark = document.createElement("button");
        mark.type = "button";
        mark.className = "ix-tl-ev " + (e.kind || "meta");
        mark.style.left = (100 * (e.t - minT) / span) + "%";
        bindTip(mark, e.tip || (hhmmss(e.t) + " · " + (e.label || "")));
        track.appendChild(mark);
      });
      row.appendChild(lab); row.appendChild(track);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function chaosTimelineChart(host, data) {
    host.innerHTML = "";
    var box = document.createElement("div");
    box.className = "ix-chaos-tl";
    var t0 = data.t0 || 0, t1 = data.t1 || 60, span = Math.max(t1 - t0, 1);
    var xPct = function (off) { return Math.max(0, Math.min(100, 100 * (off - t0) / span)); };
    if (data.samples && data.samples.length) {
      var copies = document.createElement("div");
      copies.className = "ix-chaos-copies";
      var maxC = data.wanted || 1;
      data.samples.forEach(function (s) { if (s.copies > maxC) maxC = s.copies; });
      data.samples.forEach(function (s, i) {
        var bar = document.createElement("div");
        bar.className = "ix-chaos-copy-bar";
        bar.style.left = xPct(s.off) + "%";
        bar.style.height = Math.max(8, 100 * s.copies / maxC) + "%";
        bindTip(bar, s.copies + " copies @ " + s.off + "s");
        copies.appendChild(bar);
      });
      box.appendChild(copies);
    }
    (data.lanes || []).forEach(function (lane) {
      var row = document.createElement("div");
      row.className = "ix-tl-row" + (lane.target ? " target" : "");
      var lab = document.createElement("span"); lab.className = "ix-tl-l"; lab.textContent = lane.label;
      var track = document.createElement("div"); track.className = "ix-tl-track";
      (data.segments || []).forEach(function (seg) {
        if (seg.lane !== lane.id) return;
        var band = document.createElement("div");
        band.className = "ix-chaos-seg " + (seg.cls || "");
        band.style.left = xPct(seg.from) + "%";
        band.style.width = Math.max(0.4, xPct(seg.to) - xPct(seg.from)) + "%";
        track.appendChild(band);
      });
      (data.evidence || []).forEach(function (ev) {
        if (ev.node !== lane.id) return;
        var mark = document.createElement("span");
        mark.className = "ix-chaos-work";
        mark.style.left = xPct(ev.off) + "%";
        bindTip(mark, ev.tip || "");
        track.appendChild(mark);
      });
      row.appendChild(lab); row.appendChild(track);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function passTimelineChart(host, data) {
    host.innerHTML = "";
    var box = document.createElement("div");
    box.className = "ix-pass-tl";
    (data.lanes || []).forEach(function (lane) {
      var row = document.createElement("div");
      row.className = "ix-tl-row";
      var lab = document.createElement("span"); lab.className = "ix-tl-l";
      lab.textContent = lane.node + " · " + lane.daemon;
      var track = document.createElement("div"); track.className = "ix-tl-track";
      (data.passes || []).forEach(function (p) {
        if (p.lane !== lane.id) return;
        var mark = document.createElement("span");
        mark.className = "ix-pass-mark" + (p.worked ? " worked" : "") + (p.failures ? " fail" : "") + (p.after ? "" : " base");
        bindTip(mark, p.tip || "");
        track.appendChild(mark);
      });
      row.appendChild(lab); row.appendChild(track);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function lineageChart(host, data) {
    host.innerHTML = "";
    var box = document.createElement("div"); box.className = "ix-lineage-graph";
    (data.bands || []).forEach(function (band) {
      var row = document.createElement("div"); row.className = "ix-lineage-band";
      var ins = document.createElement("div"); ins.className = "ix-lineage-col in";
      (band.inputs || []).forEach(function (n) {
        var node = document.createElement("div"); node.className = "ix-lineage-node " + (n.cls || "");
        node.innerHTML = "<b>" + n.label + "</b><em>" + (n.sub || "") + "</em>";
        bindTip(node, n.title || n.label);
        ins.appendChild(node);
      });
      if (!(band.inputs || []).length) ins.textContent = band.noInputs || "";
      var job = document.createElement("div"); job.className = "ix-lineage-job " + ((band.job || {}).cls || "");
      if (band.job) job.innerHTML = "<b>" + band.job.label + "</b><em>" + (band.job.sub || "") + "</em>";
      var outs = document.createElement("div"); outs.className = "ix-lineage-col out";
      (band.outputs || []).forEach(function (n) {
        var node = document.createElement("div"); node.className = "ix-lineage-node " + (n.cls || "");
        node.innerHTML = "<b>" + n.label + "</b><em>" + (n.sub || "") + "</em>";
        bindTip(node, n.title || n.label);
        outs.appendChild(node);
      });
      if (!(band.outputs || []).length) outs.textContent = band.noOutputs || "";
      row.appendChild(ins); row.appendChild(job); row.appendChild(outs);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function matrixChart(host, data) {
    host.innerHTML = "";
    if (data.nodes && data.devices && data.cells) {
      var table = document.createElement("div"); table.className = "ix-matrix";
      var head = document.createElement("div"); head.className = "ix-matrix-row head";
      head.appendChild(document.createElement("span"));
      data.devices.forEach(function (d) {
        var c = document.createElement("span"); c.className = "ix-matrix-h"; c.textContent = d;
        head.appendChild(c);
      });
      table.appendChild(head);
      data.nodes.forEach(function (node, ri) {
        var row = document.createElement("div"); row.className = "ix-matrix-row";
        var lab = document.createElement("span"); lab.className = "ix-matrix-l"; lab.textContent = node;
        row.appendChild(lab);
        data.devices.forEach(function (dev, ci) {
          var cell = data.cells.find(function (c) { return c.row === ri && c.col === ci; });
          var el = document.createElement("span");
          el.className = "ix-matrix-c " + ((cell && cell.cls) || "oc-c-none");
          if (cell && cell.label) {
            el.innerHTML = "<b>" + cell.label + "</b><em>" + (cell.role || "") + "</em>";
          }
          bindTip(el, (cell && cell.tip) || node + "/" + dev);
          row.appendChild(el);
        });
        table.appendChild(row);
      });
      host.appendChild(table);
      return;
    }
    var table = document.createElement("div"); table.className = "ix-matrix";
    (data.rows || []).forEach(function (r) {
      var row = document.createElement("div"); row.className = "ix-matrix-row";
      var lab = document.createElement("span"); lab.className = "ix-matrix-l"; lab.textContent = r.label;
      row.appendChild(lab);
      (r.cells || []).forEach(function (c) {
        var cell = document.createElement("span");
        cell.className = "ix-matrix-c " + (c.cls || "");
        cell.textContent = c.text || "";
        bindTip(cell, c.tip || c.text || r.label);
        row.appendChild(cell);
      });
      table.appendChild(row);
    });
    host.appendChild(table);
  }

  function hydrateChart(host) {
    var kind = host.getAttribute("data-ix-chart");
    var script = host.querySelector('script[type="application/json"]');
    if (!kind || !script) return;
    var data;
    try { data = JSON.parse(script.textContent); } catch (e) { return; }
    var mount = host.querySelector(".ix-mount");
    if (!mount) {
      mount = document.createElement("div");
      mount.className = "ix-mount";
      host.insertBefore(mount, script);
    } else {
      mount.innerHTML = "";
    }
    if (kind === "bars") barsChart(mount, data);
    else if (kind === "hbar") hbarChart(mount, data);
    else if (kind === "scatter") scatterChart(mount, data);
    else if (kind === "flow") flowChart(mount, data);
    else if (kind === "grid") gridChart(mount, data);
    else if (kind === "timeline") timelineChart(mount, data);
    else if (kind === "lineage") lineageChart(mount, data);
    else if (kind === "matrix") matrixChart(mount, data);
    else if (kind === "line") lineChart(mount, data, data.unit || "", { h: data.h });
  }

  function hydrateAll(root) {
    (root || document).querySelectorAll(".ix-host[data-ix-chart]").forEach(hydrateChart);
  }

  // pe-brow bars: bind live tip (server HTML charts)
  function bindPeTips(root) {
    (root || document).querySelectorAll(".pe-brow[title], .rs-devrow-svg, .ix-hbar-row").forEach(function (el) {
      if (el._ixTip) return;
      el._ixTip = true;
      var t = el.getAttribute("title");
      if (t) {
        el.removeAttribute("title");
        bindTip(el, t);
      }
    });
  }

  function statTile(body, resp, unit) {
    var v = resp.value;
    var big = document.createElement("div");
    big.className = "mon-stat-v";
    big.textContent = fmtVal(unit, v);
    if (unit === "ratio" && v != null && v > 0.01) big.classList.add("bad");
    else if (unit === "ratio") big.classList.add("ok");
    body.innerHTML = ""; body.appendChild(big);
  }

  function logView(body, resp) {
    var lines = resp.lines || [];
    if (!lines.length) { body.innerHTML = '<div class="mon-empty">' + T("No recent lines", "最近没有日志") + '</div>'; return; }
    var box = document.createElement("div"); box.className = "mon-logs";
    var rx = /(error|traceback|critical|panic|exception)/i;
    lines.forEach(function (ln) {
      var row = document.createElement("div");
      row.className = "mon-log" + (rx.test(ln.line) ? " err" : "");
      var unit = (ln.unit || "").replace(/^swift-/, "").replace(/\.service$/, "");
      var t = document.createElement("span"); t.className = "mon-log-t"; t.textContent = hhmmss(ln.t);
      var u = document.createElement("span"); u.className = "mon-log-u"; u.textContent = unit;
      var m = document.createElement("span"); m.className = "mon-log-m"; m.textContent = ln.line;
      row.appendChild(t); row.appendChild(u); row.appendChild(m); box.appendChild(row);
    });
    body.innerHTML = ""; body.appendChild(box);
  }


  // A swimlane: one lane for the client's clock, one per node, on a shared time
  // axis. The gap between a mark on the client lane and the same file's mark on
  // a node lane IS the diagnosis, so the two are never folded into one row.
  function swimlane(host, d) {
    timelineChart(host, {
      lanes: d.lanes || [],
      events: (d.events || []).map(function (e) {
        return {
          lane: e.lane, t: e.t, kind: e.kind, label: e.label,
          tip: (e.tip || (hhmmss(e.t) + "  " + (e.label || "")))
        };
      }),
      bands: d.offline || d.bands || [],
      delete_ts: d.delete_ts
    });
  }

  function onThemeChange() {
    _colorCache = {};
    hydrateAll(document);
    try { document.dispatchEvent(new CustomEvent("sc-theme")); } catch (e) { /* ignore */ }
  }

  var CHART = {
    SVGNS: SVGNS, svg: svg, fmtNum: fmtNum, fmtDur: fmtDur, fmtVal: fmtVal,
    hhmm: hhmm, hhmmss: hhmmss, lineChart: lineChart, statTile: statTile,
    logView: logView, swimlane: swimlane,
    hydrate: hydrateChart, hydrateAll: hydrateAll, onThemeChange: onThemeChange
  };
  window.CHART = CHART;

  hydrateAll(document);
  bindPeTips(document);
  // Warehouse lineage is server HTML; lift data-tip onto the shared tip layer.
  document.querySelectorAll(".wh-lineage-node[data-tip]").forEach(function (el) {
    var t = el.getAttribute("data-tip");
    if (t) bindTip(el, t);
  });

  // Click a lineage file node → live Range preview of the real object.
  if (PAGE === "lab-warehouse") {
    var whDlg = $("#dlg-wh-preview");
    var whTitle = $("#wh-preview-title");
    var whMeta = $("#wh-preview-meta");
    var whBody = $("#wh-preview-body");
    function openWhPreview(path) {
      if (!whDlg || !path) return;
      if (whTitle) whTitle.textContent = path.split("/").pop() || path;
      if (whMeta) whMeta.textContent = path;
      if (whBody) whBody.textContent = T("Loading…", "读取中…");
      if (!whDlg.open) whDlg.showModal();
      api("GET", "/lab/api/warehouse/sample?object=" + encodeURIComponent(path) + "&bytes=8192&lines=120")
        .then(function (d) {
          if (whMeta) {
            whMeta.textContent = (d.dataset || "") + "/" + (d.object || path) +
              " · " + fmtBytes(d.bytes_read || 0) +
              (d.bytes_total ? " / " + fmtBytes(d.bytes_total) : "") +
              (d.complete ? "" : " · " + T("prefix sample", "前缀样例"));
          }
          if (whBody) whBody.textContent = d.sample || T("(empty)", "（空）");
        })
        .catch(function (e) {
          if (whBody) whBody.textContent = e.message || String(e);
        });
    }
    document.addEventListener("click", function (ev) {
      var n = ev.target.closest && ev.target.closest("[data-wh-obj]");
      if (!n) return;
      ev.preventDefault();
      openWhPreview(n.getAttribute("data-wh-obj"));
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      var n = ev.target.closest && ev.target.closest("[data-wh-obj]");
      if (!n) return;
      ev.preventDefault();
      openWhPreview(n.getAttribute("data-wh-obj"));
    });
  }

  window.addEventListener("resize", function () {
    document.querySelectorAll(".ix-host[data-ix-chart]").forEach(function (host) {
      var mount = host.querySelector(".ix-mount");
      if (mount) { mount.innerHTML = ""; hydrateChart(host); }
    });
  });

  if (PAGE === "monitor") {
    var mon = { dashes: [], active: 0, range: 3600, timer: null,
                nodes: [], node: "", nodePanels: [], nodeTitle: "" };
    var grid = $("#mon-grid"), tabs = $("#mon-tabs");
    var rangeSel = $("#mon-range"), refreshBtn = $("#mon-refresh");
    var nodeBar = $("#mon-nodebar"), nodeSeg = $("#mon-nodes");

    function panelUrl(p, range) {
      var u = "/monitor/api/panel?id=" + encodeURIComponent(p.id) + "&range=" + range;
      // Always pin the node when one is selected. Panels without `{nf}` ignore it.
      if (mon.node) u += "&node=" + encodeURIComponent(mon.node);
      return u;
    }

    // Service-state grid: one row per node, one dot per service; every cell
    // names its service and state, every row opens that node.
    function svcGridView(body, resp) {
      var g = resp.grid || {}, services = g.services || [], rows = g.rows || [];
      if (!rows.length) { body.innerHTML = '<div class="mon-empty">' + T("No data", "没有数据") + '</div>'; return; }
      var box = document.createElement("div"); box.className = "mon-svcgrid";
      var head = document.createElement("div"); head.className = "mon-svc-row head";
      var hn = document.createElement("span"); hn.className = "mon-svc-node"; hn.textContent = T("Node", "节点");
      head.appendChild(hn);
      services.forEach(function (s) {
        var c = document.createElement("span"); c.className = "mon-svc-h";
        c.textContent = s.replace(/^swift-/, ""); head.appendChild(c);
      });
      box.appendChild(head);
      rows.forEach(function (r) {
        var row = document.createElement("div"); row.className = "mon-svc-row";
        row.setAttribute("data-node", r.node); row.tabIndex = 0;
        row.setAttribute("role", "button");
        row.title = T("Open ", "查看 ") + r.node;
        var nm = document.createElement("span"); nm.className = "mon-svc-node"; nm.textContent = r.node;
        row.appendChild(nm);
        (r.cells || []).forEach(function (c) {
          var cell = document.createElement("span");
          cell.className = "mon-svc-c " + (c.state === "active" ? "ok" : (c.state === "unreachable" ? "unk" : "bad"));
          cell.title = c.service + ": " + c.state;
          row.appendChild(cell);
        });
        box.appendChild(row);
      });
      box.addEventListener("click", function (ev) {
        var row = ev.target.closest(".mon-svc-row[data-node]");
        if (row) selectNode(row.getAttribute("data-node"));
      });
      body.innerHTML = ""; body.appendChild(box);
    }

    function paint(p, card, resp) {
      var body = card.querySelector(".mon-body"), leg = card.querySelector(".mon-legend");
      if (leg) leg.innerHTML = "";
      if (resp.error) { body.innerHTML = '<div class="mon-empty">' + T("Unavailable", "暂不可用") + '</div>'; return; }
      if (p.kind === "stat") { statTile(body, resp, p.unit); return; }
      if (p.kind === "logs") { logView(body, resp); return; }
      if (p.kind === "svcgrid") { svcGridView(body, resp); return; }
      card._resp = resp; // reused by the drill without a second query
      var legend = lineChart(body, resp, p.unit);
      if (leg && legend.length) {
        legend.forEach(function (l, li) {
          var it = document.createElement("span"); it.className = "mon-leg-i linked";
          var sw = document.createElement("i"); sw.className = l.cls;
          var nm = document.createElement("b"); nm.textContent = l.name;
          var vv = document.createElement("em"); vv.textContent = fmtVal(l.unit, l.last);
          it.appendChild(sw); it.appendChild(nm); it.appendChild(vv);
          it.title = l.key
            ? T("Open node ", "查看节点 ") + l.key
            : T("Open series ", "单独查看 ") + l.name;
          it.addEventListener("click", function (ev) {
            ev.stopPropagation();
            if (l.key) selectNode(l.key);
            else openDrill(p, l.name);
          });
          leg.appendChild(it);
        });
      }
    }

    function fetchPanel(p, card) {
      api("GET", panelUrl(p, mon.range))
        .then(function (resp) { paint(p, card, resp); })
        .catch(function () {
          var body = card.querySelector(".mon-body");
          if (body) body.innerHTML = '<div class="mon-empty">' + T("Unavailable", "暂不可用") + '</div>';
        });
    }

    function cardShell(p) {
      var card = document.createElement("div");
      card.className = "mon-card" + (p.kind === "stat" ? " mon-stat" : "") + (p.wide ? " wide" : "");
      card.setAttribute("data-panel", p.id);
      var h = document.createElement("div"); h.className = "mon-card-h";
      var t = document.createElement("span"); t.className = "mon-t"; t.textContent = p.title;
      h.appendChild(t);
      if (p.kind === "series") { var lg = document.createElement("span"); lg.className = "mon-legend"; h.appendChild(lg); }
      var b = document.createElement("div"); b.className = "mon-body";
      b.innerHTML = '<div class="mon-empty">…</div>';
      card.appendChild(h); card.appendChild(b);
      // Every tile opens: series and logs enlarge in place, stat tiles open
      // their history panel.
      if (p.kind !== "svcgrid") {
        card.classList.add("openable");
        card.title = T("Click to enlarge", "点击放大查看");
        card.addEventListener("click", function () { openDrill(p); });
      }
      return card;
    }

    function activePanels() {
      if (mon.node) return mon.nodePanels;
      var d = mon.dashes[mon.active];
      return d ? d.panels : [];
    }

    function loadDash() {
      grid.innerHTML = "";
      activePanels().forEach(function (p) {
        var card = cardShell(p);
        grid.appendChild(card);
        fetchPanel(p, card);
      });
    }
    function refresh() {
      activePanels().forEach(function (p) {
        var card = grid.querySelector('.mon-card[data-panel="' + p.id + '"]');
        if (card) fetchPanel(p, card);
      });
    }

    function buildTabs() {
      tabs.innerHTML = "";
      mon.dashes.forEach(function (d, i) {
        var b = document.createElement("button");
        b.type = "button"; b.className = "seg-b" + (!mon.node && i === mon.active ? " active" : "");
        b.textContent = d.title;
        b.addEventListener("click", function () {
          mon.active = i;
          selectNode("");
        });
        tabs.appendChild(b);
      });
    }

    function buildNodeBar() {
      if (!nodeBar || !nodeSeg || !mon.nodes.length) return;
      nodeBar.hidden = false;
      nodeSeg.innerHTML = "";
      var all = document.createElement("button");
      all.type = "button"; all.className = "seg-b" + (mon.node ? "" : " active");
      all.textContent = T("All", "全部");
      all.addEventListener("click", function () { selectNode(""); });
      nodeSeg.appendChild(all);
      mon.nodes.forEach(function (n) {
        var b = document.createElement("button");
        b.type = "button"; b.className = "seg-b" + (mon.node === n ? " active" : "");
        b.textContent = n;
        b.addEventListener("click", function () { selectNode(n); });
        nodeSeg.appendChild(b);
      });
    }

    function selectNode(name) {
      mon.node = name || "";
      buildNodeBar();
      $$(".seg-b", tabs).forEach(function (x, xi) {
        x.classList.toggle("active", !mon.node && xi === mon.active);
      });
      loadDash();
    }

    // ---- panel drill: a full-width chart plus the numbers behind it ----
    var drill = $("#mon-drill"), drillT = $("#mon-drill-t"),
        drillBody = $("#mon-drill-body"), drillTable = $("#mon-drill-table"),
        drillRange = $("#mon-drill-range"), drillClose = $("#mon-drill-close");
    var drillState = { p: null, range: 3600, focus: "" };

    function seriesStats(s) {
      var vals = (s.points || []).map(function (p) { return p[1]; })
        .filter(function (v) { return v != null && !isNaN(v); });
      if (!vals.length) return null;
      var min = Infinity, max = -Infinity, sum = 0;
      vals.forEach(function (v) { if (v < min) min = v; if (v > max) max = v; sum += v; });
      return { min: min, max: max, avg: sum / vals.length, last: vals[vals.length - 1] };
    }

    function paintDrill(resp) {
      var p = drillState.p;
      drillBody.innerHTML = ""; drillTable.innerHTML = "";
      if (!p || resp.error) { drillBody.innerHTML = '<div class="mon-empty">' + T("Unavailable", "暂不可用") + '</div>'; return; }
      if (p.kind === "logs" || resp.kind === "logs") { logView(drillBody, resp); return; }
      if (p.kind === "svcgrid" || resp.kind === "svcgrid") {
        svcGridView(drillBody, resp);
        return;
      }

      var all = resp.series || [];
      var focus = drillState.focus;
      var shown = focus
        ? all.filter(function (s) { return s.name === focus; })
        : all;
      if (!shown.length) {
        drillBody.innerHTML = '<div class="mon-empty">' + T("No data in range", "该区间内没有数据") + '</div>';
        return;
      }

      // One chart per series so P50 is never crushed under P99 on a shared axis.
      var wrap = document.createElement("div"); wrap.className = "mon-drill-split";
      shown.forEach(function (s, i) {
        var card = document.createElement("div"); card.className = "mon-drill-one";
        var h = document.createElement("div"); h.className = "mon-drill-one-h";
        var sw = document.createElement("i"); sw.className = "mon-leg-sw mon-s" + ((i % 6) + 1);
        var nm = document.createElement("b"); nm.textContent = s.name;
        h.appendChild(sw); h.appendChild(nm);
        var body = document.createElement("div"); body.className = "mon-body";
        lineChart(body, { series: [s] }, p.unit, { h: shown.length === 1 ? 280 : 180 });
        card.appendChild(h); card.appendChild(body);
        wrap.appendChild(card);
      });
      drillBody.appendChild(wrap);

      // Numbers for every series in the panel; click a row to isolate that line.
      var tbl = document.createElement("table"); tbl.className = "tbl mon-drill-tbl";
      var thead = document.createElement("thead");
      thead.innerHTML = "<tr><th></th><th>" + T("Series", "系列") + "</th><th>" +
        T("Current", "当前") + "</th><th>" + T("Min", "最小") + "</th><th>" +
        T("Avg", "平均") + "</th><th>" + T("Max", "最大") + "</th></tr>";
      tbl.appendChild(thead);
      var tb = document.createElement("tbody");
      all.forEach(function (s, i) {
        var st = seriesStats(s); if (!st) return;
        var tr = document.createElement("tr");
        if (focus && s.name === focus) tr.classList.add("on");
        tr.style.cursor = "pointer";
        var sw = "<i class='mon-leg-sw " + ("mon-s" + ((i % 6) + 1)) + "'></i>";
        tr.innerHTML = "<td>" + sw + "</td><td>" + s.name + "</td><td>" + fmtVal(p.unit, st.last) +
          "</td><td>" + fmtVal(p.unit, st.min) + "</td><td>" + fmtVal(p.unit, st.avg) +
          "</td><td>" + fmtVal(p.unit, st.max) + "</td>";
        tr.addEventListener("click", function () {
          drillState.focus = (drillState.focus === s.name) ? "" : s.name;
          drillT.textContent = p.title +
            (mon.node ? " · " + mon.node : "") +
            (drillState.focus ? " · " + drillState.focus : "");
          paintDrill(resp);
        });
        tb.appendChild(tr);
      });
      tbl.appendChild(tb);
      if (tb.children.length) {
        var hint = document.createElement("p");
        hint.className = "note";
        hint.textContent = T(
          "Click a row to show only that series; click again to show all, each on its own axis.",
          "点击一行只看该系列；再点一次恢复全部，每条线各自一条轴。"
        );
        drillTable.appendChild(hint);
        drillTable.appendChild(tbl);
      }
    }

    function fetchDrill() {
      var p = drillState.p; if (!p) return;
      drillBody.innerHTML = '<div class="mon-empty">…</div>';
      api("GET", panelUrl(p, drillState.range))
        .then(paintDrill)
        .catch(function () { drillBody.innerHTML = '<div class="mon-empty">' + T("Unavailable", "暂不可用") + '</div>'; });
    }

    function openDrill(p, focusName) {
      // A stat tile opens its history panel; everything else opens itself.
      var target = p;
      if (p.kind === "stat" && p.drill) {
        var all = mon.dashes.reduce(function (acc, d) { return acc.concat(d.panels); }, [])
          .concat(mon.nodePanels);
        var hit = all.filter(function (x) { return x.id === p.drill; })[0];
        target = hit || { id: p.drill, title: p.title, kind: "series", unit: p.unit, node_scoped: true, drill: "" };
      }
      drillState.p = target;
      drillState.focus = focusName || "";
      drillState.range = mon.range;
      drillT.textContent = target.title +
        (mon.node ? " · " + mon.node : "") +
        (drillState.focus ? " · " + drillState.focus : "");
      // range chips
      drillRange.innerHTML = "";
      [[900, T("15m", "15 分钟")], [3600, T("1h", "1 小时")], [21600, T("6h", "6 小时")],
       [86400, T("24h", "24 小时")], [604800, T("7d", "7 天")]].forEach(function (r) {
        var b = document.createElement("button");
        b.type = "button"; b.className = "seg-b" + (drillState.range === r[0] ? " active" : "");
        b.textContent = r[1];
        b.addEventListener("click", function () {
          drillState.range = r[0];
          $$(".seg-b", drillRange).forEach(function (x) { x.classList.toggle("active", x === b); });
          fetchDrill();
        });
        drillRange.appendChild(b);
      });
      if (drill && !drill.open) drill.showModal();
      fetchDrill();
    }
    if (drillClose) drillClose.addEventListener("click", function () { drill.close(); });
    if (drill) drill.addEventListener("click", function (ev) { if (ev.target === drill) drill.close(); });

    if (rangeSel) rangeSel.addEventListener("change", function () { mon.range = parseInt(rangeSel.value, 10) || 3600; loadDash(); });
    if (refreshBtn) refreshBtn.addEventListener("click", refresh);
    document.addEventListener("sc-theme", refresh);
    var rzTimer = null;
    window.addEventListener("resize", function () { clearTimeout(rzTimer); rzTimer = setTimeout(refresh, 250); });

    api("GET", "/monitor/api/dash").then(function (d) {
      mon.dashes = d.dashboards || [];
      mon.nodes = d.nodes || [];
      mon.nodePanels = d.node_panels || [];
      mon.nodeTitle = d.node_title || "";
      buildTabs();
      buildNodeBar();
      loadDash();
      mon.timer = setInterval(refresh, 30000);
    }).catch(function () {
      grid.innerHTML = '<div class="mon-empty">' + T("Monitoring is unavailable right now.", "监控暂时不可用。") + '</div>';
    });
  }

  // ------------------------------------------------------------- RingScope
  if ((PAGE === "lab-ring" || PAGE === "lab-ringscope") && $("#rs-out")) {
    var rs = { topo: null, ops: [], devices: [] };
    var out = $("#rs-out"), status = $("#rs-status");

    function b64bytes(b64) {
      var bin = atob(b64), a = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
      return a;
    }
    function devLabel(d) {
      return (d.node || d.ip) + " / " + d.device + "  (r" + d.region + "z" + d.zone + ")";
    }

    // ---- scenario builder ----
    function fillTargets() {
      var kind = $("#rs-op-kind").value;
      var t = $("#rs-op-target"), v = $("#rs-op-value");
      t.innerHTML = ""; t.hidden = false; v.hidden = true; v.value = "";
      if (kind === "add_device") {
        t.hidden = true; v.hidden = false;
        v.placeholder = "region,zone,ip,device,weight  e.g. 1,4,10.42.10.14,d1,100";
        return;
      }
      if (kind === "fail_zone") {
        var zones = {};
        rs.devices.forEach(function (d) { zones["r" + d.region + "z" + d.zone] = d; });
        Object.keys(zones).sort().forEach(function (k) {
          var o = document.createElement("option");
          o.value = zones[k].region + ":" + zones[k].zone; o.textContent = k;
          t.appendChild(o);
        });
        return;
      }
      rs.devices.forEach(function (d) {
        var o = document.createElement("option");
        o.value = String(d.dev_id); o.textContent = devLabel(d);
        t.appendChild(o);
      });
      if (kind === "set_weight") { v.hidden = false; v.placeholder = "new weight, e.g. 50"; }
    }

    function renderOps() {
      var box = $("#rs-ops"); box.innerHTML = "";
      rs.ops.forEach(function (o, i) {
        var chip = document.createElement("span");
        chip.className = "rs-chip";
        var txt = document.createElement("b"); txt.textContent = o.label;
        var x = document.createElement("button");
        x.className = "ibtn danger"; x.type = "button"; x.title = "Remove";
        x.textContent = "×";
        x.addEventListener("click", function () { rs.ops.splice(i, 1); renderOps(); });
        chip.appendChild(txt); chip.appendChild(x); box.appendChild(chip);
      });
      $("#rs-op-count").textContent = rs.ops.length
        ? rs.ops.length + " change" + (rs.ops.length === 1 ? "" : "s") + " staged"
        : "no changes — showing the ring as it stands";
    }

    $("#rs-op-kind").addEventListener("change", fillTargets);
    $("#rs-op-add").addEventListener("click", function () {
      var kind = $("#rs-op-kind").value;
      var tsel = $("#rs-op-target"), val = $("#rs-op-value").value.trim();
      var op = { op: kind }, label = "";
      if (kind === "add_device") {
        var parts = val.split(",").map(function (x) { return x.trim(); });
        if (parts.length < 4) { setErr("#rs-status", "Need region,zone,ip,device[,weight]"); return; }
        op.region = parseInt(parts[0], 10); op.zone = parseInt(parts[1], 10);
        op.ip = parts[2]; op.device = parts[3];
        op.weight = parts[4] ? parseFloat(parts[4]) : 100;
        op.port = 6200;
        label = "add " + op.ip + "/" + op.device + " (r" + op.region + "z" + op.zone + ")";
      } else if (kind === "fail_zone") {
        var rz = tsel.value.split(":");
        op.region = parseInt(rz[0], 10); op.zone = parseInt(rz[1], 10);
        label = "lose zone r" + op.region + "z" + op.zone;
      } else {
        var d = rs.devices.find(function (x) { return String(x.dev_id) === tsel.value; });
        if (!d) return;
        op.dev_id = d.dev_id;
        var name = (d.node || d.ip) + "/" + d.device;
        if (kind === "set_weight") {
          op.weight = parseFloat(val);
          if (isNaN(op.weight)) { setErr("#rs-status", "Enter a weight"); return; }
          label = "weight " + name + " -> " + op.weight;
        } else if (kind === "fail_node") { label = "take " + (d.node || d.ip) + " offline"; delete op.dev_id; op.ip = d.ip; }
        else if (kind === "remove_device") { label = "retire " + name; }
        else { label = "pull " + name; }
      }
      op.label = label;
      rs.ops.push(op);
      renderOps();
    });
    $("#rs-reset").addEventListener("click", function () { rs.ops = []; renderOps(); run(); });

    // ---- rendering ----
    function statRow(t) {
      var wrap = document.createElement("div");
      // The grid is 4-up by default; a 5-tile row gets its own track count so
      // the fifth card sits on the same baseline instead of stranded below.
      wrap.className = "mon-grid" + (t.length === 5 ? " mon-grid-5" : "");
      t.forEach(function (s) {
        var c = document.createElement("div"); c.className = "mon-card mon-stat lab-stat";
        var h = document.createElement("div"); h.className = "mon-card-h";
        var ti = document.createElement("span"); ti.className = "mon-t"; ti.textContent = s.title;
        h.appendChild(ti);
        var b = document.createElement("div"); b.className = "mon-body";
        var v = document.createElement("div"); v.className = "mon-stat-v" + (s.tone ? " " + s.tone : "");
        v.textContent = s.value;
        b.appendChild(v);
        if (s.sub) { var sub = document.createElement("div"); sub.className = "lab-b"; sub.textContent = s.sub; b.appendChild(sub); }
        c.appendChild(h); c.appendChild(b); wrap.appendChild(c);
      });
      return wrap;
    }

    // Partition map: one rect per partition, coloured by what happened to it.
    function partMap(states, policy) {
      var card = document.createElement("div"); card.className = "mon-card wide";
      var h = document.createElement("div"); h.className = "mon-card-h";
      var t = document.createElement("span"); t.className = "mon-t"; t.textContent = T("Partitions", "分区");
      var lg = document.createElement("span"); lg.className = "mon-legend";
      [[T("unchanged", "未变动"), "rs-p0"], [T("one replica moved", "移动 1 个副本"), "rs-p1"], [T("several moved", "移动多个副本"), "rs-p2"], [T("fully relocated", "全部迁移"), "rs-p3"]]
        .forEach(function (p) {
          var i = document.createElement("span"); i.className = "mon-leg-i";
          var sw = document.createElement("i"); sw.className = p[1];
          var nm = document.createElement("b"); nm.textContent = p[0];
          i.appendChild(sw); i.appendChild(nm); lg.appendChild(i);
        });
      h.appendChild(t); h.appendChild(lg);
      var body = document.createElement("div"); body.className = "mon-body";
      var n = states.length, cols = Math.min(64, Math.max(16, Math.ceil(Math.sqrt(n) * 2)));
      var rows = Math.ceil(n / cols);
      var cell = 12, gap = 1;
      var svg = CHART.svg("svg", {
        viewBox: "0 0 " + (cols * cell) + " " + (rows * cell),
        width: "100%", class: "rs-map"
      });
      for (var i = 0; i < n; i++) {
        var r = CHART.svg("rect", {
          x: (i % cols) * cell, y: Math.floor(i / cols) * cell,
          width: cell - gap, height: cell - gap, rx: 1,
          class: "rs-p" + states[i]
        });
        r.addEventListener("click", (function (part) {
          return function () { showPart(part, policy); };
        })(i));
        svg.appendChild(r);
      }
      body.appendChild(svg);
      var note = document.createElement("div"); note.className = "lab-b";
      note.textContent = T("Click a partition to see which nodes hold it.", "点击分区可查看它落在哪些节点上。");
      body.appendChild(note);
      card.appendChild(h); card.appendChild(body);
      return card;
    }

    function showPart(part, policy) {
      api("GET", "/lab/api/ring/part?policy=" + policy + "&part=" + part).then(function (d) {
        var lines = (d.nodes || []).map(function (n) {
          return (n.handoff ? "handoff  " : "primary  ") + (n.node || n.ip) + " / " + n.device;
        });
        $("#rs-part").textContent = "Partition " + part + "\n" + lines.join("\n");
      }).catch(function (e) { $("#rs-part").textContent = e.message; });
    }

    function table(cols, rows) {
      var wrap = document.createElement("div"); wrap.className = "tbl-wrap";
      var t = document.createElement("table"); t.className = "tbl";
      var th = document.createElement("thead"); var tr = document.createElement("tr");
      cols.forEach(function (c) { var e = document.createElement("th"); e.textContent = c; tr.appendChild(e); });
      th.appendChild(tr); t.appendChild(th);
      var tb = document.createElement("tbody");
      rows.forEach(function (r) {
        var row = document.createElement("tr");
        r.forEach(function (c) {
          var e = document.createElement("td");
          if (c && c.cls) { e.className = c.cls; e.textContent = c.v; } else e.textContent = c;
          row.appendChild(e);
        });
        tb.appendChild(row);
      });
      t.appendChild(tb); wrap.appendChild(t);
      return wrap;
    }

    function card(title, node) {
      var c = document.createElement("div"); c.className = "mon-card wide";
      var h = document.createElement("div"); h.className = "mon-card-h";
      var t = document.createElement("span"); t.className = "mon-t"; t.textContent = title;
      h.appendChild(t);
      var b = document.createElement("div"); b.className = "mon-body";
      b.appendChild(node);
      c.appendChild(h); c.appendChild(b);
      return c;
    }

    // The chart is the reading surface; the full table stays one click away so
    // nothing the table said is lost.
    function withTable(chartNode, cols, rows) {
      var box = document.createElement("div");
      box.appendChild(chartNode);
      var det = document.createElement("details"); det.className = "rs-det";
      var sum = document.createElement("summary");
      sum.textContent = T("Data table", "查看数据表");
      det.appendChild(sum);
      det.appendChild(table(cols, rows));
      box.appendChild(det);
      return box;
    }

    // Devices, drawn: per device a before→after partition bar pair, its share
    // of the ring, and its state — everything the table carried, readable at a
    // glance. Devices group under their node.
    function deviceChart(devices) {
      var wrap = document.createElement("div"); wrap.className = "rs-devchart";
      var maxParts = 1;
      devices.forEach(function (x) {
        maxParts = Math.max(maxParts, x.parts_before || 0, x.parts_after || 0);
      });
      var byNode = {};
      devices.forEach(function (x) {
        var k = x.node || x.ip;
        (byNode[k] = byNode[k] || []).push(x);
      });
      Object.keys(byNode).forEach(function (nodeName) {
        var g = document.createElement("div"); g.className = "rs-devgroup";
        var head = document.createElement("div"); head.className = "rs-devnode";
        var zone = byNode[nodeName][0];
        head.textContent = nodeName + "  ·  r" + zone.region + "z" + zone.zone;
        g.appendChild(head);
        byNode[nodeName].forEach(function (x) {
          var row = document.createElement("div"); row.className = "rs-devrow";
          var lab = document.createElement("span"); lab.className = "rs-devlab";
          lab.textContent = x.device;
          var meta = document.createElement("span"); meta.className = "rs-devmeta";
          meta.textContent = T("weight ", "权重 ") + x.weight;
          var bars = document.createElement("div"); bars.className = "rs-devbars";
          var pb = Math.round(100 * (x.parts_before || 0) / maxParts);
          var pa = Math.round(100 * (x.parts_after || 0) / maxParts);
          var b1 = document.createElement("div"); b1.className = "rs-bar before";
          b1.style.width = Math.max(pb, 1) + "%";
          var b1v = document.createElement("em"); b1v.textContent = x.parts_before;
          b1.appendChild(b1v);
          b1.title = T("before: ", "变更前：") + x.parts_before + T(" partitions", " 个分区");
          var b2 = document.createElement("div"); b2.className = "rs-bar after";
          b2.style.width = Math.max(pa, 1) + "%";
          var b2v = document.createElement("em"); b2v.textContent = x.parts_after;
          b2.appendChild(b2v);
          b2.title = T("after: ", "变更后：") + x.parts_after + T(" partitions", " 个分区");
          bars.appendChild(b1); bars.appendChild(b2);
          var delta = (x.parts_after || 0) - (x.parts_before || 0);
          var tail = document.createElement("span"); tail.className = "rs-devtail";
          var dchip = document.createElement("b");
          dchip.className = "rs-delta " + (delta > 0 ? "up" : (delta < 0 ? "down" : "flat"));
          dchip.textContent = (delta > 0 ? "+" : "") + delta;
          dchip.title = T("partitions gained/lost", "分区增减");
          var bal = document.createElement("i"); bal.className = "rs-bal";
          bal.textContent = (x.balance_pct || 0).toFixed(1) + "%";
          bal.title = T("balance vs fair share", "相对公平份额的均衡度");
          var st = document.createElement("i");
          st.className = "rs-state " + (x.state === "ok" || x.state === "unchanged" ? "ok" : "warn");
          st.textContent = x.state;
          tail.appendChild(dchip); tail.appendChild(bal); tail.appendChild(st);
          row.appendChild(lab); row.appendChild(meta); row.appendChild(bars); row.appendChild(tail);
          g.appendChild(row);
        });
        wrap.appendChild(g);
      });
      var legend = document.createElement("div"); legend.className = "rs-devlegend";
      [["before", T("partitions before", "变更前分区数")], ["after", T("partitions after", "变更后分区数")]]
        .forEach(function (p) {
          var i = document.createElement("span"); i.className = "mon-leg-i";
          var sw = document.createElement("i"); sw.className = "rs-bar-sw " + p[0];
          var nm = document.createElement("b"); nm.textContent = p[1];
          i.appendChild(sw); i.appendChild(nm); legend.appendChild(i);
        });
      wrap.appendChild(legend);
      return wrap;
    }

    // Where the data goes, drawn: sources on the left, destinations on the
    // right, one ribbon per flow with width carrying the replica count. Every
    // ribbon names its endpoints, replica count and bytes on hover.
    function flowChart(flows, devices, bytesPerSlot) {
      var name = function (id) {
        var d = devices.find(function (x) { return x.dev_id === id; });
        return d ? (d.node || d.ip) + "/" + d.device : "dev " + id;
      };
      var srcs = [], dsts = [], total = 0;
      var sIdx = {}, dIdx = {};
      flows.forEach(function (f) {
        if (!(f.from in sIdx)) { sIdx[f.from] = srcs.length; srcs.push({ id: f.from, sum: 0 }); }
        if (!(f.to in dIdx)) { dIdx[f.to] = dsts.length; dsts.push({ id: f.to, sum: 0 }); }
        srcs[sIdx[f.from]].sum += f.slots;
        dsts[dIdx[f.to]].sum += f.slots;
        total += f.slots;
      });
      srcs.sort(function (a, b) { return b.sum - a.sum; });
      dsts.sort(function (a, b) { return b.sum - a.sum; });
      sIdx = {}; dIdx = {};
      srcs.forEach(function (s, i) { sIdx[s.id] = i; });
      dsts.forEach(function (d, i) { dIdx[d.id] = i; });

      var W = 860, labW = 190, colW = 10;
      var innerH = Math.max(srcs.length, dsts.length) * 34 + 20;
      var H = innerH + 16;
      var x1 = labW, x2 = W - labW;
      var sy = {}, dy = {};
      var pack = function (list, idx, yMap) {
        var gap = 8;
        var scale = (innerH - gap * (list.length - 1)) / Math.max(total, 1);
        var y = 10;
        list.forEach(function (e) {
          var h = Math.max(e.sum * scale, 4);
          yMap[e.id] = { y: y, h: h, off: 0 };
          y += h + gap;
        });
      };
      pack(srcs, sIdx, sy); pack(dsts, dIdx, dy);

      var s = CHART.svg("svg", { viewBox: "0 0 " + W + " " + H, width: "100%", class: "rs-flow" });
      // endpoint bars + labels
      var endpoint = function (list, yMap, isSrc) {
        list.forEach(function (e) {
          var m = yMap[e.id];
          s.appendChild(CHART.svg("rect", {
            x: isSrc ? x1 - colW : x2, y: m.y, width: colW, height: m.h, rx: 2,
            class: isSrc ? "rs-fl-src" : "rs-fl-dst"
          }));
          var lab = CHART.svg("text", {
            x: isSrc ? x1 - colW - 8 : x2 + colW + 8, y: m.y + m.h / 2 + 3.5,
            "text-anchor": isSrc ? "end" : "start", class: "rs-fl-lab"
          });
          lab.textContent = name(e.id) + "  (" + e.sum + ")";
          s.appendChild(lab);
        });
      };
      endpoint(srcs, sy, true); endpoint(dsts, dy, false);
      // ribbons
      var scale = function (slots, sum, h) { return Math.max(h * slots / Math.max(sum, 1), 2); };
      flows.forEach(function (f) {
        var sm = sy[f.from], dm = dy[f.to];
        var sh = scale(f.slots, srcs[sIdx[f.from]].sum, sm.h);
        var dh = scale(f.slots, dsts[dIdx[f.to]].sum, dm.h);
        var ys = sm.y + sm.off + sh / 2, yd = dm.y + dm.off + dh / 2;
        sm.off += sh; dm.off += dh;
        var mid = (x1 + x2) / 2;
        var path = CHART.svg("path", {
          d: "M" + x1 + " " + ys + " C" + mid + " " + ys + " " + mid + " " + yd + " " + x2 + " " + yd,
          class: "rs-fl-rib", "stroke-width": Math.max((sh + dh) / 2, 1.6), fill: "none"
        });
        var tt = CHART.svg("title", {});
        tt.textContent = name(f.from) + " -> " + name(f.to) + " · " + f.slots +
          T(" replicas · ", " 个副本 · ") + fmtBytes((bytesPerSlot || 0) * f.slots);
        path.appendChild(tt);
        s.appendChild(path);
      });
      var box = document.createElement("div");
      box.appendChild(s);
      var note = document.createElement("div"); note.className = "lab-b";
      note.textContent = T("Ribbon width is the replica count; hover for exact replicas and bytes.",
        "带宽代表副本数量；悬停可见精确的副本数与数据量。");
      box.appendChild(note);
      return box;
    }

    function render(d) {
      out.innerHTML = "";
      if (d.warnings && d.warnings.length) {
        var w = document.createElement("p"); w.className = "err on";
        w.textContent = d.warnings.join(" · ");
        out.appendChild(w);
      }
      var s = d.survival || {}, mv = d.movement || {}, tr = d.transfer || {};
      var tb = d.tolerance_before || {}, ta = d.tolerance_after || {};
      // Reads and writes fail at different thresholds and must not be merged:
      // an EC 2+1 partition with one node down is BELOW WRITE QUORUM (3 of 3)
      // yet perfectly readable from its surviving k=2 fragments. Reporting
      // those partitions as unreadable would be the opposite of the truth.
      var lost = s.parts_lost || 0;
      var noWrite = s.parts_below_quorum || 0;
      var total = s.parts_total || 0;
      out.appendChild(statRow([
        { title: T("Readable now", "当前可读"), value: lost ? (total - lost) + " of " + total : "all " + total,
          tone: lost ? "bad" : "ok",
          sub: lost ? lost + T(" unreadable", " 个分区不可读")
                    : T("min ", "每分区最少 ") + (s.min_surviving_replicas || 0) + T(" copies per partition", " 份") },
        { title: T("Writable now", "当前可写"), value: noWrite ? (total - noWrite) + " of " + total : "all " + total,
          tone: noWrite ? "bad" : "ok",
          sub: noWrite
            ? T("below write quorum of ", "低于写入法定数 ") + (s.quorum || 0) + T(" — writes fail", " —— 写入会失败")
            : T("write quorum ", "写入法定数 ") + (s.quorum || 0) + T(" met", " 已满足") },
        { title: T("Replicas to move", "需迁移副本"), value: (mv.slots_moved || 0) + "",
          sub: (mv.moved_pct || 0).toFixed(1) + "% of all replica slots" },
        { title: T("Data to move", "需迁移数据"), value: fmtBytes(tr.bytes_moved || 0),
          sub: tr.eta_secs != null
            ? "about " + fmtDuration(tr.eta_secs) + " " + (tr.eta_note || "")
            : (tr.eta_note || "no estimate") },
        { title: T("Failure tolerance", "容错能力"), value: (ta.node_loss != null ? ta.node_loss : tb.node_loss || 0) + " node" +
            ((ta.node_loss || tb.node_loss) === 1 ? "" : "s"),
          sub: "zones " + (tb.zone_loss || 0) + " -> " + (ta.zone_loss || 0) + ", limited by " + (ta.limiting_domain || tb.limiting_domain || "-") }
      ]));

      var grid = document.createElement("div"); grid.className = "mon-grid";
      if (mv.part_states) {
        grid.appendChild(partMap(b64bytes(mv.part_states), d.policy_info ? d.policy_info.index : 0));
        var pre = document.createElement("pre"); pre.className = "rs-part"; pre.id = "rs-part";
        pre.textContent = "";
        grid.appendChild(card(T("Partition detail", "分区详情"), pre));
      }

      var devRows = (d.devices || []).map(function (x) {
        return [
          (x.node || x.ip) + " / " + x.device,
          "r" + x.region + "z" + x.zone,
          { cls: "num", v: String(x.weight) },
          { cls: "num", v: String(x.parts_before) },
          { cls: "num", v: String(x.parts_after) },
          { cls: "num", v: (x.balance_pct || 0).toFixed(1) + "%" },
          x.state
        ];
      });
      grid.appendChild(card(T("Devices", "设备"),
        withTable(deviceChart(d.devices || []),
          ["Device", "Zone", "Weight", "Partitions before", "after", "Balance", "State"], devRows)));

      var flowRows = (mv.flows || []).map(function (f) {
        var from = (d.devices || []).find(function (x) { return x.dev_id === f.from; });
        var to = (d.devices || []).find(function (x) { return x.dev_id === f.to; });
        return [
          from ? (from.node || from.ip) + "/" + from.device : "dev " + f.from,
          to ? (to.node || to.ip) + "/" + to.device : "dev " + f.to,
          { cls: "num", v: String(f.slots) },
          { cls: "num", v: fmtBytes((tr.bytes_per_slot || 0) * f.slots) }
        ];
      });
      if (flowRows.length) grid.appendChild(card(T("Where the data goes", "数据流向"),
        withTable(flowChart(mv.flows || [], d.devices || [], tr.bytes_per_slot || 0),
          ["From", "To", "Replicas", "Bytes"], flowRows)));

      var disp = d.dispersion_after || d.dispersion_before;
      if (disp) {
        var p = document.createElement("div"); p.className = "lab-b";
        p.textContent = "Region dispersion " + (disp.region_dispersion_pct || 0).toFixed(0) +
          "% · " + disp.zone_overlaps + " partitions with two replicas in one zone";
        grid.appendChild(card(T("Dispersion", "分散度"), p));
      }
      out.appendChild(grid);
    }

    function fmtDuration(s) {
      if (s < 60) return Math.round(s) + "s";
      if (s < 3600) return Math.round(s / 60) + " min";
      return (s / 3600).toFixed(1) + " h";
    }

    function run() {
      var policy = parseInt($("#rs-policy").value || "0", 10);
      setErr("#rs-status", "");
      status.textContent = rs.ops.length ? "Simulating…" : "Reading the ring…";
      var ops = rs.ops.map(function (o) {
        var c = {}; for (var k in o) if (k !== "label") c[k] = o[k];
        return c;
      });
      api("POST", "/lab/api/ring/simulate", {
        policy: policy, ops: ops, rebalance: $("#rs-rebalance").checked
      }).then(function (d) {
        var f = d.fidelity || {};
        var pi = d.policy_info || {};
        status.innerHTML = "";
        status.textContent = (pi.name || "policy " + policy) +
          " · " + (d.ring ? d.ring.partitions : "?") + " partitions × " +
          (d.ring ? d.ring.replicas : "?") + " replicas" +
          (f.faithful === false ? " · movement measured against a re-derived baseline" : "");
        render(d);
      }).catch(function (e) {
        status.textContent = "";
        out.innerHTML = '<p class="err on">' + e.message + "</p>";
      });
    }
    $("#rs-run").addEventListener("click", run);
    $("#rs-policy").addEventListener("change", function () { rs.ops = []; renderOps(); loadTopo(); });

    function loadTopo() {
      var policy = parseInt($("#rs-policy").value || "0", 10);
      api("GET", "/lab/api/ring/topology?policy=" + policy).then(function (d) {
        rs.topo = d;
        rs.devices = (d.topology && d.topology.devices) || [];
        fillTargets();
        run();
      }).catch(function (e) { status.textContent = e.message; });
    }
    loadTopo();
  }

  // ------------------------------------------------------------- Testing
  if (PAGE === "test") {
    var tt = { runs: [], view: "chart", timer: null };
    var ttOut = $("#tt-out"), ttState = $("#tt-state");

    function ttLabel(r) {
      return r.size + " " + r.op + " ×" + r.workers;
    }

    function ttEmpty() {
      var e = document.createElement("div"); e.className = "empty";
      e.textContent = T("No test runs yet.", "还没有测试记录。");
      return e;
    }

    function ttTable(runs) {
      var wrap = document.createElement("div"); wrap.className = "tbl-wrap";
      var t = document.createElement("table"); t.className = "tbl";
      var head = [
        [T("Finished", "完成时间"), ""], [T("Size", "对象大小"), ""], [T("Op", "操作"), ""],
        [T("Workers", "并发数"), "num"], [T("Operations", "操作数"), "num"], [T("Data", "数据量"), "num"],
        [T("Throughput", "吞吐量"), "num"], [T("Bandwidth", "带宽"), "num"],
        [T("Avg latency", "平均延迟"), "num"], [T("Success", "成功率"), "num"]
      ];
      t.innerHTML = "<thead><tr>" + head.map(function (h) {
        return "<th" + (h[1] ? " class='" + h[1] + "'" : "") + ">" + h[0] + "</th>";
      }).join("") + "</tr></thead>";
      var tb = document.createElement("tbody");
      runs.forEach(function (r) {
        var tr = document.createElement("tr");
        [[r.finished, ""], [r.size, ""], [r.op, ""],
         [r.workers, "num"], [r.ops, "num"], [fmtBytes(r.bytes), "num"],
         [r.throughput.toFixed(2) + " op/s", "num"],
         [fmtBytes(r.bandwidth) + "/s", "num"],
         [r.avg_res_ms.toFixed(1) + " ms", "num"],
         [r.success_pct.toFixed(1) + "%", "num"]
        ].forEach(function (c) {
          var td = document.createElement("td");
          if (c[1]) td.className = c[1];
          td.textContent = String(c[0]);
          tr.appendChild(td);
        });
        if (r.success_pct < 100) tr.classList.add("tt-bad");
        tb.appendChild(tr);
      });
      t.appendChild(tb); wrap.appendChild(t);
      return wrap;
    }

    function ttKpis(runs) {
      var bestT = runs.reduce(function (a, r) { return r.throughput > a.throughput ? r : a; }, runs[0]);
      var bestB = runs.reduce(function (a, r) { return r.bandwidth > a.bandwidth ? r : a; }, runs[0]);
      var bestL = runs.reduce(function (a, r) { return r.avg_res_ms < a.avg_res_ms ? r : a; }, runs[0]);
      var ok = runs.filter(function (r) { return r.success_pct >= 99.9; }).length;
      var strip = document.createElement("div"); strip.className = "tt-kpis";
      [
        [T("Peak throughput", "峰值吞吐量"), CHART.fmtNum(bestT.throughput) + " op/s", ttLabel(bestT)],
        [T("Peak bandwidth", "峰值带宽"), fmtBytes(bestB.bandwidth) + "/s", ttLabel(bestB)],
        [T("Lowest latency", "最低延迟"), bestL.avg_res_ms.toFixed(1) + " ms", ttLabel(bestL)],
        [T("Clean runs", "零错误轮次"), ok + " / " + runs.length, T("success ≥ 99.9%", "成功率 ≥ 99.9%")]
      ].forEach(function (k) {
        var card = document.createElement("div"); card.className = "tt-kpi";
        var lab = document.createElement("div"); lab.className = "tt-kpi-l"; lab.textContent = k[0];
        var val = document.createElement("div"); val.className = "tt-kpi-v"; val.textContent = k[1];
        var sub = document.createElement("div"); sub.className = "tt-kpi-s"; sub.textContent = k[2];
        card.appendChild(lab); card.appendChild(val); card.appendChild(sub);
        strip.appendChild(card);
      });
      return strip;
    }

    function ttColChart(title, runs, getV, fmtV, colorIndex) {
      var card = document.createElement("div"); card.className = "mon-card wide tt-chart";
      var h = document.createElement("div"); h.className = "mon-card-h";
      var ti = document.createElement("span"); ti.className = "mon-t"; ti.textContent = title;
      h.appendChild(ti);
      var body = document.createElement("div"); body.className = "mon-body";
      // Horizontal bars: long labels ("64KB write") stay readable; values sit
      // in a right column with theme ink — never cramped canvas text.
      var items = runs.map(function (r) {
        var v = getV(r);
        return {
          label: r.size + " · " + r.op,
          value: v,
          display: fmtV(v),
          tip: ttLabel(r) + " — " + fmtV(v),
          colorIndex: colorIndex != null ? colorIndex : 0
        };
      });
      hbarChart(body, { items: items });
      card.appendChild(h); card.appendChild(body);
      return card;
    }

    function ttCompare(runs) {
      var map = {};
      runs.forEach(function (r) {
        var k = r.size + "|" + r.workers;
        if (!map[k]) map[k] = {};
        map[k][r.op] = r;
      });
      var pairs = Object.keys(map).filter(function (k) {
        return map[k].read && map[k].write;
      }).slice(0, 8);
      if (!pairs.length) return null;
      var card = document.createElement("div"); card.className = "mon-card wide tt-chart";
      var h = document.createElement("div"); h.className = "mon-card-h";
      var ti = document.createElement("span"); ti.className = "mon-t";
      ti.textContent = T("Read vs write throughput", "读 / 写吞吐量对照");
      h.appendChild(ti);
      var body = document.createElement("div"); body.className = "mon-body";
      var items = [];
      pairs.forEach(function (k) {
        var parts = k.split("|");
        ["read", "write"].forEach(function (op, oi) {
          var r = map[k][op];
          items.push({
            label: parts[0] + " ×" + parts[1] + " · " + op,
            value: r.throughput,
            display: CHART.fmtNum(r.throughput) + " op/s",
            tip: ttLabel(r) + " — " + CHART.fmtNum(r.throughput) + " op/s",
            colorIndex: oi
          });
        });
      });
      hbarChart(body, { items: items });
      var leg = document.createElement("div"); leg.className = "tt-leg";
      leg.innerHTML = '<span class="tt-leg-i mon-s1"></span>' + T("read", "读") +
        '<span class="tt-leg-i mon-s2"></span>' + T("write", "写");
      body.appendChild(leg);
      card.appendChild(h); card.appendChild(body);
      return card;
    }

    function ttChart() {
      if (!tt.runs.length) return ttEmpty();
      var runs = tt.runs.slice(0, 16).reverse();
      var box = document.createElement("div"); box.className = "tt-dash";
      box.appendChild(ttKpis(tt.runs));
      var grid = document.createElement("div"); grid.className = "tt-grid";
      grid.appendChild(ttColChart(
        T("Throughput (op/s)", "吞吐量（op/s）"), runs,
        function (r) { return r.throughput; },
        function (v) { return CHART.fmtNum(v); }, 0
      ));
      grid.appendChild(ttColChart(
        T("Bandwidth", "带宽"), runs,
        function (r) { return r.bandwidth; },
        function (v) { return fmtBytes(v) + "/s"; }, 1
      ));
      grid.appendChild(ttColChart(
        T("Average latency (ms)", "平均延迟（毫秒）"), runs,
        function (r) { return r.avg_res_ms; },
        function (v) { return v.toFixed(1); }, 2
      ));
      var cmp = ttCompare(tt.runs);
      if (cmp) grid.appendChild(cmp);
      box.appendChild(grid);

      var det = document.createElement("details"); det.className = "tt-data";
      var sum = document.createElement("summary");
      sum.textContent = T("Data table", "数据表");
      det.appendChild(sum);
      det.appendChild(ttTable(tt.runs));
      box.appendChild(det);
      return box;
    }

    function ttRender() {
      ttOut.innerHTML = "";
      if (!tt.runs.length && tt.view !== "table") {
        ttOut.appendChild(ttEmpty());
        return;
      }
      if (tt.view === "table") {
        ttOut.appendChild(tt.runs.length ? ttTable(tt.runs) : ttEmpty());
      } else {
        ttOut.appendChild(ttChart());
      }
    }

    function ttLoad() {
      return api("GET", "/test/api/runs").then(function (d) {
        tt.runs = d.runs || [];
        if (d.running) {
          ttState.textContent = T("Running ", "正在运行 ") + d.running.task + "…";
          $("#tt-run").disabled = true;
          if (!tt.timer) tt.timer = setInterval(ttLoad, 3000);
        } else {
          ttState.textContent = "";
          $("#tt-run").disabled = false;
          if (tt.timer) { clearInterval(tt.timer); tt.timer = null; }
        }
        ttRender();
      }).catch(function (e) {
        ttOut.innerHTML = '<p class="err on">' + e.message + "</p>";
      });
    }

    $$("#tt-view .seg-b").forEach(function (b) {
      b.addEventListener("click", function () {
        $$("#tt-view .seg-b").forEach(function (x) { x.classList.remove("active"); });
        b.classList.add("active");
        tt.view = b.dataset.view;
        ttRender();
      });
    });

    $("#tt-run").addEventListener("click", function () {
      var body = {
        size: $("#tt-size").value,
        op: $("#tt-op").value,
        workers: parseInt($("#tt-workers").value, 10) || 1,
        runtime: parseInt($("#tt-runtime").value, 10) || 30,
        objects: parseInt($("#tt-objects").value, 10) || 500
      };
      $("#tt-run").disabled = true;
      ttState.textContent = T("Starting…", "启动中…");
      api("POST", "/test/api/run", body)
        .then(function () { ttLoad(); })
        .catch(function (e) {
          $("#tt-run").disabled = false;
          ttState.textContent = e.message;
        });
    });

    document.addEventListener("sc-theme", function () { ttRender(); });
    ttLoad();
  }

  // ---------------------------------------------------- Policy Economist
  // Server-rendered /lab/policy already paints charts. The form+API path below
  // only runs when the interactive shell (#pe-out) is present.
  if ((PAGE === "lab-policy" || PAGE === "lab-economist") && $("#pe-out") && $("#pe-run")) {
    var peOut = $("#pe-out");

    function num(id, dflt) { var v = parseFloat($(id).value); return isFinite(v) ? v : dflt; }

    function cell(v, cls) { return { v: v, cls: cls || "" }; }

    function peTable(rows) {
      var wrap = document.createElement("div"); wrap.className = "tbl-wrap";
      var t = document.createElement("table"); t.className = "tbl pe-tbl";
      // Candidates are columns: the point is comparing them, not listing them.
      var metrics = [
        [T("Storage amplification", "存储放大率"), function (r) { return r.amplification.toFixed(2) + "×"; }],
        [T("Raw capacity needed", "所需裸容量"), function (r) { return CHART.fmtNum(r.raw_needed_tb) + " TB"; }],
        [T("Minimum devices", "最少设备数"), function (r) { return String(r.min_devices); }],
        [T("Write fanout", "写入扇出"), function (r) { return String(r.write_fanout); }],
        [T("Write quorum", "写入法定数"), function (r) { return String(r.write_quorum); }],
        [T("Write margin", "写入余量"), function (r) {
          return r.write_margin + (r.write_margin === 0 ? T("  (none)", "（无）") : "");
        }],
        [T("Devices to read", "读取所需设备"), function (r) { return String(r.read_min_devices); }],
        [T("Survives losing", "可损失设备"), function (r) { return String(r.tolerates_loss); }],
        [T("Rebuild reads", "重建读取量"), function (r) { return CHART.fmtNum(r.rebuild_read_tb) + " TB"; }],
        [T("Worst repair time", "最坏修复时间"), function (r) { return r.repair_hours.toFixed(1) + " h"; }],
        [T("Durability", "耐久性"), function (r) { return r.durability_nines.toFixed(1) + T(" nines", " 个 9"); }],
        [T("5-year disk cost", "五年磁盘成本"), function (r) { return CHART.fmtNum(r.tco); }]
      ];
      var head = "<thead><tr><th>" + T("Metric", "指标") + "</th>" +
        rows.map(function (r) {
          return "<th class='num" + (r.feasible ? "" : " pe-x") + "'>" + r.label + "</th>";
        }).join("") + "</tr></thead>";
      t.innerHTML = head;
      var tb = document.createElement("tbody");
      metrics.forEach(function (m) {
        var tr = document.createElement("tr");
        var th = document.createElement("td"); th.textContent = m[0]; tr.appendChild(th);
        rows.forEach(function (r) {
          var td = document.createElement("td"); td.className = "num" + (r.feasible ? "" : " pe-x");
          td.textContent = m[1](r);
          tr.appendChild(td);
        });
        tb.appendChild(tr);
      });
      // Whether each candidate meets the stated constraints.
      [[T("Meets durability", "满足耐久目标"), "meets_durability"],
       [T("Meets repair time", "满足修复时间"), "meets_repair_time"],
       [T("Meets loss tolerance", "满足容错要求"), "meets_node_loss"]
      ].forEach(function (chk) {
        var tr = document.createElement("tr");
        var th = document.createElement("td"); th.textContent = chk[0]; tr.appendChild(th);
        rows.forEach(function (r) {
          var td = document.createElement("td");
          td.className = "num " + (r[chk[1]] ? "pe-ok" : "pe-no") + (r.feasible ? "" : " pe-x");
          td.textContent = r[chk[1]] ? "✓" : "✗";
          tr.appendChild(td);
        });
        tb.appendChild(tr);
      });
      t.appendChild(tb); wrap.appendChild(t);
      return wrap;
    }

    // Candidates drawn as small multiples: one mini bar chart per metric so
    // magnitudes are comparable within a metric, every bar carries its exact
    // value, and the direction of "better" is stated instead of implied.
    function peCharts(rows) {
      var box = document.createElement("div"); box.className = "pe-charts";
      // legend: one colour per candidate, infeasible ones marked
      var lg = document.createElement("div"); lg.className = "pe-legend";
      rows.forEach(function (r, i) {
        var it = document.createElement("span"); it.className = "mon-leg-i";
        var sw = document.createElement("i"); sw.className = "pe-sw mon-s" + ((i % 6) + 1);
        var nm = document.createElement("b"); nm.textContent = r.label;
        it.appendChild(sw); it.appendChild(nm);
        if (!r.feasible) {
          var x = document.createElement("em"); x.className = "pe-infeasible";
          x.textContent = T("infeasible here", "本集群不可行");
          it.appendChild(x);
        }
        lg.appendChild(it);
      });
      box.appendChild(lg);

      var metrics = [
        { t: T("Storage amplification", "存储放大率"), dir: -1, v: function (r) { return r.amplification; }, f: function (r) { return r.amplification.toFixed(2) + "×"; } },
        { t: T("Raw capacity needed", "所需裸容量"), dir: -1, v: function (r) { return r.raw_needed_tb; }, f: function (r) { return CHART.fmtNum(r.raw_needed_tb) + " TB"; } },
        { t: T("Minimum devices", "最少设备数"), dir: -1, v: function (r) { return r.min_devices; }, f: function (r) { return String(r.min_devices); } },
        { t: T("Write fanout", "写入扇出"), dir: -1, v: function (r) { return r.write_fanout; }, f: function (r) { return String(r.write_fanout); } },
        { t: T("Write quorum", "写入法定数"), dir: 0, v: function (r) { return r.write_quorum; }, f: function (r) { return String(r.write_quorum); } },
        { t: T("Write margin", "写入余量"), dir: 1, v: function (r) { return r.write_margin; }, f: function (r) { return String(r.write_margin) + (r.write_margin === 0 ? T(" (none)", "（无）") : ""); } },
        { t: T("Devices to read", "读取所需设备"), dir: -1, v: function (r) { return r.read_min_devices; }, f: function (r) { return String(r.read_min_devices); } },
        { t: T("Survives losing", "可损失设备"), dir: 1, v: function (r) { return r.tolerates_loss; }, f: function (r) { return String(r.tolerates_loss); } },
        { t: T("Rebuild reads", "重建读取量"), dir: -1, v: function (r) { return r.rebuild_read_tb; }, f: function (r) { return CHART.fmtNum(r.rebuild_read_tb) + " TB"; } },
        { t: T("Worst repair time", "最坏修复时间"), dir: -1, v: function (r) { return r.repair_hours; }, f: function (r) { return r.repair_hours.toFixed(1) + " h"; } },
        { t: T("Durability", "耐久性"), dir: 1, v: function (r) { return r.durability_nines; }, f: function (r) { return r.durability_nines.toFixed(1) + T(" nines", " 个 9"); } },
        { t: T("5-year disk cost", "五年磁盘成本"), dir: -1, v: function (r) { return r.tco; }, f: function (r) { return CHART.fmtNum(r.tco); } }
      ];
      var grid = document.createElement("div"); grid.className = "pe-mgrid";
      metrics.forEach(function (m) {
        var cardEl = document.createElement("div"); cardEl.className = "pe-metric";
        var h = document.createElement("div"); h.className = "pe-metric-t";
        var tt = document.createElement("b"); tt.textContent = m.t;
        h.appendChild(tt);
        if (m.dir !== 0) {
          var dd = document.createElement("i"); dd.className = "pe-dir";
          dd.textContent = m.dir > 0 ? T("higher is better", "越高越好") : T("lower is better", "越低越好");
          h.appendChild(dd);
        }
        cardEl.appendChild(h);
        var max = 0;
        rows.forEach(function (r) { max = Math.max(max, Math.abs(m.v(r) || 0)); });
        // best feasible value gets the mark
        var best = null;
        rows.forEach(function (r) {
          if (!r.feasible || m.dir === 0) return;
          var v = m.v(r);
          if (best === null || (m.dir > 0 ? v > best : v < best)) best = v;
        });
        rows.forEach(function (r, i) {
          var v = m.v(r) || 0;
          var row = document.createElement("div");
          row.className = "pe-brow" + (r.feasible ? "" : " pe-dim");
          var lab = document.createElement("span"); lab.className = "pe-blab"; lab.textContent = r.label;
          var track = document.createElement("div"); track.className = "pe-btrack";
          var bar = document.createElement("div");
          bar.className = "pe-bbar mon-s" + ((i % 6) + 1);
          bar.style.width = (max ? Math.max(100 * Math.abs(v) / max, 2) : 2) + "%";
          track.appendChild(bar);
          var val = document.createElement("span");
          val.className = "pe-bval" + (r.feasible && best !== null && v === best ? " best" : "");
          val.textContent = m.f(r) + (r.feasible && best !== null && v === best ? " ●" : "");
          if (r.feasible && best !== null && v === best) val.title = T("best of the feasible candidates", "可行方案中的最优值");
          row.appendChild(lab); row.appendChild(track); row.appendChild(val);
          cardEl.appendChild(row);
        });
        grid.appendChild(cardEl);
      });
      box.appendChild(grid);

      // Constraint verdicts: same ✓/✗ facts as the table's last three rows.
      var cons = document.createElement("div"); cons.className = "pe-cons";
      var ch = document.createElement("div"); ch.className = "pe-metric-t";
      var cb = document.createElement("b"); cb.textContent = T("Meets the stated constraints", "是否满足设定约束");
      ch.appendChild(cb); cons.appendChild(ch);
      [[T("Durability target", "耐久目标"), "meets_durability"],
       [T("Repair-time cap", "修复时间上限"), "meets_repair_time"],
       [T("Loss tolerance", "容错要求"), "meets_node_loss"]
      ].forEach(function (chk) {
        var row = document.createElement("div"); row.className = "pe-conrow";
        var lab = document.createElement("span"); lab.className = "pe-blab"; lab.textContent = chk[0];
        row.appendChild(lab);
        var chips = document.createElement("div"); chips.className = "pe-chips";
        rows.forEach(function (r) {
          var c = document.createElement("span");
          c.className = "pe-chip " + (r[chk[1]] ? "ok" : "no") + (r.feasible ? "" : " pe-dim");
          c.textContent = (r[chk[1]] ? "✓ " : "✗ ") + r.label;
          chips.appendChild(c);
        });
        row.appendChild(chips);
        cons.appendChild(row);
      });
      box.appendChild(cons);

      // The numbers, exactly as before, one click away.
      var det = document.createElement("details"); det.className = "rs-det";
      var sum = document.createElement("summary"); sum.textContent = T("Data table", "查看数据表");
      det.appendChild(sum); det.appendChild(peTable(rows));
      box.appendChild(det);
      return box;
    }

    function peNotes(rows) {
      var box = document.createElement("div"); box.className = "pe-notes";
      rows.forEach(function (r) {
        if (!r.reasons.length) return;
        var p = document.createElement("p");
        p.className = r.feasible ? "note" : "err on";
        p.textContent = r.label + " — " + r.reasons.map(function (x) {
          if (x.code === "needs_devices") {
            return T("needs " + x.need + " devices in distinct failure domains; this cluster has " + x.have,
                     "需要 " + x.need + " 个分处不同故障域的设备，本集群只有 " + x.have + " 个");
          }
          if (x.code === "fewer_zones") {
            return T("more fragments (" + x.need + ") than zones (" + x.zones + "), so some zones hold several",
                     "分片数（" + x.need + "）多于 zone 数（" + x.zones + "），部分 zone 会放多个分片");
          }
          if (x.code === "no_write_margin") {
            return T("write quorum equals the fanout — one node down stops writes",
                     "写入法定数等于扇出 —— 一个节点下线就无法写入");
          }
          return x.text || x.code;
        }).join("; ");
        box.appendChild(p);
      });
      return box;
    }

    function peRun() {
      var body = {
        raw_tb: num("#pe-raw", 1000),
        disk_cost_per_tb_year: num("#pe-cost", 20),
        cross_rack_gbps: num("#pe-bw", 10),
        target_durability_nines: num("#pe-nines", 11),
        max_repair_hours: num("#pe-repair", 8),
        tolerate_node_loss: num("#pe-loss", 1),
        years: num("#pe-years", 5),
        node_count: peCluster.node_count || 3,
        devices_total: peCluster.devices_total || 3,
        zone_count: peCluster.zone_count || 3,
        device_tb: peCluster.device_tb || 1,
        candidates: [
          { kind: "replication", replicas: 3 },
          { kind: "replication", replicas: 2 },
          { kind: "ec", k: 2, m: 1 },
          { kind: "ec", k: 4, m: 2 },
          { kind: "ec", k: 8, m: 3 }
        ]
      };
      api("POST", "/lab/api/policy/compare", body).then(function (d) {
        peOut.innerHTML = "";
        peOut.appendChild(peCharts(d.rows || []));
        peOut.appendChild(peNotes(d.rows || []));
      }).catch(function (e) {
        peOut.innerHTML = '<p class="err on">' + e.message + "</p>";
      });
    }

    var peCluster = {};
    api("GET", "/lab/api/policy/defaults").then(function (d) {
      peCluster = d.cluster || {};
      $("#pe-cluster").textContent =
        T("This cluster: ", "本集群：") + peCluster.node_count + T(" nodes, ", " 个节点，") +
        peCluster.devices_total + T(" devices, ", " 个设备，") +
        peCluster.zone_count + T(" zones, ", " 个 zone，") +
        peCluster.device_tb + T(" TB per device.", " TB/设备。");
      peRun();
    }).catch(function (e) { $("#pe-cluster").textContent = e.message; });

    $("#pe-run").addEventListener("click", peRun);
  }

  // ---------------------------------------------------- Tombstone Museum
  // The page is already complete without this: the report is server-rendered
  // and every mark drawn here also sits in the timeline table below it. The
  // swimlane reads the same payload out of the document rather than asking for
  // it again, because rebuilding it costs a fan-out across every node.
  if (PAGE === "lab-tombstone") {
    var tmHost = $("#tm-lane"), tmSrc = $("#tm-data"), tmData = null;
    if (tmHost && tmSrc) {
      try { tmData = JSON.parse(tmSrc.textContent); } catch (e) { tmData = null; }
    }
    if (tmData) {
      var tmDraw = function () { CHART.swimlane(tmHost, tmData); };
      tmDraw();
      var tmTimer = null;
      window.addEventListener("resize", function () {
        clearTimeout(tmTimer); tmTimer = setTimeout(tmDraw, 200);
      });
    }
  }
})();

/* ---------------------------------------------------- API Parity family bars */
(function () {
  "use strict";
  var src = document.getElementById("sh-data");
  var host = document.getElementById("sh-bars");
  if (!src || !host) return;
  var d;
  try { d = JSON.parse(src.textContent); } catch (e) { return; }
  var fams = (d.families || []).filter(function (f) {
    return (f.comparable || 0) + (f.suppressed || 0) > 0;
  });
  if (!fams.length) return;
  function tipShow(x, y, html) {
    if (window.ixTipShow) { window.ixTipShow(x, y, html); return; }
    var el = document.querySelector(".ix-tip");
    if (!el) { el = document.createElement("div"); el.className = "ix-tip"; document.body.appendChild(el); }
    el.hidden = false; el.textContent = html;
    el.style.left = Math.max(4, x + 12) + "px";
    el.style.top = Math.max(4, y + 12) + "px";
  }
  function tipHide() {
    if (window.ixTipHide) { window.ixTipHide(); return; }
    var el = document.querySelector(".ix-tip"); if (el) el.hidden = true;
  }
  host.innerHTML = "";
  var box = document.createElement("div"); box.className = "ix-hbar sh-hbar";
  var max = 1;
  fams.forEach(function (f) { max = Math.max(max, (f.comparable || 0) + (f.suppressed || 0)); });
  fams.forEach(function (f) {
    var comparable = f.comparable || 0, sup = f.suppressed || 0, diff = f.differing || 0;
    var same = Math.max(comparable - diff, 0), total = comparable + sup;
    var row = document.createElement("div"); row.className = "ix-hbar-row";
    var lab = document.createElement("span"); lab.className = "ix-hbar-l"; lab.textContent = f.label;
    var track = document.createElement("div"); track.className = "ix-hbar-track sh-seg-track";
    [[same, "sh-seg-ok", "same"], [diff, "sh-seg-diff", "diff"], [sup, "sh-seg-sup", "noise"]].forEach(function (seg) {
      if (!seg[0]) return;
      var fill = document.createElement("div");
      fill.className = "sh-seg " + seg[1];
      fill.style.flex = String(seg[0]);
      fill.style.width = Math.max(1.5, 100 * seg[0] / max) + "%";
      fill.dataset.tip = f.label + " · " + seg[2] + ": " + seg[0];
      track.appendChild(fill);
    });
    var val = document.createElement("span"); val.className = "ix-hbar-v"; val.textContent = comparable + " / " + total;
    row.appendChild(lab); row.appendChild(track); row.appendChild(val);
    row.addEventListener("mousemove", function (ev) {
      var t = (ev.target.dataset && ev.target.dataset.tip) || (f.label + ": " + comparable + "/" + total);
      tipShow(ev.clientX, ev.clientY, t);
    });
    row.addEventListener("mouseleave", tipHide);
    box.appendChild(row);
  });
  host.appendChild(box);
})();
/* ------------------------------------------------------ API Parity bars: end */



/* ------------------------------------------- warehouse expiry lane (HTML) */
(function () {
  "use strict";
  var host = document.getElementById("wh-exp-lane");
  var src = document.getElementById("wh-exp-data");
  if (!host || !src) return;
  var rows;
  try { rows = JSON.parse(src.textContent); } catch (e) { return; }
  if (!rows || !rows.length) return;
  var ZH = document.documentElement.lang === "zh-CN";
  function T(en, zh) { return ZH ? zh : en; }
  function left(s) {
    if (s <= 0) return T("gone", "已过期");
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return ZH ? (d + " 天 " + h + " 小时") : (d + "d " + h + "h");
    if (h) return ZH ? (h + " 小时 " + m + " 分") : (h + "h " + m + "m");
    return ZH ? (m + " 分") : (m + "m");
  }
  function tail(p) { var i = p.lastIndexOf("/"); return i < 0 ? p : p.slice(i + 1); }
  rows = rows.slice().sort(function (a, b) { return a.at - b.at; }).slice(0, 16);
  function tipShow(x, y, html) {
    if (window.ixTipShow) { window.ixTipShow(x, y, html); return; }
    var el = document.querySelector(".ix-tip");
    if (!el) { el = document.createElement("div"); el.className = "ix-tip"; document.body.appendChild(el); }
    el.hidden = false; el.textContent = html;
    el.style.left = Math.max(4, x + 12) + "px"; el.style.top = Math.max(4, y + 12) + "px";
  }
  function tipHide() {
    if (window.ixTipHide) { window.ixTipHide(); return; }
    var el = document.querySelector(".ix-tip"); if (el) el.hidden = true;
  }
  function draw() {
    host.innerHTML = "";
    var now = Math.floor(Date.now() / 1000);
    var maxLeft = 1;
    rows.forEach(function (r) { maxLeft = Math.max(maxLeft, Math.max(0, r.at - now)); });
    var box = document.createElement("div"); box.className = "ix-hbar wh-exp";
    rows.forEach(function (r) {
      var rem = Math.max(0, r.at - now);
      var row = document.createElement("div"); row.className = "ix-hbar-row" + (rem < 3600 ? " soon" : "");
      var lab = document.createElement("span"); lab.className = "ix-hbar-l"; lab.textContent = tail(r.path);
      var track = document.createElement("div"); track.className = "ix-hbar-track";
      var fill = document.createElement("div"); fill.className = "ix-hbar-fill" + (rem < 3600 ? " warn" : "");
      fill.style.width = Math.max(2, 100 * rem / maxLeft) + "%";
      track.appendChild(fill);
      var val = document.createElement("span"); val.className = "ix-hbar-v"; val.textContent = left(rem);
      row.appendChild(lab); row.appendChild(track); row.appendChild(val);
      row.addEventListener("mousemove", function (ev) { tipShow(ev.clientX, ev.clientY, r.path + " · " + left(rem)); });
      row.addEventListener("mouseleave", tipHide);
      box.appendChild(row);
    });
    host.appendChild(box);
  }
  draw();
  var t = null;
  window.addEventListener("resize", function () { clearTimeout(t); t = setTimeout(draw, 200); });
  setInterval(draw, 30000);
})();



/* ------------------------------------------------- chaos arcade [ca-*] */
/* Owned by src/chaos.rs. Its own closure rather than a branch inside the main
   one, because it is appended after that file's IIFE has already closed.

   The page is complete without this: the form is a real POST, the report is
   server-rendered, and an in-flight run carries a refresh link plus a <noscript>
   line saying so. All this adds is that an operator watching a 150-second
   experiment does not have to keep clicking. */
(function () {
  "use strict";
  var page = document.body.dataset.page || "";
  if (page !== "lab-chaos") return;
  var host = document.querySelector("[data-chaos-live]");
  if (!host) return;

  var live = document.querySelector(".ca-live");
  var zh = document.documentElement.lang === "zh-CN";
  var stalled = 0;

  function tick() {
    fetch("/lab/api/chaos/status", { headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) { stalled++; return schedule(); }
        // The report is rendered by the server, so the only useful thing to do
        // when the run ends is to go and get it.
        if (!d.live) { location.reload(); return; }
        if (live && d.step) {
          live.firstChild.nodeValue =
            (zh ? "实验进行中：" : "Experiment in flight: ") + d.step + " · " +
            d.elapsed + (zh ? " 秒 " : " s ");
        }
        schedule();
      })
      .catch(function () { stalled++; schedule(); });
  }
  function schedule() {
    // Give up quietly rather than hammering a console that is not answering;
    // the refresh link on the page still works.
    if (stalled > 5) return;
    setTimeout(tick, 4000);
  }
  schedule();
})();
/* ------------------------------------------- end chaos arcade [ca-*] */
