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
  }

  var themeForm = $(".theme-seg");
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

  // ------------------------------------------------------------ objects page

  var filter = $("#filter");
  if (filter) filter.addEventListener("input", function () {
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
  // Hand-drawn SVG kit, shared by Monitor and the Lab surfaces. Colours
  // live in CSS (.mon-s1..6) so everything re-themes with no re-render.
  var SVGNS = "http://www.w3.org/2000/svg";
  // Series colours live in CSS (.mon-s1..6) so they follow the theme with
  // no re-render. They cannot be read from JS: getPropertyValue returns the
  // literal "light-dark(a, b)" string, not the resolved colour.

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

  function lineChart(body, resp, unit) {
    var series = (resp.series || []).filter(function (s) { return s.points && s.points.length; });
    var legend = [];
    if (!series.length) { body.innerHTML = '<div class="mon-empty">' + T("No data in range", "该区间内没有数据") + '</div>'; return legend; }
    var W = Math.max(body.clientWidth || 600, 260), H = 172;
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
    // Size the label gutter to the widest tick actually rendered: a fixed
    // gutter clips long labels ("110 MiB/s") against the left edge.
    var tickLabels = [];
    for (var ti = 0; ti <= 4; ti++) tickLabels.push(fmtVal(unit, minV + (maxV - minV) * (ti / 4)));
    var widest = tickLabels.reduce(function (m, s) { return Math.max(m, s.length); }, 0);
    var padL = Math.min(Math.max(34, Math.ceil(widest * 5.9) + 12), Math.round(W * 0.34));
    var x = function (t) { return padL + (maxT === minT ? 0 : (t - minT) / (maxT - minT)) * (W - padL - padR); };
    var y = function (v) { return padT + (1 - (v - minV) / (maxV - minV)) * (H - padT - padB); };
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, class: "mon-svg" });
    // horizontal gridlines + y labels
    var i, gy, yv;
    for (i = 0; i <= 4; i++) {
      yv = minV + (maxV - minV) * (i / 4); gy = y(yv);
      s.appendChild(svg("line", { x1: padL, y1: gy, x2: W - padR, y2: gy, class: "mon-grid-l" }));
      var lbl = svg("text", { x: padL - 6, y: gy + 3, class: "mon-axis", "text-anchor": "end" });
      lbl.textContent = tickLabels[i]; s.appendChild(lbl);
    }
    // x time ticks
    for (i = 0; i <= 3; i++) {
      var tt = minT + (maxT - minT) * (i / 3), gx = x(tt);
      var xl = svg("text", { x: gx, y: H - 6, class: "mon-axis", "text-anchor": i === 0 ? "start" : (i === 3 ? "end" : "middle") });
      xl.textContent = hhmm(tt); s.appendChild(xl);
    }
    // series polylines (break on null)
    series.forEach(function (ser, si) {
      var cls = "mon-s" + ((si % 6) + 1), d = "", pen = false, last = null;
      ser.points.forEach(function (p) {
        if (p[1] == null) { pen = false; return; }
        d += (pen ? " L" : " M") + x(p[0]).toFixed(1) + " " + y(p[1]).toFixed(1);
        pen = true; last = p[1];
      });
      if (d) s.appendChild(svg("path", { d: d.trim(), class: "mon-ser " + cls }));
      legend.push({ name: ser.name, cls: cls, last: last, unit: unit });
    });
    body.innerHTML = ""; body.appendChild(s);
    return legend;
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
    var lanes = d.lanes || [], events = d.events || [];
    host.innerHTML = "";
    if (!lanes.length || !events.length) return;
    var known = Object.create(null);
    lanes.forEach(function (l) { known[l.id] = true; });
    var minT = Infinity, maxT = -Infinity;
    events.forEach(function (e) {
      if (e.t < minT) minT = e.t;
      if (e.t > maxT) maxT = e.t;
    });
    // Only outages that touch this object's own history belong on this axis;
    // one from yesterday would squash everything that matters into a pixel.
    var bands = (d.offline || []).filter(function (b) {
      return known[b.node] && b.to >= minT - 60 && b.from <= maxT + 60;
    });
    bands.forEach(function (b) {
      if (b.from < minT) minT = b.from;
      if (b.to > maxT) maxT = b.to;
    });
    if (maxT - minT < 120) { var mid = (maxT + minT) / 2; minT = mid - 60; maxT = mid + 60; }
    var span = maxT - minT;
    minT -= span * 0.04; maxT += span * 0.04; span = maxT - minT;

    var W = Math.max(host.clientWidth || 720, 320);
    var rowH = 26, padT = 12, padB = 26, padR = 14;
    var widest = lanes.reduce(function (m, l) { return Math.max(m, l.label.length); }, 6);
    var padL = Math.min(Math.max(52, Math.ceil(widest * 6.6) + 14), Math.round(W * 0.34));
    var H = padT + lanes.length * rowH + padB;
    var x = function (t) { return padL + (t - minT) / span * (W - padL - padR); };
    var row = function (i) { return padT + i * rowH + rowH / 2; };
    // UTC, matching the tables below: the storage nodes and the service log are
    // both UTC, and a swimlane on browser-local time would put the delete an
    // hour away from the same delete in the row underneath it.
    var clock = function (t) {
      var u = new Date(t * 1000);
      return pad2(u.getUTCHours()) + ":" + pad2(u.getUTCMinutes()) +
        (span < 5400 ? ":" + pad2(u.getUTCSeconds()) : "");
    };
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, class: "tm-svg" });

    var index = Object.create(null);
    lanes.forEach(function (l, i) {
      index[l.id] = i;
      var y = row(i);
      s.appendChild(svg("line", {
        x1: padL, y1: y, x2: W - padR, y2: y,
        class: "tm-track" + (l.role === "client" ? " client" : "")
      }));
      var lab = svg("text", {
        x: padL - 8, y: y + 3.5, "text-anchor": "end",
        class: "tm-lane-l" + (l.role === "client" ? " client" : (l.primary ? "" : " handoff"))
      });
      lab.textContent = l.label;
      s.appendChild(lab);
    });

    // Outages first, so every mark reads on top of the band it happened inside.
    bands.forEach(function (b) {
      var y = row(index[b.node]) - rowH / 2 + 2;
      var x1 = Math.max(x(b.from), padL), x2 = Math.min(x(b.to), W - padR);
      var g = svg("g", {});
      g.appendChild(svg("rect", { x: x1, y: y, width: Math.max(x2 - x1, 1), height: rowH - 4, class: "tm-band" }));
      g.appendChild(svg("line", { x1: x1, y1: y, x2: x1, y2: y + rowH - 4, class: "tm-band-e" }));
      g.appendChild(svg("line", { x1: x2, y1: y, x2: x2, y2: y + rowH - 4, class: "tm-band-e" }));
      var bt = svg("title", {});
      bt.textContent = b.node + T(" offline ", " 离线 ") + clock(b.from) + "-" + clock(b.to);
      g.appendChild(bt);
      s.appendChild(g);
    });

    if (d.delete_ts != null) {
      var dx = x(d.delete_ts);
      s.appendChild(svg("line", { x1: dx, y1: padT - 4, x2: dx, y2: H - padB + 2, class: "tm-rule" }));
      // Flip the label inside the frame when the delete lands near the right
      // edge, so the word is never shaved off by the viewBox.
      var flip = dx > W - padR - 46;
      var dl = svg("text", {
        x: dx + (flip ? -5 : 5), y: padT + 3, class: "tm-rule-l",
        "text-anchor": flip ? "end" : "start"
      });
      dl.textContent = T("delete", "删除");
      s.appendChild(dl);
    }

    events.forEach(function (e) {
      var i = index[e.lane];
      if (i === undefined) return;
      var cx = x(e.t), cy = row(i), mark;
      if (e.kind === "tombstone") {
        // A delete is struck out, not just recoloured: the shape carries it.
        mark = svg("path", {
          d: "M" + (cx - 4) + " " + (cy - 4) + "L" + (cx + 4) + " " + (cy + 4) +
             "M" + (cx + 4) + " " + (cy - 4) + "L" + (cx - 4) + " " + (cy + 4),
          class: "tm-ev-tombstone"
        });
      } else if (e.kind === "meta") {
        mark = svg("circle", { cx: cx, cy: cy, r: 3.5, class: "tm-ev-meta" });
      } else {
        mark = svg("circle", { cx: cx, cy: cy, r: 4, class: "tm-ev-" + e.kind });
      }
      var tt = svg("title", {});
      tt.textContent = clock(e.t) + "  " + e.label;
      mark.appendChild(tt);
      s.appendChild(mark);
    });

    for (var ti = 0; ti <= 3; ti++) {
      var tt2 = minT + span * (ti / 3);
      var xl = svg("text", {
        x: x(tt2), y: H - 8, class: "tm-axis",
        "text-anchor": ti === 0 ? "start" : (ti === 3 ? "end" : "middle")
      });
      xl.textContent = clock(tt2);
      s.appendChild(xl);
    }
    host.appendChild(s);
  }

  var CHART = {
    SVGNS: SVGNS, svg: svg, fmtNum: fmtNum, fmtDur: fmtDur, fmtVal: fmtVal,
    hhmm: hhmm, hhmmss: hhmmss, lineChart: lineChart, statTile: statTile,
    logView: logView, swimlane: swimlane
  };

  if (PAGE === "monitor") {
    var mon = { dashes: [], active: 0, range: 3600, timer: null };
    var grid = $("#mon-grid"), tabs = $("#mon-tabs");
    var rangeSel = $("#mon-range"), refreshBtn = $("#mon-refresh");
    function paint(p, card, resp) {
      var body = card.querySelector(".mon-body"), leg = card.querySelector(".mon-legend");
      if (leg) leg.innerHTML = "";
      if (resp.error) { body.innerHTML = '<div class="mon-empty">' + T("Unavailable", "暂不可用") + '</div>'; return; }
      if (p.kind === "stat") { statTile(body, resp, p.unit); return; }
      if (p.kind === "logs") { logView(body, resp); return; }
      var legend = lineChart(body, resp, p.unit);
      if (leg && legend.length) {
        legend.forEach(function (l) {
          var it = document.createElement("span"); it.className = "mon-leg-i";
          var sw = document.createElement("i"); sw.className = l.cls;
          var nm = document.createElement("b"); nm.textContent = l.name;
          var vv = document.createElement("em"); vv.textContent = fmtVal(l.unit, l.last);
          it.appendChild(sw); it.appendChild(nm); it.appendChild(vv); leg.appendChild(it);
        });
      }
    }

    function fetchPanel(p, card) {
      api("GET", "/monitor/api/panel?id=" + encodeURIComponent(p.id) + "&range=" + mon.range)
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
      return card;
    }

    function loadDash() {
      var d = mon.dashes[mon.active]; if (!d) return;
      grid.innerHTML = "";
      d.panels.forEach(function (p) {
        var card = cardShell(p);
        grid.appendChild(card);
        fetchPanel(p, card);
      });
    }
    function refresh() {
      var d = mon.dashes[mon.active]; if (!d) return;
      d.panels.forEach(function (p) {
        var card = grid.querySelector('.mon-card[data-panel="' + p.id + '"]');
        if (card) fetchPanel(p, card);
      });
    }

    function buildTabs() {
      tabs.innerHTML = "";
      mon.dashes.forEach(function (d, i) {
        var b = document.createElement("button");
        b.type = "button"; b.className = "seg-b" + (i === mon.active ? " active" : "");
        b.textContent = d.title;
        b.addEventListener("click", function () {
          mon.active = i;
          $$(".seg-b", tabs).forEach(function (x, xi) { x.classList.toggle("active", xi === i); });
          loadDash();
        });
        tabs.appendChild(b);
      });
    }

    if (rangeSel) rangeSel.addEventListener("change", function () { mon.range = parseInt(rangeSel.value, 10) || 3600; loadDash(); });
    if (refreshBtn) refreshBtn.addEventListener("click", refresh);
    var rzTimer = null;
    window.addEventListener("resize", function () { clearTimeout(rzTimer); rzTimer = setTimeout(refresh, 250); });

    api("GET", "/monitor/api/dash").then(function (d) {
      mon.dashes = d.dashboards || [];
      buildTabs();
      loadDash();
      mon.timer = setInterval(refresh, 30000);
    }).catch(function () {
      grid.innerHTML = '<div class="mon-empty">' + T("Monitoring is unavailable right now.", "监控暂时不可用。") + '</div>';
    });
  }

  // ------------------------------------------------------------- RingScope
  if (PAGE === "lab-ring") {
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
        table(["Device", "Zone", "Weight", "Partitions before", "after", "Balance", "State"], devRows)));

      var flows = (mv.flows || []).map(function (f) {
        var from = (d.devices || []).find(function (x) { return x.dev_id === f.from; });
        var to = (d.devices || []).find(function (x) { return x.dev_id === f.to; });
        return [
          from ? (from.node || from.ip) + "/" + from.device : "dev " + f.from,
          to ? (to.node || to.ip) + "/" + to.device : "dev " + f.to,
          { cls: "num", v: String(f.slots) },
          { cls: "num", v: fmtBytes((tr.bytes_per_slot || 0) * f.slots) }
        ];
      });
      if (flows.length) grid.appendChild(card(T("Where the data goes", "数据流向"), table(["From", "To", "Replicas", "Bytes"], flows)));

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
    var tt = { runs: [], view: "table", timer: null };
    var ttOut = $("#tt-out"), ttState = $("#tt-state");

    function fmtRate(v) { return CHART.fmtNum(v) + " op/s"; }

    function ttTable() {
      if (!tt.runs.length) {
        var e = document.createElement("div"); e.className = "empty";
        e.textContent = T("No test runs yet.", "还没有测试记录。");
        return e;
      }
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
      tt.runs.forEach(function (r) {
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

    // Grouped bars: one group per run, so different workloads compare directly.
    function ttChart() {
      if (!tt.runs.length) {
        var e = document.createElement("div"); e.className = "empty";
        e.textContent = T("No test runs yet.", "还没有测试记录。");
        return e;
      }
      var runs = tt.runs.slice(0, 12).reverse();
      var box = document.createElement("div");
      [[T("Throughput (op/s)", "吞吐量（op/s）"), function (r) { return r.throughput; }, function (v) { return CHART.fmtNum(v); }, "mon-s1"],
       [T("Bandwidth", "带宽"), function (r) { return r.bandwidth; }, function (v) { return fmtBytes(v) + "/s"; }, "mon-s2"],
       [T("Average latency (ms)", "平均延迟（毫秒）"), function (r) { return r.avg_res_ms; }, function (v) { return v.toFixed(1) + " ms"; }, "mon-s3"]
      ].forEach(function (metric) {
        var card = document.createElement("div"); card.className = "mon-card wide";
        var h = document.createElement("div"); h.className = "mon-card-h";
        var ti = document.createElement("span"); ti.className = "mon-t"; ti.textContent = metric[0];
        h.appendChild(ti);
        var body = document.createElement("div"); body.className = "mon-body";

        var max = Math.max.apply(null, runs.map(metric[1])) || 1;
        var rows = document.createElement("div"); rows.className = "tt-bars";
        runs.forEach(function (r) {
          var row = document.createElement("div"); row.className = "tt-bar-row";
          var lab = document.createElement("span"); lab.className = "tt-bar-l";
          lab.textContent = r.size + " " + r.op + " ×" + r.workers;
          var track = document.createElement("span"); track.className = "tt-bar-t";
          var fill = document.createElement("i");
          fill.className = metric[3];
          fill.style.width = Math.max(1, (metric[1](r) / max) * 100) + "%";
          track.appendChild(fill);
          var val = document.createElement("span"); val.className = "tt-bar-v";
          val.textContent = metric[2](metric[1](r));
          row.appendChild(lab); row.appendChild(track); row.appendChild(val);
          rows.appendChild(row);
        });
        body.appendChild(rows);
        card.appendChild(h); card.appendChild(body);
        box.appendChild(card);
      });
      return box;
    }

    function ttRender() {
      ttOut.innerHTML = "";
      ttOut.appendChild(tt.view === "chart" ? ttChart() : ttTable());
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

    ttLoad();
  }

  // ---------------------------------------------------- Policy Economist
  if (PAGE === "lab-policy") {
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
        peOut.appendChild(peTable(d.rows || []));
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

/* ---------------------------------------------------- swift-shadow: begin */
/* Owned by the Shadow tool, appended rather than merged into the block above:
   the console's single IIFE is shared by every surface, and four tools editing
   one closure is how a page loses its script. That closure exports nothing, so
   the two helpers this needs are re-declared here rather than reached for. */
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

  var NS = "http://www.w3.org/2000/svg";
  function el(name, attrs) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  // The bars carry the same three numbers as the table underneath. They exist
  // because the ratio between "compared" and "set aside as noise" is the thing
  // a reader has to feel, and a column of integers does not convey a ratio.
  function draw() {
    host.innerHTML = "";
    var W = Math.max(host.clientWidth || 720, 320);
    var rowH = 30, padT = 6, padB = 6, padR = 96;
    var widest = fams.reduce(function (m, f) { return Math.max(m, f.label.length); }, 6);
    var padL = Math.min(Math.max(70, Math.ceil(widest * 7.2) + 12), Math.round(W * 0.34));
    var H = padT + fams.length * rowH + padB;
    var max = fams.reduce(function (m, f) {
      return Math.max(m, (f.comparable || 0) + (f.suppressed || 0));
    }, 1);
    var track = Math.max(W - padL - padR, 60);
    var s = el("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, class: "sh-svg" });

    fams.forEach(function (f, i) {
      var y = padT + i * rowH + 8, h = 13;
      var comparable = f.comparable || 0, sup = f.suppressed || 0, diff = f.differing || 0;
      var same = Math.max(comparable - diff, 0);
      var total = comparable + sup;
      var unit = track / max;

      var lab = el("text", { x: padL - 10, y: y + h - 2.5, "text-anchor": "end", class: "sh-bar-l" });
      lab.textContent = f.label;
      s.appendChild(lab);

      s.appendChild(el("rect", {
        x: padL, y: y, width: track, height: h, rx: 3, class: "sh-bar-bg"
      }));

      var x = padL;
      [[same, "sh-seg-ok"], [diff, "sh-seg-diff"], [sup, "sh-seg-sup"]].forEach(function (seg) {
        var n = seg[0];
        if (!n) return;
        var w = Math.max(n * unit, 1.5);
        var r = el("rect", { x: x, y: y, width: w, height: h, rx: 2, class: seg[1] });
        var t = el("title", {});
        t.textContent = f.label + " · " + n;
        r.appendChild(t);
        s.appendChild(r);
        x += w;
      });

      var v = el("text", {
        x: W - padR + 10, y: y + h - 2.5, "text-anchor": "start", class: "sh-bar-v"
      });
      v.textContent = comparable + " / " + total;
      s.appendChild(v);
    });
    host.appendChild(s);
  }

  draw();
  var t = null;
  window.addEventListener("resize", function () {
    clearTimeout(t); t = setTimeout(draw, 200);
  });
})();
/* ------------------------------------------------------ swift-shadow: end */

/* ------------------------------------------- warehouse expiry lane (appended)
   Owned by the Agent-Native Object Warehouse tool. It draws only what the table
   directly beneath it already states, so a page with no script loses a picture
   and no information. The countdown is redrawn on a timer because a "42 minutes
   left" rendered once is wrong five minutes later. */
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
  var NS = "http://www.w3.org/2000/svg";
  // console.js keeps its svg() helper inside its own IIFE. Restating four lines
  // here beats reaching into, or exporting from, a scope every tool shares.
  function svg(n, a) {
    var e = document.createElementNS(NS, n);
    for (var k in a) e.setAttribute(k, a[k]);
    return e;
  }
  function pad2(n) { return (n < 10 ? "0" : "") + n; }
  function clock(t) {
    var d = new Date(t * 1000);
    return pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes()) + "Z";
  }
  function left(s) {
    if (s <= 0) return T("gone", "已过期");
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return ZH ? (d + " 天 " + h + " 小时") : (d + "d " + h + "h");
    if (h) return ZH ? (h + " 小时 " + m + " 分") : (h + "h " + m + "m");
    return ZH ? (m + " 分") : (m + "m");
  }
  function tail(p) { var i = p.lastIndexOf("/"); return i < 0 ? p : p.slice(i + 1); }

  rows = rows.slice().sort(function (a, b) { return a.at - b.at; }).slice(0, 16);

  function draw() {
    host.innerHTML = "";
    var W = Math.max(host.clientWidth || 640, 300);
    var now = Math.floor(Date.now() / 1000);
    var maxT = rows[rows.length - 1].at;
    if (maxT <= now + 60) maxT = now + 60;
    var i, longest = 0;
    for (i = 0; i < rows.length; i++) longest = Math.max(longest, tail(rows[i].path).length);
    var padL = Math.min(Math.max(84, longest * 6.3 + 10), Math.round(W * 0.34));
    var padR = 78, padT = 6, rowH = 22, padB = 20;
    var H = padT + rows.length * rowH + padB;
    var span = maxT - now;
    var x = function (t) {
      var f = (t - now) / span;
      if (f < 0) f = 0; if (f > 1) f = 1;
      return padL + f * (W - padL - padR);
    };
    var s = svg("svg", {
      viewBox: "0 0 " + W + " " + H, width: W, height: H, class: "wh-lane-svg", role: "img",
      "aria-label": T("Time left before each working file is removed",
                      "每个 working 文件被删除前的剩余时间")
    });

    for (i = 0; i < rows.length; i++) {
      var r = rows[i];
      var top = padT + i * rowH;
      var cy = top + rowH / 2;
      var soon = (r.at - now) < 3600 ? " soon" : "";

      var lbl = svg("text", { x: 0, y: cy + 4, class: "wh-lane-l" });
      lbl.textContent = tail(r.path);
      var lt = svg("title", {});
      lt.textContent = r.path;
      lbl.appendChild(lt);
      s.appendChild(lbl);

      s.appendChild(svg("rect", {
        x: padL, y: cy - 4, width: Math.max(W - padL - padR, 1), height: 8, rx: 2, class: "wh-lane-track"
      }));
      var end = x(r.at);
      s.appendChild(svg("rect", {
        x: padL, y: cy - 4, width: Math.max(end - padL, 1), height: 8, rx: 2, class: "wh-lane-bar" + soon
      }));
      s.appendChild(svg("line", {
        x1: end, y1: cy - 6, x2: end, y2: cy + 6, class: "wh-lane-cap" + soon
      }));

      var v = svg("text", { x: W - padR + 8, y: cy + 4, class: "wh-lane-v" });
      v.textContent = left(r.at - now);
      s.appendChild(v);
    }

    var floor = padT + rows.length * rowH;
    s.appendChild(svg("line", { x1: padL, y1: padT - 2, x2: padL, y2: floor + 2, class: "wh-lane-now" }));
    var ticks = [[padL, T("now", "现在")], [(padL + W - padR) / 2, clock(now + span / 2)], [W - padR, clock(maxT)]];
    for (i = 0; i < ticks.length; i++) {
      var tx = svg("text", {
        x: ticks[i][0], y: floor + 14, class: "wh-lane-ax",
        "text-anchor": i === 0 ? "start" : (i === 2 ? "end" : "middle")
      });
      tx.textContent = ticks[i][1];
      s.appendChild(tx);
    }
    host.appendChild(s);
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
