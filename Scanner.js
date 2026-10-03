.pragma library
.import "Model.js" as Model

// Installed-plugin scanner: pure logic shared by PluginScanner.qml and the
// node tests in tests/scanner.test.js. No QML context and no I/O; keep it
// ES5-compatible like Model.js.
//
// The scanner never judges a file itself. A file counts as "flagged" only
// when VirusTotal returned engine detections (malicious/suspicious > 0) or an
// AI insight (Code Insight) whose own verdict is malicious or suspicious; see
// Model.hasFlags. Everything shown is VirusTotal's numbers and text.

var MIN_MS = 60000
var DAY_MS = 86400000
var FOUND_TTL_MS = 7 * DAY_MS        // re-check files with a report weekly
var MISS_TTL_MS = 3600000            // unknown files: look again after 1 h
var ANALYZING_TTL_MS = 15 * MIN_MS   // an analysis we stopped polling
var ERROR_TTL_MS = 3600000
var UPLOAD_RETRY_MS = DAY_MS         // never re-upload the same file within 24 h
var REFRESH_DELAY_MS = 90000         // report re-read after an analysis (AI insight)
var CACHE_LIMIT = 4000
var MAX_FILES_PER_PLUGIN = 2000
var MAX_ATTEMPTS = 4

// perMin/perDay are the share of each quota the scanner may use. For VTAI it
// leaves headroom for manual checks and the Downloads watcher, which share the
// same token. The classic API counts every request against one quota.
var BACKENDS = {
  vtai: {
    id: "vtai",
    label: "VirusTotal AI",
    base: "https://ai.virustotal.com/api/v3",
    shared: false,
    limits: { lookup: { perMin: 48, perDay: 900 }, upload: { perMin: 16, perDay: 450 } },
    pollMinMs: 5000,
    maxPolls: 40
  },
  classic: {
    id: "classic",
    label: "VirusTotal API key",
    base: "https://www.virustotal.com/api/v3",
    shared: true,
    limits: { any: { perMin: 4, perDay: 500 } },
    pollMinMs: 60000,
    maxPolls: 15
  }
}

function backendFor(id) {
  return BACKENDS[id] || BACKENDS.vtai
}

function clampInt(value, lo, hi, fallback) {
  var n = Number(value)
  if (!isFinite(n)) return fallback
  n = Math.floor(n)
  return n < lo ? lo : (n > hi ? hi : n)
}

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

function keys(obj) {
  var out = []
  if (!obj || typeof obj !== "object") return out
  for (var k in obj) if (hasOwn(obj, k)) out.push(k)
  return out
}

function utcDay(now) {
  return new Date(now).toISOString().slice(0, 10)
}

function nextUtcMidnight(now) {
  var d = new Date(now)
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1)
}

// --- rate limiter ------------------------------------------------------------

// Sliding one-minute window plus a per-UTC-day counter per bucket. `persisted`
// ({ backend, day, used }) restores today's counters after a restart.
function makeLimiter(backendId, overrides, persisted, now) {
  var b = backendFor(backendId)
  var limits = Model.copy(b.limits)
  var o = overrides || {}
  if (b.shared) {
    limits.any.perMin = clampInt(o.perMin, 1, 100000, limits.any.perMin)
    limits.any.perDay = clampInt(o.perDay, 1, 10000000, limits.any.perDay)
  }
  var l = { backend: b.id, shared: b.shared, limits: limits, day: utcDay(now), used: {}, recent: {} }
  var p = persisted && typeof persisted === "object" ? persisted : null
  var restore = p && p.backend === b.id && p.day === l.day && p.used && typeof p.used === "object"
  var ks = keys(limits)
  for (var i = 0; i < ks.length; i++) {
    l.used[ks[i]] = restore ? Model.num(p.used[ks[i]]) : 0
    l.recent[ks[i]] = []
  }
  return l
}

function bucketOf(limiter, cls) {
  return limiter.shared ? "any" : cls
}

function rollDay(limiter, now) {
  var d = utcDay(now)
  if (d === limiter.day) return
  limiter.day = d
  var ks = keys(limiter.used)
  for (var i = 0; i < ks.length; i++) limiter.used[ks[i]] = 0
}

function pruneWindow(limiter, key, now) {
  var r = limiter.recent[key] || []
  var i = 0
  while (i < r.length && now - r[i] >= MIN_MS) i++
  if (i > 0) r = r.slice(i)
  limiter.recent[key] = r
  return r
}

// 0 when a request of class `cls` ("lookup" | "upload") may start now,
// otherwise the milliseconds to wait.
function waitMs(limiter, cls, now) {
  rollDay(limiter, now)
  var key = bucketOf(limiter, cls)
  var lim = limiter.limits[key]
  if (!lim) return 0
  if ((limiter.used[key] || 0) >= lim.perDay) return Math.max(1000, nextUtcMidnight(now) - now)
  var r = pruneWindow(limiter, key, now)
  if (r.length >= lim.perMin) return Math.max(1, r[0] + MIN_MS - now)
  return 0
}

function take(limiter, cls, now) {
  rollDay(limiter, now)
  var key = bucketOf(limiter, cls)
  limiter.used[key] = (limiter.used[key] || 0) + 1
  if (!limiter.recent[key]) limiter.recent[key] = []
  limiter.recent[key].push(now)
}

// [{ key, used, perDay, perMin, inWindow }] for the UI.
function quotaInfo(limiter, now) {
  var out = []
  if (!limiter) return out
  rollDay(limiter, now)
  var ks = keys(limiter.limits)
  for (var i = 0; i < ks.length; i++) {
    var k = ks[i]
    out.push({ key: k, used: limiter.used[k] || 0, perDay: limiter.limits[k].perDay,
               perMin: limiter.limits[k].perMin, inWindow: pruneWindow(limiter, k, now).length })
  }
  return out
}

function persistLimiter(limiter) {
  return limiter ? { backend: limiter.backend, day: limiter.day, used: Model.copy(limiter.used) } : null
}

// --- scheduler ---------------------------------------------------------------

// Tasks: { type: "lookup" | "upload" | "poll", sha, notBefore, attempts, ... }.
// Polls go first (they finish work already paid for), then lookups, then uploads.
var PRIORITY = { poll: 0, lookup: 1, upload: 2 }

function taskClass(task) {
  return task && task.type === "upload" ? "upload" : "lookup"
}

// s: { queue, inFlight, maxParallel, pauseUntil, limiter }. Removes the tasks
// it starts from s.queue and takes their quota. Returns { start, wakeAt }:
// wakeAt is when something waiting could start (0 = nothing to wake for, e.g.
// every slot is busy and a finishing job will pump again).
function dispatch(s, now) {
  var start = []
  var wakeAt = 0
  var queue = s.queue || []
  function wake(t) {
    if (t > now && (!wakeAt || t < wakeAt)) wakeAt = t
  }
  if (queue.length === 0) return { start: start, wakeAt: 0 }
  if ((s.pauseUntil || 0) > now) {
    wake(s.pauseUntil)
    return { start: start, wakeAt: wakeAt }
  }
  var order = []
  for (var i = 0; i < queue.length; i++) order.push(i)
  order.sort(function(a, b) {
    var pa = PRIORITY[queue[a].type], pb = PRIORITY[queue[b].type]
    return (pa === undefined ? 9 : pa) - (pb === undefined ? 9 : pb) || a - b
  })
  var maxParallel = Math.max(1, s.maxParallel || 1)
  var started = {}
  for (var j = 0; j < order.length; j++) {
    if ((s.inFlight || 0) + start.length >= maxParallel) {
      wakeAt = 0
      break
    }
    var idx = order[j]
    var t = queue[idx]
    if ((t.notBefore || 0) > now) {
      wake(t.notBefore)
      continue
    }
    var w = s.limiter ? waitMs(s.limiter, taskClass(t), now) : 0
    if (w > 0) {
      wake(now + w)
      continue
    }
    if (s.limiter) take(s.limiter, taskClass(t), now)
    start.push(t)
    started[idx] = true
  }
  if (start.length) {
    var rest = []
    for (var k = 0; k < queue.length; k++) if (!started[k]) rest.push(queue[k])
    s.queue = rest
  }
  return { start: start, wakeAt: wakeAt }
}

// --- shell output parsing ----------------------------------------------------

function cleanText(value, max) {
  return Model.truncate(String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim(), max || 120)
}

// Scripts.probePlugins: "dir\thead\tcount size mtime\tversion\tname\tlink".
function parseProbe(text) {
  var out = []
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var f = lines[i].split("\t")
    if (f.length < 3 || f[0] === "") continue
    var head = /^[a-f0-9]{40,64}$/.test(f[1]) ? f[1] : ""
    out.push({
      id: f[0],
      head: head,
      stamp: head + "|" + String(f[2]).trim(),
      version: cleanText(f[3], 40),
      name: cleanText(f[4], 80),
      link: f[5] === "link"
    })
  }
  return out
}

// Scripts.hashPlugin: "#\t<total>\t<skipped>" then "sha256\tsize\trelpath".
function parseHashList(text, maxFiles) {
  var max = maxFiles || MAX_FILES_PER_PLUGIN
  var files = {}
  var count = 0
  var total = 0
  var skipped = 0
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i]
    if (line === "") continue
    var a = line.indexOf("\t")
    var b = a >= 0 ? line.indexOf("\t", a + 1) : -1
    if (a < 0 || b < 0) continue
    var first = line.slice(0, a)
    if (first === "#") {
      var rest = line.slice(a + 1).split("\t")
      total = Model.num(rest[0])
      skipped = Model.num(rest[1])
      continue
    }
    var sha = first.toLowerCase()
    var size = Number(line.slice(a + 1, b))
    var rel = line.slice(b + 1)
    if (!/^[a-f0-9]{64}$/.test(sha) || !isFinite(size) || size <= 0 || rel === "") continue
    if (count >= max) continue
    if (!hasOwn(files, rel)) count++
    files[rel] = { sha: sha, size: size }
  }
  return { files: files, count: count, total: Math.max(total, count), skipped: skipped,
           truncated: Math.max(total, count) > count }
}

// --- plugin state ------------------------------------------------------------

// Compare a plugin's stored files with a fresh hash list.
// Returns { kind: "added" | "updated" | "unchanged", changed: [rel], removed: [rel] }.
function diffPlugin(prev, files) {
  var changed = []
  var removed = []
  var next = files || {}
  var old = prev && prev.files ? prev.files : null
  var rels = keys(next).sort()
  for (var i = 0; i < rels.length; i++) {
    var rel = rels[i]
    if (!old || !hasOwn(old, rel) || old[rel].sha !== next[rel].sha) changed.push(rel)
  }
  if (old) {
    var olds = keys(old).sort()
    for (var j = 0; j < olds.length; j++) if (!hasOwn(next, olds[j])) removed.push(olds[j])
  }
  var kind = !old ? "added" : (changed.length || removed.length ? "updated" : "unchanged")
  return { kind: kind, changed: changed, removed: removed }
}

// What a cached file needs next: "lookup" or "" (fresh enough).
function needsLookup(entry, now, force) {
  if (!entry) return true
  if (force) return true
  var age = now - (Number(entry.time) || 0)
  switch (entry.status) {
  case "found": return age > FOUND_TTL_MS
  case "not_found": return age > MISS_TTL_MS
  case "analyzing": return age > ANALYZING_TTL_MS
  }
  return age > ERROR_TTL_MS
}

function canAutoUpload(entry, size, now) {
  return !!entry && entry.status === "not_found" && size > 0 && size <= Model.MAX_UPLOAD_BYTES
    && (!entry.uploadedAt || now - entry.uploadedAt > UPLOAD_RETRY_MS)
}

// New tasks for one plugin. `busy` maps sha -> true for work already queued or
// running, so a file shared by several plugins (or versions) is checked once.
// opts: { autoUpload, force }.
function tasksFor(record, dir, cache, busy, now, opts) {
  var o = opts || {}
  var out = []
  var seen = {}
  var files = record && record.files ? record.files : {}
  var rels = keys(files).sort()
  for (var i = 0; i < rels.length; i++) {
    var rel = rels[i]
    var f = files[rel]
    if (!f || !f.sha || seen[f.sha] || (busy && busy[f.sha])) continue
    var entry = cache ? cache[f.sha] : null
    var type = ""
    if (needsLookup(entry, now, o.force)) type = "lookup"
    else if (o.autoUpload && canAutoUpload(entry, f.size, now)) type = "upload"
    if (!type) continue
    seen[f.sha] = true
    out.push({ type: type, sha: f.sha, size: f.size, path: dir + "/" + rel, name: record.id + "/" + rel,
               plugin: record.id, notBefore: now, attempts: 0 })
  }
  return out
}

// Compact cache entry from a Model result (no local path or name: the same
// sha256 can belong to several plugins).
function cacheEntry(r, now, prev) {
  var e = {
    status: r.status,
    time: now,
    stats: r.stats,
    engines: r.engines || 0,
    topDetections: r.topDetections || [],
    typeDescription: r.typeDescription || "",
    insight: r.insight || null,
    reportUrl: r.reportUrl || "",
    analysisDate: r.analysisDate || "",
    analysisId: r.analysisId || "",
    message: r.message || ""
  }
  if (e.insight && e.insight.analysis) e.insight = { verdict: e.insight.verdict, rawVerdict: e.insight.rawVerdict,
                                                     source: e.insight.source, analysis: Model.truncate(e.insight.analysis, 400) }
  if (prev && prev.uploadedAt) e.uploadedAt = prev.uploadedAt
  return e
}

function errorEntry(message, now, prev) {
  var e = { status: "error", time: now, stats: Model.normalizeStats(null), engines: 0, topDetections: [],
            insight: null, reportUrl: "", message: String(message || "") }
  if (prev && prev.uploadedAt) e.uploadedAt = prev.uploadedAt
  return e
}

// Keep the newest CACHE_LIMIT entries.
function pruneCache(cache) {
  var ks = keys(cache)
  if (ks.length <= CACHE_LIMIT) return cache
  ks.sort(function(a, b) { return (Number(cache[b].time) || 0) - (Number(cache[a].time) || 0) })
  var out = {}
  for (var i = 0; i < CACHE_LIMIT; i++) out[ks[i]] = cache[ks[i]]
  return out
}

// True when VirusTotal flagged this cached file (engines or AI insight).
function entryFlagged(entry) {
  return !!entry && entry.status === "found"
    && Model.hasFlags({ status: "found", stats: Model.normalizeStats(entry.stats), insight: entry.insight })
}

// A Model-shaped file result for one plugin file (history, alerts, notifications).
function fileResult(record, dir, rel, cache) {
  var f = record && record.files ? record.files[rel] : null
  if (!f) return null
  var e = cache ? cache[f.sha] : null
  var r = Model.baseResult("file", dir + "/" + rel, { name: record.id + "/" + rel, path: dir + "/" + rel,
                                                     sha256: f.sha, size: f.size, source: "plugins" })
  if (!e) return r
  r.status = e.status
  r.stats = Model.normalizeStats(e.stats)
  r.engines = e.engines || 0
  r.topDetections = e.topDetections || []
  r.typeDescription = e.typeDescription || ""
  r.insight = e.insight || null
  r.reportUrl = Model.safeReportUrl(e.reportUrl) || Model.fallbackReportUrl("file", f.sha)
  r.analysisDate = e.analysisDate || ""
  r.analysisId = e.analysisId || ""
  r.message = e.message || ""
  r.verdict = e.status === "found" ? Model.verdictFor(r.stats) : "unknown"
  r.time = Number(e.time) || 0
  return r
}

// Per-plugin totals, counted per file. Only VirusTotal's numbers are used.
function summarize(record, cache, busy) {
  var s = { files: 0, checked: 0, flagged: 0, engineFlagged: 0, insightFlagged: 0, withMalicious: 0,
            notFound: 0, analyzing: 0, errors: 0, pending: 0, flaggedFiles: [] }
  var files = record && record.files ? record.files : {}
  var rels = keys(files).sort()
  for (var i = 0; i < rels.length; i++) {
    var rel = rels[i]
    var f = files[rel]
    s.files++
    var e = cache ? cache[f.sha] : null
    if ((busy && busy[f.sha]) || !e) {
      s.pending++
      continue
    }
    if (e.status === "found") {
      s.checked++
      var stats = Model.normalizeStats(e.stats)
      var probe = { status: "found", stats: stats, insight: e.insight }
      var engineHits = Model.flaggedCount(probe)
      var aiHit = Model.insightFlags(probe)
      if (engineHits > 0 || aiHit) {
        s.flagged++
        if (engineHits > 0) s.engineFlagged++
        if (aiHit) s.insightFlagged++
        if (stats.malicious > 0) s.withMalicious++
        s.flaggedFiles.push({ rel: rel, sha: f.sha, malicious: stats.malicious, suspicious: stats.suspicious,
                              rated: Model.ratedCount({ stats: stats, engines: e.engines }),
                              insight: aiHit ? String(e.insight.rawVerdict || e.insight.verdict || "") : "" })
      }
    } else if (e.status === "not_found") {
      s.notFound++
    } else if (e.status === "analyzing") {
      s.analyzing++
    } else {
      s.errors++
    }
  }
  // Order by VirusTotal's own counts: malicious, then suspicious, then AI insight.
  s.flaggedFiles.sort(function(a, b) {
    return b.malicious - a.malicious || b.suspicious - a.suspicious
      || (b.insight ? 1 : 0) - (a.insight ? 1 : 0) || (a.rel < b.rel ? -1 : 1)
  })
  return s
}

function plural(n, word) {
  return n + " " + word + (n === 1 ? "" : "s")
}

// One file's line in the flagged list: "Service.qml: 3/62 flagged · AI insight: malicious".
function flaggedFileLine(f) {
  var parts = []
  if (f.malicious + f.suspicious > 0) parts.push((f.malicious + f.suspicious) + "/" + f.rated + " flagged")
  if (f.insight) parts.push("AI insight: " + f.insight)
  return f.rel + ": " + parts.join(" \u00b7 ")
}

// Headline + theme role for a plugin row.
function pluginStatus(summary) {
  var s = summary
  if (!s) return { label: "", role: "muted" }
  if (s.pending > 0) return { label: "Checking " + (s.files - s.pending) + "/" + s.files + " files", role: "pending" }
  var extra = []
  if (s.notFound > 0) extra.push(s.notFound + " unknown to VirusTotal")
  if (s.analyzing > 0) extra.push(s.analyzing + " analyzing")
  if (s.errors > 0) extra.push(plural(s.errors, "error"))
  var tail = extra.length ? " \u00b7 " + extra.join(" \u00b7 ") : ""
  if (s.flagged > 0) {
    var role = s.withMalicious > 0 ? "danger" : "warning"
    return { label: s.flagged + " of " + plural(s.files, "file") + " flagged" + tail, role: role }
  }
  if (s.checked > 0) return { label: "No detections in " + plural(s.checked, "file") + tail, role: "ok" }
  if (s.files === 0) return { label: "No files", role: "muted" }
  return { label: extra.join(" \u00b7 ") || "Not checked", role: "muted" }
}

// Status line + role for a single file row.
function fileStatus(entry, busy) {
  if (busy) return { label: "Checking\u2026", role: "pending" }
  if (!entry) return { label: "Not checked", role: "muted" }
  if (entry.status === "found") {
    var r = { status: "found", stats: Model.normalizeStats(entry.stats), engines: entry.engines, insight: entry.insight }
    var label = Model.verdictLabel(r)
    if (Model.insightFlags(r)) label += " \u00b7 AI insight: " + (entry.insight.rawVerdict || entry.insight.verdict)
    var role = r.stats.malicious > 0 ? "danger" : (Model.hasFlags(r) ? "warning" : "ok")
    return { label: label, role: role }
  }
  if (entry.status === "not_found") return { label: "Unknown to VirusTotal", role: "muted" }
  if (entry.status === "analyzing") return { label: "Analyzing", role: "pending" }
  return { label: entry.message ? Model.truncate(entry.message, 80) : "Error", role: "muted" }
}

// Notification when a plugin appears or changes (before any result).
function eventNotification(kind, record, changedCount) {
  var name = record.name || record.id
  if (kind === "added") {
    return { urgency: "low", glyph: Model.Glyph.puzzle, title: "New plugin: " + name,
             body: record.id + " \u00b7 " + plural(keys(record.files).length, "file") + ". Checking with VirusTotal\u2026" }
  }
  return { urgency: "low", glyph: Model.Glyph.puzzle, title: "Plugin updated: " + name,
           body: record.id + " \u00b7 " + plural(changedCount || 0, "changed file") + ". Checking with VirusTotal\u2026" }
}

// Notification when a plugin's check finishes; null when nothing to say.
function summaryNotification(record, summary, notifyAll) {
  var name = record.name || record.id
  var s = summary
  if (s.flagged > 0) {
    var lines = []
    for (var i = 0; i < s.flaggedFiles.length && i < 3; i++) lines.push(flaggedFileLine(s.flaggedFiles[i]))
    if (s.flaggedFiles.length > 3) lines.push("and " + (s.flaggedFiles.length - 3) + " more")
    return { urgency: s.withMalicious > 0 ? "critical" : "normal",
             glyph: s.withMalicious > 0 ? Model.Glyph.alertOctagon : Model.Glyph.alert,
             title: "VirusTotal flagged " + plural(s.flagged, "file") + " in " + name,
             body: lines.join("\n") }
  }
  if (!notifyAll) return null
  var body = "0 of " + plural(s.checked, "checked file") + " flagged."
  if (s.notFound > 0) body += " " + s.notFound + " unknown to VirusTotal."
  return { urgency: "low", glyph: Model.Glyph.shieldCheck, title: "No detections: " + name, body: body }
}

// --- persisted state ---------------------------------------------------------

function sanitizeFiles(files) {
  var out = {}
  var ks = keys(files)
  for (var i = 0; i < ks.length && i < MAX_FILES_PER_PLUGIN; i++) {
    var f = files[ks[i]]
    if (f && /^[a-f0-9]{64}$/.test(String(f.sha)) && Number(f.size) > 0) out[ks[i]] = { sha: String(f.sha), size: Number(f.size) }
  }
  return out
}

function parseState(text) {
  var j = Model.parseJson(text)
  var s = { version: 1, baselineDone: false, plugins: {}, cache: {}, quota: null }
  if (!j || typeof j !== "object" || Array.isArray(j)) return s
  s.baselineDone = j.baselineDone === true
  var ps = keys(j.plugins)
  for (var i = 0; i < ps.length; i++) {
    var p = j.plugins[ps[i]]
    if (!p || typeof p !== "object") continue
    s.plugins[ps[i]] = {
      id: ps[i], name: cleanText(p.name, 80), version: cleanText(p.version, 40),
      head: /^[a-f0-9]{40,64}$/.test(String(p.head)) ? String(p.head) : "",
      stamp: String(p.stamp || ""), link: p.link === true, files: sanitizeFiles(p.files),
      firstSeen: Number(p.firstSeen) || 0, changedAt: Number(p.changedAt) || 0, lastScan: Number(p.lastScan) || 0,
      truncated: p.truncated === true, skipped: Model.num(p.skipped)
    }
  }
  var cs = keys(j.cache)
  for (var k = 0; k < cs.length; k++) {
    var e = j.cache[cs[k]]
    if (/^[a-f0-9]{64}$/.test(cs[k]) && e && typeof e === "object" && typeof e.status === "string") s.cache[cs[k]] = e
  }
  if (j.quota && typeof j.quota === "object") s.quota = j.quota
  return s
}

function serializeState(s) {
  return JSON.stringify({
    version: 1,
    baselineDone: s.baselineDone === true,
    plugins: s.plugins || {},
    cache: pruneCache(s.cache || {}),
    quota: s.quota || null
  }) + "\n"
}

// --- classic VirusTotal API v3 -----------------------------------------------

// Engine results -> the anonymized label list VTAI returns in `detections`:
// the engine's result name when it flagged the file, else its category.
function classicDetections(results) {
  var out = []
  var ks = keys(results)
  for (var i = 0; i < ks.length; i++) {
    var r = results[ks[i]]
    if (!r || typeof r !== "object") continue
    var cat = String(r.category || "")
    out.push((cat === "malicious" || cat === "suspicious") && r.result ? String(r.result) : cat)
  }
  return out
}

// Code Insight and other crowdsourced AI results, as returned.
function classicInsights(list) {
  var out = []
  if (!Array.isArray(list)) return out
  for (var i = 0; i < list.length; i++) {
    var a = list[i]
    if (!a || typeof a !== "object") continue
    out.push({ verdict: String(a.verdict || a.category || ""), source: String(a.source || "Code Insight"),
               analysis: String(a.analysis || "") })
  }
  return out
}

// GET /files/{id} `data` -> the VTAI report shape Model.resultFromReport reads.
function classicReport(data) {
  var d = data && typeof data === "object" ? data : {}
  var a = d.attributes && typeof d.attributes === "object" ? d.attributes : {}
  var sha = /^[a-f0-9]{64}$/i.test(String(a.sha256 || "")) ? String(a.sha256).toLowerCase() : String(d.id || "")
  var results = a.last_analysis_results && typeof a.last_analysis_results === "object" ? a.last_analysis_results : {}
  return {
    id: sha,
    last_analysis_stats: a.last_analysis_stats || null,
    coverage: { engines: keys(results).length },
    detections: classicDetections(results),
    type_description: a.type_description || "",
    ai_insights: classicInsights(a.crowdsourced_ai_results),
    analysis_date: a.last_analysis_date || "",
    report_url: /^[a-f0-9]{64}$/i.test(sha) ? "https://www.virustotal.com/gui/file/" + sha.toLowerCase() : ""
  }
}

// GET /analyses/{id} JSON -> the VTAI analysis shape Model.resultFromAnalysis reads.
function classicAnalysis(json) {
  var j = json && typeof json === "object" ? json : {}
  var d = j.data && typeof j.data === "object" ? j.data : {}
  var a = d.attributes && typeof d.attributes === "object" ? d.attributes : {}
  var info = j.meta && j.meta.file_info && typeof j.meta.file_info === "object" ? j.meta.file_info : {}
  var sha = /^[a-f0-9]{64}$/i.test(String(info.sha256 || "")) ? String(info.sha256).toLowerCase() : ""
  var results = a.results && typeof a.results === "object" ? a.results : {}
  return {
    status: a.status === "completed" ? "completed" : "pending",
    stats: a.stats || null,
    coverage: { engines: keys(results).length },
    detections: classicDetections(results),
    sha256: sha,
    analysis_id: String(d.id || ""),
    analysis_date: a.date || "",
    report_url: sha ? "https://www.virustotal.com/gui/file/" + sha : ""
  }
}

// POST /files JSON -> analysis id, or "".
function classicUploadId(json) {
  var d = json && json.data && typeof json.data === "object" ? json.data : null
  return d && d.type === "analysis" && d.id ? String(d.id) : ""
}

// Classic API errors ({"error": {"code", "message"}}) -> Model.apiError shape.
function classicError(http, json, exitCode) {
  var err = json && json.error && typeof json.error === "object" ? json.error : {}
  var code = String(err.code || "")
  var message = String(err.message || "")
  if (!http) {
    var net = Model.apiError(0, null, exitCode)
    if (net.kind === "network") net.message = "Could not reach www.virustotal.com. Check your connection."
    return net
  }
  if (http === 401 || http === 403 || code === "WrongCredentialsError" || code === "AuthenticationRequiredError"
      || code === "ForbiddenError" || code === "UserNotActiveError")
    return { kind: "auth", code: code, retryAfter: 0, message: "VirusTotal rejected the API key. Check it in Settings." }
  if (http === 429 || code === "QuotaExceededError" || code === "TooManyRequestsError")
    return { kind: "rate_limit", code: code, retryAfter: 60, message: "API key quota reached; waiting before the next request." }
  if (http === 413)
    return { kind: "too_large", code: code, retryAfter: 0, message: "The file is larger than the 32 MB upload limit." }
  if (http >= 500)
    return { kind: "unavailable", code: code, retryAfter: 0, message: "VirusTotal is temporarily unavailable (HTTP " + http + ")." }
  return { kind: "http", code: code, retryAfter: 0,
           message: (message ? Model.truncate(message, 200) : "The request failed") + " (HTTP " + http + ")." }
}
