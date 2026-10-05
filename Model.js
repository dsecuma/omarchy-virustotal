.pragma library

// Pure helpers shared by the plugin's QML files, Scanner.js and Agents.js.
//
// No QML context and no I/O: the same file runs under node for the unit
// tests in tests/model.test.js. Keep it ES5-compatible.

var MAX_UPLOAD_BYTES = 32000000        // VTAI /submissions limit
var MAX_WATCH_BYTES = 1073741824       // watcher skips files above 1 GiB
var HISTORY_LIMIT = 50
var DEDUPE_WINDOW_MS = 60000
var DEFAULT_VERSION = "1.1.8"
var AGENT_FAMILY = "omarchy"
var AGENT_DISPLAY_NAME = "Omarchy VirusTotal"

function cp(code) {
  if (code < 0x10000) return String.fromCharCode(code)
  var c = code - 0x10000
  return String.fromCharCode(0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF))
}

// Nerd Font Material Design glyphs (nf-md-*), bundled with Omarchy's fonts.
var Glyph = {
  shield: cp(0xF0498),
  shieldCheck: cp(0xF0565),
  shieldAlert: cp(0xF0ECC),
  shieldOutline: cp(0xF0499),
  shieldSearch: cp(0xF0D9A),
  virus: cp(0xF13B6),
  magnify: cp(0xF0349),
  history: cp(0xF02DA),
  cog: cp(0xF0493),
  upload: cp(0xF0552),
  cloudUpload: cp(0xF0167),
  openInNew: cp(0xF03CC),
  refresh: cp(0xF0450),
  trash: cp(0xF01B4),
  close: cp(0xF0156),
  file: cp(0xF0214),
  fileSearch: cp(0xF0C7C),
  link: cp(0xF0339),
  web: cp(0xF059F),
  ip: cp(0xF0A60),
  hash: cp(0xF0423),
  alert: cp(0xF0026),
  alertCircle: cp(0xF0028),
  alertOctagon: cp(0xF0029),
  checkCircle: cp(0xF05E0),
  helpCircle: cp(0xF02D7),
  download: cp(0xF01DA),
  folderDownload: cp(0xF024D),
  bell: cp(0xF009A),
  key: cp(0xF0306),
  logout: cp(0xF0343),
  login: cp(0xF0342),
  timerSand: cp(0xF051F),
  progressClock: cp(0xF0996),
  eye: cp(0xF0208),
  earth: cp(0xF01E7),
  copy: cp(0xF018F),
  puzzle: cp(0xF0431),
  robot: cp(0xF06A9),
  plus: cp(0xF0415),
  linkOff: cp(0xF033A)
}

// --- small utilities ---------------------------------------------------------

function num(value) {
  var n = Number(value)
  return isFinite(n) && n > 0 ? Math.floor(n) : 0
}

function copy(obj) {
  return obj ? JSON.parse(JSON.stringify(obj)) : obj
}

function parseJson(text) {
  if (text === undefined || text === null) return null
  var s = String(text).trim()
  if (s === "") return null
  try { return JSON.parse(s) } catch (e) { return null }
}

function basename(path) {
  var s = String(path || "").replace(/\/+$/, "")
  var i = s.lastIndexOf("/")
  return i >= 0 ? s.slice(i + 1) : s
}

function truncate(text, max) {
  var s = String(text || "")
  return s.length > max ? s.slice(0, max - 1) + "\u2026" : s
}

function safeVersion(value) {
  var v = String(value || "")
  return /^[A-Za-z0-9.-]{1,20}$/.test(v) ? v : DEFAULT_VERSION
}

function registerBody(version) {
  return JSON.stringify({
    agent_family: AGENT_FAMILY,
    agent_version: safeVersion(version),
    display_name: AGENT_DISPLAY_NAME
  })
}

function pad2(n) {
  return n < 10 ? "0" + n : String(n)
}

function formatBytes(value) {
  var v = Number(value)
  if (!isFinite(v) || v < 0) return ""
  if (v < 1000) return Math.round(v) + " B"
  var units = ["kB", "MB", "GB", "TB"]
  var i = -1
  do {
    v /= 1000
    i++
  } while (v >= 999.95 && i < units.length - 1)
  return (v >= 100 ? String(Math.round(v)) : v.toFixed(1).replace(/\.0$/, "")) + " " + units[i]
}

function formatDuration(seconds) {
  var s = Math.max(0, Math.round(Number(seconds) || 0))
  if (s < 60) return s + " s"
  if (s < 3600) return Math.round(s / 60) + " min"
  return Math.round(s / 3600) + " h"
}

// Milliseconds since the epoch from ms, epoch seconds (VirusTotal reports),
// numeric strings or ISO dates; 0 when unknown.
function toMillis(value) {
  if (value === undefined || value === null || value === "") return 0
  var s = String(value).trim()
  var n = typeof value === "number" ? value : (/^\d+(\.\d+)?$/.test(s) ? Number(s) : NaN)
  if (isFinite(n)) return n > 0 && n < 1e11 ? Math.round(n * 1000) : n
  var t = Date.parse(s)
  return isFinite(t) ? t : 0
}

function timeAgo(value, now) {
  var t = toMillis(value)
  if (!t) return ""
  var ref = now || Date.now()
  var d = Math.max(0, Math.floor((ref - t) / 1000))
  if (d < 45) return "just now"
  if (d < 3600) return Math.max(1, Math.round(d / 60)) + " min ago"
  if (d < 86400) return Math.round(d / 3600) + " h ago"
  if (d < 172800) return "yesterday"
  if (d < 30 * 86400) return Math.round(d / 86400) + " d ago"
  var date = new Date(t)
  return date.getFullYear() + "-" + pad2(date.getMonth() + 1) + "-" + pad2(date.getDate())
}

// "key=value" lines (startup probe output) -> object.
function parseKeyValues(text) {
  var out = {}
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i]
    var eq = line.indexOf("=")
    if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim()
  }
  return out
}

// XDG_DOWNLOAD_DIR from user-dirs.dirs, then the environment, then
// ~/Downloads. xdg-user-dirs uses $HOME itself to mean "disabled", and
// watching the whole home directory would be wrong, so that value is skipped.
function resolveDownloadsDir(fromFile, home, fromEnv) {
  var h = String(home || "").replace(/\/+$/, "")
  function expand(value) {
    var s = String(value || "").trim()
    if (s === "") return ""
    if (s === "$HOME" || s.indexOf("$HOME/") === 0) s = h ? h + s.slice(5) : ""
    else if (s === "${HOME}" || s.indexOf("${HOME}/") === 0) s = h ? h + s.slice(7) : ""
    s = s.replace(/\/+$/, "")
    if (s.charAt(0) !== "/" || s === h) return ""
    return s
  }
  return expand(fromFile) || expand(fromEnv) || (h ? h + "/Downloads" : "")
}

function displayPath(path, home) {
  var p = String(path || "")
  var h = String(home || "").replace(/\/+$/, "")
  if (h && (p === h || p.indexOf(h + "/") === 0)) return "~" + p.slice(h.length)
  return p
}

// --- input classification ----------------------------------------------------

function trimQuotes(s) {
  if (s.length >= 2) {
    var a = s.charAt(0)
    var b = s.charAt(s.length - 1)
    if ((a === "\"" && b === "\"") || (a === "'" && b === "'")) return s.slice(1, -1).trim()
  }
  return s
}

// Undo common IOC "defanging": hxxp://, example[.]com, 1.2.3[.]4, [:], [/].
function refang(s) {
  return String(s)
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/^hxxp(s?):\/\//i, "http$1://")
}

function isIPv4(s) {
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s))
  if (!m) return false
  for (var i = 1; i <= 4; i++) {
    if (parseInt(m[i], 10) > 255) return false
  }
  return true
}

function isIPv6(value) {
  var s = String(value)
  if (s.indexOf(":") < 0 || s.indexOf("%") >= 0) return false
  var body = s
  var extra = 0
  var tail4 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s)
  if (tail4) {
    if (!isIPv4(tail4[1])) return false
    body = s.slice(0, s.length - tail4[1].length)
    if (body.charAt(body.length - 1) !== ":") return false
    // Stand-in group so the trailing colon splits cleanly; the IPv4 part
    // counts as two 16-bit groups, the stand-in already counts as one.
    body = body + "0"
    extra = 1
  }
  var parts = body.split("::")
  if (parts.length > 2) return false
  var head = parts[0] === "" ? [] : parts[0].split(":")
  var tail = parts.length === 2 && parts[1] !== "" ? parts[1].split(":") : []
  var groups = head.concat(tail)
  for (var i = 0; i < groups.length; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return false
  }
  var count = groups.length + extra
  return parts.length === 2 ? count < 8 : count === 8
}

function isHostname(value) {
  var s = String(value)
  if (s.length < 3 || s.length > 253) return false
  var labels = s.split(".")
  if (labels.length < 2) return false
  for (var i = 0; i < labels.length; i++) {
    var l = labels[i]
    if (l.length < 1 || l.length > 63) return false
    if (!/^[a-z0-9_\u00a1-\uffff](?:[a-z0-9_\u00a1-\uffff-]*[a-z0-9_\u00a1-\uffff])?$/i.test(l)) return false
  }
  var tld = labels[labels.length - 1]
  return /^(?:[a-z\u00a1-\uffff]{2,63}|xn--[a-z0-9-]{1,59})$/i.test(tld)
}

// Host part of "host", "host:port", "[v6]" or "[v6]:port"; "" when invalid.
function hostOf(authority) {
  var a = String(authority || "")
  if (a.charAt(0) === "[") {
    var end = a.indexOf("]")
    if (end < 0) return ""
    var after = a.slice(end + 1)
    if (after !== "" && !/^:\d{1,5}$/.test(after)) return ""
    return a.slice(1, end)
  }
  var colon = a.indexOf(":")
  if (colon >= 0) {
    if (!/^\d{1,5}$/.test(a.slice(colon + 1))) return ""
    a = a.slice(0, colon)
  }
  return a
}

function invalid(value, message) {
  return { kind: "", value: value, error: message }
}

// Classify free-form input into one lookup target:
//   { kind: "file" | "hash" | "url" | "domain" | "ip", value } or
//   { kind: "", value, error }.
function detectTargetType(input, homeDir) {
  var s = trimQuotes(String(input === undefined || input === null ? "" : input).trim())
  if (s === "") return invalid("", "Enter a URL, domain, IP address, file hash or file path.")

  if (/^file:\/\//i.test(s)) {
    var p = s.replace(/^file:\/\/(localhost)?/i, "")
    try { p = decodeURIComponent(p) } catch (e) { /* keep raw */ }
    return p.charAt(0) === "/" ? { kind: "file", value: p } : invalid(s, "Unsupported file URL.")
  }
  if (s === "~" || s.indexOf("~/") === 0) {
    if (!homeDir) return invalid(s, "Cannot expand ~ because HOME is not set.")
    return { kind: "file", value: String(homeDir).replace(/\/+$/, "") + s.slice(1) }
  }
  if (s.charAt(0) === "/") return { kind: "file", value: s }

  s = refang(s)

  if (isHash(s)) return { kind: "hash", value: s.toLowerCase() }

  var scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s)
  if (scheme) {
    var sc = scheme[1].toLowerCase()
    if (sc !== "http" && sc !== "https") return invalid(s, "Only http:// and https:// URLs can be looked up.")
    if (/[\s\u0000-\u001f\u007f]/.test(s)) return invalid(s, "URLs cannot contain spaces or control characters.")
    var authority = s.slice(scheme[0].length).split(/[\/?#]/)[0]
    if (authority.indexOf("@") >= 0) return invalid(s, "URLs with embedded credentials are not supported.")
    if (hostOf(authority) === "") return invalid(s, "That URL has no valid host.")
    if (s.length > 8192) return invalid(s, "URL is too long (8192 characters max).")
    return { kind: "url", value: s }
  }

  var bracket = /^\[([^\]]+)\]$/.exec(s)
  if (bracket && isIPv6(bracket[1])) return { kind: "ip", value: bracket[1].toLowerCase() }
  if (isIPv4(s)) return { kind: "ip", value: s }
  if (isIPv6(s)) return { kind: "ip", value: s.toLowerCase() }

  var host = s.replace(/\.$/, "")
  if (isHostname(host)) return { kind: "domain", value: host.toLowerCase() }

  // Scheme-less URL: "example.com/path", "example.com:8080", "1.2.3.4/x".
  if (!/\s/.test(s)) {
    var m = /^([^\/?#]+)([\/?#].*)?$/.exec(s)
    if (m && m[1].indexOf("@") < 0) {
      var h = hostOf(m[1])
      var validHost = h !== "" && (isHostname(h.replace(/\.$/, "")) || isIPv4(h) || isIPv6(h))
      if (validHost && (m[2] || m[1] !== h) && s.length + 7 <= 8192) return { kind: "url", value: "http://" + s }
    }
  }
  return invalid(s, "Not a URL, domain, IP address, file hash or absolute file path.")
}

function kindNoun(kind) {
  switch (kind) {
  case "url": return "URL"
  case "domain": return "domain"
  case "ip": return "IP address"
  case "hash": return "hash"
  case "file": return "file"
  }
  return "item"
}

function kindGlyph(kind) {
  switch (kind) {
  case "url": return Glyph.link
  case "domain": return Glyph.web
  case "ip": return Glyph.ip
  case "hash": return Glyph.hash
  case "file": return Glyph.file
  }
  return Glyph.magnify
}

// HTTP request for a lookup target; paths are relative to the API base.
function requestFor(kind, value) {
  switch (kind) {
  case "file":
  case "hash":
    return { method: "GET", path: "/files/" + encodeURIComponent(value) }
  case "url":
    return { method: "POST", path: "/urls/lookup", json: { url: value } }
  case "domain":
    return { method: "GET", path: "/domains/" + encodeURIComponent(value) }
  case "ip":
    return { method: "GET", path: "/ip_addresses/" + encodeURIComponent(value) }
  }
  return null
}

// --- reports -----------------------------------------------------------------

function normalizeStats(stats) {
  var out = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 }
  if (!stats || typeof stats !== "object") return out
  for (var k in stats) {
    if (!Object.prototype.hasOwnProperty.call(stats, k)) continue
    if (k === "total") continue
    var n = num(stats[k])
    out.total += n
    if (k === "malicious" || k === "suspicious" || k === "harmless" || k === "undetected") out[k] = n
  }
  // Cached normalized stats already contain total; do not count it twice.
  out.total = Math.max(out.total, num(stats.total))
  return out
}

var NON_DETECTION_LABELS = {
  "clean": true, "unrated": true, "undetected": true, "harmless": true,
  "type-unsupported": true, "timeout": true, "confirmed-timeout": true,
  "failure": true, "none": true, "-": true
}

// Most frequent informative detection labels (engine results, not names).
function topDetections(list, limit) {
  if (!list || !list.length) return []
  var counts = {}
  var order = []
  for (var i = 0; i < list.length; i++) {
    var label = String(list[i] === undefined || list[i] === null ? "" : list[i]).trim()
    var key = label.toLowerCase()
    if (label === "" || NON_DETECTION_LABELS[key]) continue
    if (!counts[key]) {
      counts[key] = { label: label, count: 0, first: order.length }
      order.push(key)
    }
    counts[key].count++
  }
  order.sort(function(a, b) {
    return counts[b].count - counts[a].count || counts[a].first - counts[b].first
  })
  var out = []
  for (var j = 0; j < order.length && out.length < (limit || 3); j++) out.push(counts[order[j]].label)
  return out
}

function aiVerdict(value) {
  var s = String(value || "").trim().toLowerCase()
  if (s === "") return ""
  if (/\bnot\b|\bnon[- ]?malicious\b|\bno threat/.test(s)) return "benign"
  if (s.indexOf("malicious") >= 0) return "malicious"
  if (s.indexOf("suspicious") >= 0) return "suspicious"
  if (/benign|clean|harmless|undetected|safe/.test(s)) return "benign"
  return "unknown"
}

var INSIGHT_RANK = { malicious: 3, suspicious: 2, benign: 1, unknown: 0 }

// Pick the most severe AI insight so an alarming one is never hidden.
function pickInsight(list) {
  if (!list || !list.length) return null
  var best = null
  var bestRank = -1
  for (var i = 0; i < list.length; i++) {
    var item = list[i]
    if (!item || typeof item !== "object") continue
    var v = aiVerdict(item.verdict) || "unknown"
    var rank = INSIGHT_RANK[v] || 0
    if (rank > bestRank) {
      best = item
      bestRank = rank
    }
  }
  if (!best) return null
  return {
    verdict: aiVerdict(best.verdict) || "unknown",
    rawVerdict: String(best.verdict || ""),
    source: String(best.source || ""),
    analysis: truncate(String(best.analysis || "").trim(), 700)
  }
}

// Most severe engine category VirusTotal returned. This is not a judgement by
// the plugin: labels shown to the user are the raw counts (see verdictLabel).
// AI insights never change it; they are shown as returned.
function verdictFor(stats) {
  if (stats.malicious > 0) return "malicious"
  if (stats.suspicious > 0) return "suspicious"
  if (usableEngineCount({ stats: stats }) > 0) return "undetected"
  return "unknown"
}

function flaggedCount(r) {
  return r && r.stats ? r.stats.malicious + r.stats.suspicious : 0
}

function insightFlags(r) {
  return !!(r && r.insight && (r.insight.verdict === "malicious" || r.insight.verdict === "suspicious"))
}

// True when VirusTotal itself returned detections (engines or AI insight).
function hasFlags(r) {
  return !!r && r.status === "found" && (flaggedCount(r) > 0 || insightFlags(r))
}

function safeReportUrl(url) {
  var s = String(url || "")
  return /^https:\/\/([a-z0-9-]+\.)*virustotal\.com\//i.test(s) ? s : ""
}

function fallbackReportUrl(kind, id) {
  var base = "https://www.virustotal.com/gui/"
  var v = String(id || "")
  if ((kind === "file" || kind === "hash") && v) return base + "file/" + encodeURIComponent(v)
  if (kind === "domain" && v) return base + "domain/" + encodeURIComponent(v)
  if (kind === "ip" && v) return base + "ip-address/" + encodeURIComponent(v)
  if (kind === "url" && /^[a-f0-9]{64}$/i.test(v)) return base + "url/" + v
  return base + "search/" + encodeURIComponent(v)
}

function baseResult(kind, target, extra) {
  var r = {
    kind: kind,
    target: String(target || ""),
    name: "",
    path: "",
    sha256: "",
    size: -1,
    status: "",
    verdict: "unknown",
    stats: normalizeStats(null),
    engines: 0,
    topDetections: [],
    typeDescription: "",
    insight: null,
    reportUrl: "",
    analysisDate: "",
    analysisId: "",
    message: "",
    canUpload: false,
    time: 0,
    source: "manual"
  }
  if (extra) {
    for (var k in extra) {
      if (Object.prototype.hasOwnProperty.call(extra, k) && extra[k] !== undefined) r[k] = extra[k]
    }
  }
  if (kind === "hash" && !r.sha256 && /^[a-f0-9]{64}$/.test(r.target)) r.sha256 = r.target
  return r
}

function resultFromReport(kind, target, data, extra) {
  var d = data || {}
  var r = baseResult(kind, target, extra)
  r.status = "found"
  r.stats = normalizeStats(d.last_analysis_stats)
  r.engines = d.coverage && num(d.coverage.engines) ? num(d.coverage.engines) : r.stats.total
  r.topDetections = topDetections(d.detections, 3)
  r.typeDescription = d.type_description ? String(d.type_description) : ""
  r.insight = pickInsight(d.ai_insights)
  r.verdict = verdictFor(r.stats)
  var id = String(d.id || "")
  if ((kind === "file" || kind === "hash") && /^[a-f0-9]{64}$/i.test(id)) r.sha256 = id.toLowerCase()
  r.analysisDate = d.analysis_date ? String(d.analysis_date) : ""
  var fallbackId = kind === "domain" ? (d.domain || r.target)
    : kind === "ip" ? (d.ip || r.target)
    : kind === "url" ? id
    : (r.sha256 || r.target)
  r.reportUrl = safeReportUrl(d.report_url) || fallbackReportUrl(kind, fallbackId)
  r.canUpload = false
  return r
}

function notFoundResult(kind, target, extra) {
  var r = baseResult(kind, target, extra)
  r.status = "not_found"
  r.verdict = "unknown"
  var isFile = kind === "file"
  r.canUpload = isFile && !!r.sha256 && !!r.path && r.size > 0 && r.size <= MAX_UPLOAD_BYTES
  if (isFile) {
    if (r.canUpload) r.message = "VirusTotal has never seen this file. Upload it to get it analyzed."
    else if (r.size > MAX_UPLOAD_BYTES) r.message = "VirusTotal has never seen this file. It is larger than the 32 MB upload limit."
    else r.message = "VirusTotal has no report for this file yet."
  } else if (kind === "hash") {
    r.message = "VirusTotal has no report for this hash. A hash alone cannot be analyzed: enter the file path (e.g. ~/Downloads/file) to upload it."
  } else {
    r.message = "VirusTotal has no report for this " + kindNoun(kind) + " yet."
  }
  return r
}

function analyzingResult(base, analysisId, polls, maxPolls, pendingReason) {
  var r = copy(base)
  r.status = "analyzing"
  r.verdict = "unknown"
  r.canUpload = false
  r.analysisId = String(analysisId || r.analysisId || "")
  var stalled = maxPolls > 0 && polls >= maxPolls
  if (stalled) r.message = "Still analyzing. Check again in a few minutes."
  else if (pendingReason === "not_available_yet") r.message = "Uploaded. Waiting for VirusTotal to start the analysis."
  else r.message = "Uploaded. VirusTotal is analyzing the file."
  return r
}

function unknownSubmissionResult(base, message) {
  var r = copy(base)
  r.status = "unknown_submission"
  r.verdict = "unknown"
  r.canUpload = false
  r.message = message || "The upload did not finish cleanly. Check its status before uploading again."
  return r
}

function resultFromAnalysis(base, analysis, now) {
  var a = analysis || {}
  var r = copy(base)
  r.analysisId = String(a.analysis_id || r.analysisId || "")
  if (a.status !== "completed") return analyzingResult(r, r.analysisId, 0, 0, a.pending_reason)
  r.status = "found"
  r.stats = normalizeStats(a.stats)
  r.engines = a.coverage && num(a.coverage.engines) ? num(a.coverage.engines) : r.stats.total
  r.topDetections = topDetections(a.detections, 3)
  r.verdict = verdictFor(r.stats)
  if (/^[a-f0-9]{64}$/i.test(String(a.sha256 || ""))) r.sha256 = String(a.sha256).toLowerCase()
  r.analysisDate = a.analysis_date ? String(a.analysis_date) : ""
  r.reportUrl = safeReportUrl(a.report_url) || fallbackReportUrl(r.kind, r.sha256 || r.target)
  r.canUpload = false
  r.message = ""
  r.time = now || r.time
  return r
}

// --- presentation ------------------------------------------------------------

function verdictLabel(r) {
  if (!r) return ""
  switch (r.status) {
  case "analyzing": return "Analyzing"
  case "not_found": return "Not found"
  case "unknown_submission": return "Upload status unknown"
  case "error": return "Error"
  }
  var denom = ratedCount(r)
  if (!usableEngineCount(r)) return "No engine results"
  var flagged = flaggedCount(r)
  return flagged > 0 ? flagged + "/" + denom + " flagged" : "No detections"
}

// Theme role for a result; Panel.qml maps roles to Color tokens.
function verdictRole(r) {
  if (!r) return "muted"
  if (r.status === "analyzing") return "pending"
  if (r.status === "error") return "danger"
  if (r.status !== "found") return "muted"
  if (r.verdict === "malicious") return "danger"
  if (r.verdict === "suspicious") return "warning"
  if (r.verdict === "undetected") return "ok"
  return "muted"
}

function verdictGlyph(r) {
  if (!r) return Glyph.shieldOutline
  switch (r.status) {
  case "analyzing": return Glyph.progressClock
  case "not_found": return Glyph.helpCircle
  case "unknown_submission": return Glyph.alertCircle
  case "error": return Glyph.alertCircle
  }
  switch (r.verdict) {
  case "malicious": return Glyph.alertOctagon
  case "suspicious": return Glyph.alert
  case "undetected": return Glyph.shieldCheck
  }
  return Glyph.shieldOutline
}

function ratedCount(r) {
  var s = r && r.stats ? r.stats : normalizeStats(null)
  var rated = s.malicious + s.suspicious + s.harmless + s.undetected
  return rated || (r ? r.engines : 0) || s.total
}

// Timeouts, failures and engine inventory counts are not returned verdicts.
function usableEngineCount(r) {
  var s = r && r.stats ? r.stats : {}
  return num(s.malicious) + num(s.suspicious) + num(s.harmless) + num(s.undetected)
}

function summaryLine(r) {
  if (!r) return ""
  if (r.status !== "found") return r.message || ""
  var s = r.stats
  var denom = ratedCount(r)
  if (!usableEngineCount(r)) return "VirusTotal returned no engine verdicts for this " + kindNoun(r.kind) + "."
  var line = "Malicious " + s.malicious + " \u00b7 Suspicious " + s.suspicious
    + " \u00b7 Harmless " + s.harmless + " \u00b7 Undetected " + s.undetected
  if (flaggedCount(r) === 0) line += ". No detections is not a guarantee of safety."
  return line
}

// MD5, SHA-1 or SHA-256 in hex.
function isHash(s) {
  return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(String(s === undefined || s === null ? "" : s))
}

function displayTarget(r) {
  if (!r) return ""
  if (r.kind === "file") return r.name || basename(r.path || r.target)
  return r.target
}

function uploadConsentMessage(r) {
  var name = r ? (r.name || basename(r.path)) : ""
  var size = r && r.size >= 0 ? " (" + formatBytes(r.size) + ")" : ""
  return "Upload \u201c" + name + "\u201d" + size + " to VirusTotal?\n\n"
    + "This is a standard, non-private submission: the file is shared with the "
    + "VirusTotal security community and partners. Don't upload personal "
    + "documents, internal code or anything containing credentials."
}

function notificationFor(r) {
  var name = displayTarget(r)
  var denom = ratedCount(r)
  var flagged = flaggedCount(r)
  var noun = r && r.source === "watcher" ? "download" : (r && r.source === "plugins" ? "plugin file" : "file")
  if (hasFlags(r)) {
    var parts = []
    if (flagged > 0) {
      parts.push(flagged + " of " + denom + " security vendors flagged it (malicious "
        + r.stats.malicious + ", suspicious " + r.stats.suspicious + ").")
    }
    if (insightFlags(r)) parts.push("VirusTotal AI insight: " + (r.insight.rawVerdict || r.insight.verdict) + ".")
    return { urgency: r.stats.malicious > 0 ? "critical" : "normal",
             glyph: r.stats.malicious > 0 ? Glyph.alertOctagon : Glyph.alert,
             title: "Flagged " + noun + ": " + name, body: parts.join(" ") }
  }
  if (r && r.status === "not_found") {
    return { urgency: "low", glyph: Glyph.helpCircle, title: "Unknown to VirusTotal: " + name,
             body: "No report exists yet. You can upload it from the VirusTotal panel." }
  }
  if (!r || r.status !== "found" || !usableEngineCount(r)) {
    return { urgency: "low", glyph: Glyph.helpCircle, title: "Incomplete scan: " + name,
             body: "No engine verdicts are available. Open the VirusTotal panel for details." }
  }
  return { urgency: "low", glyph: Glyph.shieldCheck, title: "No detections: " + name,
           body: "0 of " + denom + " security vendors flagged it." }
}

// --- theme -------------------------------------------------------------------

// A #rrggbb colour whose hue is yellow or amber (33–65°), clearly saturated
// and neither near black nor near white.
function isYellow(hex) {
  var m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(String(hex || ""))
  if (!m) return false
  var r = parseInt(m[1], 16) / 255
  var g = parseInt(m[2], 16) / 255
  var b = parseInt(m[3], 16) / 255
  var max = Math.max(r, g, b)
  var min = Math.min(r, g, b)
  var d = max - min
  if (d === 0) return false
  var l = (max + min) / 2
  var s = d / (1 - Math.abs(2 * l - 1))
  var h = max === r ? 60 * (((g - b) / d) % 6)
    : max === g ? 60 * ((b - r) / d + 2)
    : 60 * ((r - g) / d + 4)
  if (h < 0) h += 360
  return h >= 33 && h <= 65 && s >= 0.3 && l >= 0.25 && l <= 0.9
}

// The theme's own yellow from its colors.toml (`yellow`, or `color3` in
// terminal-style palettes), lower-cased, or "" when it has none. Omarchy's
// Color singleton exposes no yellow, and several themes' "yellow" is not one
// (matte-black's is red, lumon's blue, vantablack's grey): those return "".
function themeYellow(raw) {
  var found = {}
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var m = /^\s*(yellow|color3)\s*=\s*["']?(#[0-9A-Fa-f]{6})(?![0-9A-Fa-f])/.exec(lines[i])
    if (m && !found[m[1]]) found[m[1]] = m[2]
  }
  var candidates = [found.yellow, found.color3]
  for (var j = 0; j < candidates.length; j++) {
    if (isYellow(candidates[j])) return candidates[j].toLowerCase()
  }
  return ""
}

// --- errors ------------------------------------------------------------------

// curl >= 7.84: capture the final response's Retry-After without logging headers.
var CURL_WRITE_OUT = "\n%{http_code}\nretry-after:%header{retry-after}"

function retryAfterSeconds(value, now) {
  var s = String(value || "").trim()
  if (/^\d+$/.test(s)) return num(s)
  // Reject numeric/ambiguous strings which Date.parse accepts as calendar years.
  if (!/^[A-Za-z]{3},?\s/.test(s)) return 0
  var date = Date.parse(s)
  return isFinite(date) ? Math.max(0, Math.ceil((date - (now === undefined ? Date.now() : now)) / 1000)) : 0
}

function parseCurlOutput(out, now) {
  var s = String(out || "").replace(/\s+$/, "")
  var trailer = /\nretry-after:([^\r\n]*)$/.exec(s)
  if (trailer) s = s.slice(0, trailer.index)
  var idx = s.lastIndexOf("\n")
  var codeText = (idx >= 0 ? s.slice(idx + 1) : s).trim()
  if (!/^\d{3}$/.test(codeText)) return { http: 0, body: s }
  var result = { http: parseInt(codeText, 10), body: idx >= 0 ? s.slice(0, idx) : "" }
  if (trailer) result.retryAfter = retryAfterSeconds(trailer[1], now)
  return result
}

function apiError(http, json, exitCode, retryAfter) {
  var d = json && typeof json === "object" ? json.detail : null
  var message = ""
  var retry = 0
  var code = ""
  if (typeof d === "string") {
    message = d
  } else if (Array.isArray(d)) {
    message = d.length && d[0] && d[0].msg ? String(d[0].msg) : ""
  } else if (d && typeof d === "object") {
    message = String(d.message || d.error || "")
    code = String(d.code || "")
    retry = num(d.retry_after_seconds) || num(d.retry_after)
  }
  retry = Math.max(retry, num(retryAfter))
  if (!http) {
    if (exitCode === 127)
      return { kind: "missing_tool", code: code, retryAfter: 0, message: "curl is not installed. Install it and try again." }
    if (exitCode === 28 || exitCode === 124)
      return { kind: "timeout", code: code, retryAfter: 0, message: "The request timed out. Check your connection and try again." }
    return { kind: "network", code: code, retryAfter: 0, message: "Could not reach ai.virustotal.com. Check your connection." }
  }
  if (http === 401 || http === 403)
    return { kind: "auth", code: code, retryAfter: 0, message: "VirusTotal AI rejected the saved token. Disconnect and connect again in Settings." }
  if (http === 429)
    return { kind: "rate_limit", code: code, retryAfter: retry,
             message: "Rate limit reached" + (retry ? "; try again in " + formatDuration(retry) : "; try again later") + "." }
  if (http === 413)
    return { kind: "too_large", code: code, retryAfter: 0, message: "The file is larger than the 32 MB upload limit." }
  if (http >= 500)
    return { kind: "unavailable", code: code, retryAfter: retry, message: "VirusTotal AI is temporarily unavailable (HTTP " + http + "). Try again later." }
  return { kind: "http", code: code, retryAfter: retry,
           message: (message ? truncate(message, 200) : "The request failed") + " (HTTP " + http + ")." }
}

function registerErrorMessage(exitCode, out) {
  switch (exitCode) {
  case 10: return "Could not create the ~/.config/vtai directory."
  case 11: return "Could not reach ai.virustotal.com. Check your connection."
  case 13: return "VirusTotal AI answered without a token. Try again later."
  case 14: return "Could not save the credential file."
  case 124: return "Registration timed out. Try again."
  case 12:
    var lines = String(out || "").split("\n")
    var m = /^http (\d{3})/.exec(lines[0] || "")
    var http = m ? parseInt(m[1], 10) : 0
    if (http === 429) {
      var e = apiError(429, parseJson(lines.slice(1).join("\n")), 0)
      return "Too many registrations from this network" + (e.retryAfter ? "; try again in " + formatDuration(e.retryAfter) : "; try again later") + "."
    }
    if (http === 503) return "Registration is temporarily unavailable. Try again later."
    return "Registration failed" + (http ? " (HTTP " + http + ")" : "") + "."
  }
  return "Registration failed (exit " + exitCode + ")."
}

function hashErrorMessage(exitCode, path) {
  var name = basename(path)
  switch (exitCode) {
  case 3: return "\u201c" + name + "\u201d is not a regular file or does not exist."
  case 4: return "\u201c" + name + "\u201d is not readable."
  case 6: return "\u201c" + name + "\u201d is still changing. Try again when it finishes."
  case 7: return "\u201c" + name + "\u201d is empty."
  case 8: return "\u201c" + name + "\u201d is too large to check automatically."
  case 124: return "Hashing \u201c" + name + "\u201d timed out."
  }
  return "Could not hash \u201c" + name + "\u201d."
}

// --- polling -----------------------------------------------------------------

// Local backoff is a minimum; every poll must also respect the server hint.
function pollDelayMs(polls, nextPollSeconds) {
  var n = Number(polls) || 0
  var seconds = Math.max(num(nextPollSeconds), n < 6 ? 5 : (n < 12 ? 10 : 15))
  return seconds * 1000
}

// Watcher retries for files that are still being written.
function watchBackoffMs(attempts) {
  var steps = [5, 10, 20, 30, 60]
  var n = Math.max(1, Number(attempts) || 1)
  return steps[Math.min(n, steps.length) - 1] * 1000
}

// --- history -----------------------------------------------------------------

function compactResult(r) {
  var c = copy(r)
  if (c && c.insight && c.insight.analysis) c.insight.analysis = truncate(c.insight.analysis, 400)
  return c
}

function isFileKind(kind) {
  return kind === "file" || kind === "hash"
}

// Newest first. Repeats of the same target within DEDUPE_WINDOW_MS collapse,
// and a newer result for the same file (same SHA-256) replaces any older
// entry that was still waiting for a verdict (not found, analyzing, unknown
// upload status), so a finished analysis does not leave stale rows behind.
function addHistory(list, r, now, limit) {
  var t = now || r.time || Date.now()
  var entry = compactResult(r)
  entry.time = t
  var out = [entry]
  var src = Array.isArray(list) ? list : []
  for (var i = 0; i < src.length; i++) {
    var e = src[i]
    if (!e || typeof e !== "object") continue
    var same = e.kind === r.kind && e.target === r.target
    if (same && Math.abs(t - (Number(e.time) || 0)) < DEDUPE_WINDOW_MS) continue
    if (r.sha256 && e.sha256 === r.sha256 && isFileKind(r.kind) && isFileKind(e.kind) && e.status !== "found") continue
    out.push(e)
  }
  return out.slice(0, limit || HISTORY_LIMIT)
}

function findRecentBySha(list, sha, now, windowMs) {
  if (!sha || !Array.isArray(list)) return null
  var ref = now || Date.now()
  for (var i = 0; i < list.length; i++) {
    var e = list[i]
    if (e && e.sha256 === sha && e.status === "found" && ref - (Number(e.time) || 0) < windowMs) return e
  }
  return null
}

function sanitizeEntries(list) {
  if (!Array.isArray(list)) return []
  var out = []
  for (var i = 0; i < list.length && out.length < HISTORY_LIMIT; i++) {
    var e = list[i]
    if (e && typeof e === "object" && typeof e.kind === "string" && typeof e.target === "string") out.push(e)
  }
  return out
}

function parseState(text) {
  var j = parseJson(text)
  if (Array.isArray(j)) return { entries: sanitizeEntries(j), alert: null, alertAcknowledged: true }
  if (!j || typeof j !== "object") return { entries: [], alert: null, alertAcknowledged: true }
  var alert = j.alert && typeof j.alert === "object" && typeof j.alert.target === "string" ? j.alert : null
  return { entries: sanitizeEntries(j.entries), alert: alert, alertAcknowledged: !alert || j.alertAcknowledged !== false }
}

function serializeState(entries, alert, alertAcknowledged) {
  return JSON.stringify({
    version: 1,
    entries: sanitizeEntries(entries),
    alert: alert || null,
    alertAcknowledged: alertAcknowledged !== false
  }, null, 2) + "\n"
}

// Scanner engines: "vtai" (the agent token) or "classic" (a VirusTotal API key).
var PLUGIN_BACKENDS = ["vtai", "classic"]

function intSetting(value, lo, hi, fallback) {
  var n = Number(value)
  if (!isFinite(n)) return fallback
  n = Math.floor(n)
  return n < lo ? lo : (n > hi ? hi : n)
}

function normalizeConfig(j) {
  var c = j && typeof j === "object" && !Array.isArray(j) ? j : {}
  return {
    watcherEnabled: c.watcherEnabled === true,
    notifyAll: c.notifyAll === true,
    pluginScanEnabled: c.pluginScanEnabled === true,
    pluginAutoUpload: c.pluginAutoUpload === true,
    pluginBackend: PLUGIN_BACKENDS.indexOf(c.pluginBackend) >= 0 ? c.pluginBackend : "vtai",
    maxParallel: intSetting(c.maxParallel, 1, 8, 4),
    classicPerMin: intSetting(c.classicPerMin, 1, 100000, 4),
    classicPerDay: intSetting(c.classicPerDay, 1, 10000000, 500),
    // "Ask <agent>" buttons (on unless turned off) and the one-time
    // auto-approve warning.
    agentButtons: c.agentButtons !== false,
    agentHandoffAck: c.agentHandoffAck === true
  }
}

function parseConfig(text) {
  return normalizeConfig(parseJson(text))
}

function serializeConfig(config) {
  var c = normalizeConfig(config)
  var out = { version: 1 }
  for (var k in c) {
    if (Object.prototype.hasOwnProperty.call(c, k)) out[k] = c[k]
  }
  return JSON.stringify(out, null, 2) + "\n"
}

// --- downloads ---------------------------------------------------------------

var TEMP_SUFFIXES = [".crdownload", ".part", ".partial", ".tmp", ".opdownload", ".download", ".filepart", ".aria2", ".!ut"]

function isIgnoredDownload(name) {
  var n = String(name || "")
  if (n === "" || n.charAt(0) === "." || n.charAt(n.length - 1) === "~") return true
  var lower = n.toLowerCase()
  for (var i = 0; i < TEMP_SUFFIXES.length; i++) {
    var suffix = TEMP_SUFFIXES[i]
    if (lower.length > suffix.length && lower.slice(-suffix.length) === suffix) return true
  }
  return false
}

// Compare the current folder listing against the previous one.
//   prevSeen: map path -> true from the last call, or null for the first
//             call, which only records a baseline (existing files never alert).
//   list:     [{ name, path }]
// Returns { seen, added, dropped }. At most opts.maxNew files are reported
// per call so a bulk move into Downloads cannot drain the lookup quota.
function diffDownloads(prevSeen, list, opts) {
  var maxNew = opts && opts.maxNew > 0 ? opts.maxNew : 20
  var seen = {}
  var added = []
  var dropped = 0
  var src = Array.isArray(list) ? list : []
  for (var i = 0; i < src.length; i++) {
    var item = src[i]
    if (!item || !item.path || isIgnoredDownload(item.name || basename(item.path))) continue
    seen[item.path] = true
    if (!prevSeen || prevSeen[item.path]) continue
    if (added.length < maxNew) added.push({ name: item.name || basename(item.path), path: item.path })
    else dropped++
  }
  return { seen: seen, added: added, dropped: dropped }
}

// Newest non-temporary files first.
function recentDownloads(list, count) {
  var src = Array.isArray(list) ? list : []
  var out = []
  for (var i = 0; i < src.length; i++) {
    var f = src[i]
    if (f && f.path && !isIgnoredDownload(f.name || basename(f.path)) && Number(f.size) > 0) out.push(f)
  }
  out.sort(function(a, b) { return (Number(b.mtime) || 0) - (Number(a.mtime) || 0) })
  return out.slice(0, count || 4)
}
