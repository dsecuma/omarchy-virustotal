// Unit tests for Model.js. Run with: node tests/model.test.js
// Model.js is a QML JavaScript library (".pragma library"), so load it into a
// plain VM context after dropping the pragma line.
"use strict"

const assert = require("assert")
const fs = require("fs")
const path = require("path")
const vm = require("vm")

const source = fs.readFileSync(path.join(__dirname, "..", "Model.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "")
const M = vm.createContext({})
vm.runInContext(source, M, { filename: "Model.js" })

let passed = 0
let failed = 0
function test(name, fn) {
  try {
    fn()
    passed++
  } catch (e) {
    failed++
    console.error("FAIL " + name + "\n  " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join("\n  ") : e))
  }
}
// Objects created inside the VM have a different prototype chain; compare
// through JSON so deepStrictEqual does not trip over realms.
function same(actual, expected) {
  assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected)
}
function kind(input, home) {
  const t = M.detectTargetType(input, home)
  return t.kind ? t.kind + ":" + t.value : "error"
}

test("detects files", () => {
  assert.strictEqual(kind("/home/me/Downloads/a b.exe"), "file:/home/me/Downloads/a b.exe")
  assert.strictEqual(kind("~/Downloads/x.zip", "/home/me"), "file:/home/me/Downloads/x.zip")
  assert.strictEqual(kind("~/x", "/home/me/"), "file:/home/me/x")
  assert.strictEqual(kind("~/x", ""), "error")
  assert.strictEqual(kind("file:///home/me/My%20File.pdf"), "file:/home/me/My File.pdf")
  assert.strictEqual(kind("'/tmp/quoted file'"), "file:/tmp/quoted file")
  assert.strictEqual(kind("\"/tmp/x\""), "file:/tmp/x")
})

test("detects hashes", () => {
  assert.strictEqual(kind("44D88612FEA8A8F36DE82E1278ABB02F"), "hash:44d88612fea8a8f36de82e1278abb02f")
  assert.strictEqual(kind("3395856ce81f2b7382dee72602f798b642f14140"), "hash:3395856ce81f2b7382dee72602f798b642f14140")
  const sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  assert.strictEqual(kind(sha), "hash:" + sha)
  assert.strictEqual(kind("abc123"), "error")
})

test("detects URLs", () => {
  assert.strictEqual(kind("https://example.com/a?b=c"), "url:https://example.com/a?b=c")
  assert.strictEqual(kind("hxxps://evil[.]example/payload"), "url:https://evil.example/payload")
  assert.strictEqual(kind("hxxp[:]//bad[.]site/x"), "url:http://bad.site/x")
  assert.strictEqual(kind("example.com/path"), "url:http://example.com/path")
  assert.strictEqual(kind("example.com:8080"), "url:http://example.com:8080")
  assert.strictEqual(kind("1.2.3.4/login"), "url:http://1.2.3.4/login")
  assert.strictEqual(kind("[2001:db8::1]:443/x"), "url:http://[2001:db8::1]:443/x")
  assert.strictEqual(kind("ftp://example.com/file"), "error")
  assert.strictEqual(kind("https://user:pw@example.com/"), "error")
  assert.strictEqual(kind("https://exa mple.com/"), "error")
  assert.strictEqual(kind("https:///nohost"), "error")
})

test("detects domains", () => {
  assert.strictEqual(kind("Example.COM"), "domain:example.com")
  assert.strictEqual(kind("sub.example.co.uk."), "domain:sub.example.co.uk")
  assert.strictEqual(kind("evil[.]example"), "domain:evil.example")
  assert.strictEqual(kind("xn--80ak6aa92e.com"), "domain:xn--80ak6aa92e.com")
  assert.strictEqual(kind("m\u00fcnchen.de"), "domain:m\u00fcnchen.de")
  assert.strictEqual(kind("localhost"), "error")
  assert.strictEqual(kind("not a domain"), "error")
  assert.strictEqual(kind("-bad.com"), "error")
})

test("detects IP addresses", () => {
  assert.strictEqual(kind("8.8.8.8"), "ip:8.8.8.8")
  assert.strictEqual(kind("8.8.8[.]8"), "ip:8.8.8.8")
  assert.strictEqual(kind("256.1.1.1"), "error")
  assert.strictEqual(kind("2001:DB8::1"), "ip:2001:db8::1")
  assert.strictEqual(kind("[2001:db8::1]"), "ip:2001:db8::1")
  assert.strictEqual(kind("::ffff:192.0.2.1"), "ip:::ffff:192.0.2.1")
  assert.strictEqual(kind("1:2:3:4:5:6:7:8"), "ip:1:2:3:4:5:6:7:8")
  assert.strictEqual(kind("1:2:3:4:5:6:7:8:9"), "error")
  assert.strictEqual(kind("fe80::1%eth0"), "error")
  assert.strictEqual(M.isIPv6("1::2::3"), false)
})

test("empty input explains what to enter", () => {
  const t = M.detectTargetType("   ")
  assert.strictEqual(t.kind, "")
  assert.ok(/Enter a URL/.test(t.error))
})

test("builds lookup requests", () => {
  same(M.requestFor("hash", "abc"), { method: "GET", path: "/files/abc" })
  same(M.requestFor("url", "https://x.y/"), { method: "POST", path: "/urls/lookup", json: { url: "https://x.y/" } })
  same(M.requestFor("domain", "example.com"), { method: "GET", path: "/domains/example.com" })
  same(M.requestFor("ip", "2001:db8::1"), { method: "GET", path: "/ip_addresses/2001%3Adb8%3A%3A1" })
})

test("normalizes stats and verdicts", () => {
  const stats = M.normalizeStats({ malicious: 3, suspicious: 1, undetected: 60, harmless: 0, "type-unsupported": 8 })
  same(stats, { malicious: 3, suspicious: 1, harmless: 0, undetected: 60, total: 72 })
  assert.strictEqual(M.verdictFor(stats), "malicious")
  assert.strictEqual(M.verdictFor(M.normalizeStats({ suspicious: 2, undetected: 5 })), "suspicious")
  assert.strictEqual(M.verdictFor(M.normalizeStats({ undetected: 70 })), "undetected")
  assert.strictEqual(M.verdictFor(M.normalizeStats(null)), "unknown")
})

test("classifies AI insight verdicts", () => {
  assert.strictEqual(M.aiVerdict("Malicious"), "malicious")
  assert.strictEqual(M.aiVerdict("not malicious"), "benign")
  assert.strictEqual(M.aiVerdict("benign"), "benign")
  assert.strictEqual(M.aiVerdict("Suspicious"), "suspicious")
  assert.strictEqual(M.aiVerdict("weird"), "unknown")
  assert.strictEqual(M.aiVerdict(null), "")
  const picked = M.pickInsight([{ verdict: "benign", source: "a" }, { verdict: "malicious", source: "b", analysis: "x" }])
  assert.strictEqual(picked.source, "b")
  assert.strictEqual(M.pickInsight([]), null)
})

test("summarizes top detections", () => {
  same(M.topDetections(["clean", "Trojan.A", "unrated", "trojan.a", "Worm.B", "Adware.C", "Worm.B", "Worm.B", null], 3),
       ["Worm.B", "Trojan.A", "Adware.C"])
  same(M.topDetections(["malicious", "phishing", "clean", "phishing"], 3), ["phishing", "malicious"])
  same(M.topDetections(null, 3), [])
})

test("builds a result from a file report", () => {
  const data = {
    id: "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F",
    last_analysis_stats: { malicious: 60, suspicious: 0, undetected: 5, harmless: 0 },
    detections: ["EICAR-Test-File", "EICAR-Test-File", "clean"],
    type_description: "Text",
    ai_insights: [{ verdict: "malicious", source: "Code Insight", analysis: "Test file." }],
    analysis_date: "2026-09-01T10:00:00Z",
    report_url: "https://www.virustotal.com/gui/file/275a",
    coverage: { engines: 70, categories: ["malicious"] }
  }
  const r = M.resultFromReport("file", "/tmp/eicar.com", data, { path: "/tmp/eicar.com", name: "eicar.com", size: 68 })
  assert.strictEqual(r.status, "found")
  assert.strictEqual(r.verdict, "malicious")
  assert.strictEqual(r.sha256, data.id.toLowerCase())
  assert.strictEqual(r.engines, 70)
  same(r.topDetections, ["EICAR-Test-File"])
  assert.strictEqual(r.insight.verdict, "malicious")
  assert.strictEqual(r.reportUrl, data.report_url)
  assert.strictEqual(M.verdictLabel(r), "60/65 flagged")
  assert.strictEqual(M.verdictRole(r), "danger")
  assert.strictEqual(M.summaryLine(r), "Malicious 60 \u00b7 Suspicious 0 \u00b7 Harmless 0 \u00b7 Undetected 5")
  assert.strictEqual(M.hasFlags(r), true)
})

test("labels only report VirusTotal data (8.8.4.4 case)", () => {
  const r = M.resultFromReport("ip", "8.8.4.4", {
    id: "8.8.4.4", ip: "8.8.4.4", last_analysis_stats: { malicious: 2, suspicious: 0, undetected: 34, harmless: 55 },
    detections: ["clean", "phishing", "unrated", "malicious"], ai_insights: null, coverage: { engines: 91 }
  })
  assert.strictEqual(M.verdictLabel(r), "2/91 flagged")
  assert.ok(!/^Malicious$|^Suspicious$/.test(M.verdictLabel(r)))
  same(r.topDetections, ["phishing", "malicious"])
  const aiOnly = M.resultFromReport("file", "/d/a", { id: "a".repeat(64), last_analysis_stats: { undetected: 60 },
    ai_insights: [{ verdict: "malicious", source: "Code Insight" }] }, { path: "/d/a", name: "a", size: 1 })
  assert.strictEqual(aiOnly.verdict, "undetected")
  assert.strictEqual(M.verdictLabel(aiOnly), "No detections")
  assert.strictEqual(M.hasFlags(aiOnly), true)
  assert.ok(/AI insight: malicious/.test(M.notificationFor(aiOnly).body))
})

test("never trusts non-VirusTotal report URLs", () => {
  const r = M.resultFromReport("domain", "example.com", {
    id: "example.com", domain: "example.com", last_analysis_stats: { undetected: 90 },
    detections: [], report_url: "https://evil.example/phish", coverage: { engines: 90, categories: [] }
  })
  assert.strictEqual(r.reportUrl, "https://www.virustotal.com/gui/domain/example.com")
  assert.strictEqual(r.verdict, "undetected")
  assert.strictEqual(M.verdictLabel(r), "No detections")
  assert.ok(/not a guarantee of safety/.test(M.summaryLine(r)))
})

test("not found results only allow uploads of small files", () => {
  const extra = { path: "/tmp/a.bin", name: "a.bin", size: 1000, sha256: "a".repeat(64) }
  const small = M.notFoundResult("file", "/tmp/a.bin", extra)
  assert.strictEqual(small.canUpload, true)
  assert.ok(/Upload it/.test(small.message))
  extra.size = 32000001
  const big = M.notFoundResult("file", "/tmp/a.bin", extra)
  assert.strictEqual(big.canUpload, false)
  assert.ok(/32 MB/.test(big.message))
  const hash = M.notFoundResult("hash", "b".repeat(64), {})
  assert.strictEqual(hash.canUpload, false)
  assert.ok(/file path/.test(hash.message))
  assert.strictEqual(M.notFoundResult("url", "https://x.y/", {}).message, "VirusTotal has no report for this URL yet.")
})

test("tracks analyses", () => {
  const base = M.notFoundResult("file", "/tmp/a.bin", { path: "/tmp/a.bin", name: "a.bin", size: 10, sha256: "c".repeat(64) })
  const pending = M.analyzingResult(base, "an-1", 2, 24, "processing")
  assert.strictEqual(pending.status, "analyzing")
  assert.strictEqual(pending.analysisId, "an-1")
  assert.strictEqual(M.analyzingResult(base, "an-1", 24, 24, null).message, "Still analyzing. Check again in a few minutes.")
  const done = M.resultFromAnalysis(pending, {
    status: "completed", analysis_id: "an-1", sha256: "c".repeat(64),
    stats: { malicious: 0, suspicious: 0, undetected: 50, harmless: 0 }, detections: [],
    coverage: { engines: 50, categories: [] }, report_url: null, analysis_date: "2026-09-29T10:00:00Z"
  }, 1234)
  assert.strictEqual(done.status, "found")
  assert.strictEqual(done.verdict, "undetected")
  assert.strictEqual(done.reportUrl, "https://www.virustotal.com/gui/file/" + "c".repeat(64))
  assert.strictEqual(done.time, 1234)
  const unknown = M.unknownSubmissionResult(base, "")
  assert.strictEqual(unknown.status, "unknown_submission")
  assert.strictEqual(M.verdictLabel(unknown), "Upload status unknown")
})

test("parses curl output", () => {
  same(M.parseCurlOutput("{\"a\":1}\n200"), { http: 200, body: "{\"a\":1}" })
  same(M.parseCurlOutput("\n204"), { http: 204, body: "" })
  same(M.parseCurlOutput("line1\nline2\n404\n"), { http: 404, body: "line1\nline2" })
  same(M.parseCurlOutput("\n000"), { http: 0, body: "" })
  assert.strictEqual(M.parseCurlOutput("").http, 0)
})

test("maps API errors", () => {
  assert.strictEqual(M.apiError(0, null, 6).kind, "network")
  assert.strictEqual(M.apiError(0, null, 28).kind, "timeout")
  assert.strictEqual(M.apiError(401, null, 0).kind, "auth")
  const rl = M.apiError(429, { detail: { error: "rate", status_code: 429, retry_after_seconds: 42 } }, 0)
  assert.strictEqual(rl.kind, "rate_limit")
  assert.strictEqual(rl.retryAfter, 42)
  assert.ok(/42 s/.test(rl.message))
  assert.strictEqual(M.apiError(503, { detail: "down" }, 0).kind, "unavailable")
  assert.strictEqual(M.apiError(400, { detail: "Bad input" }, 0).message, "Bad input (HTTP 400).")
  assert.strictEqual(M.apiError(422, { detail: [{ msg: "field required" }] }, 0).message, "field required (HTTP 422).")
  assert.strictEqual(M.apiError(409, { detail: { code: "x", message: "Conflict here", retryable: false } }, 0).message, "Conflict here (HTTP 409).")
})

test("maps registration errors", () => {
  assert.ok(/Too many registrations.*1 h/.test(M.registerErrorMessage(12, "http 429\n{\"detail\":{\"error\":\"x\",\"status_code\":429,\"retry_after\":\"3600\"}}")))
  assert.ok(/temporarily unavailable/.test(M.registerErrorMessage(12, "http 503\n")))
  assert.strictEqual(M.registerErrorMessage(12, "http 500\n"), "Registration failed (HTTP 500).")
  assert.ok(/credential file/.test(M.registerErrorMessage(14, "")))
})

test("builds the registration body", () => {
  same(JSON.parse(M.registerBody("1.0.0")), { agent_family: "omarchy", agent_version: "1.0.0", display_name: "Omarchy VirusTotal" })
  assert.strictEqual(JSON.parse(M.registerBody("1.0 beta; rm")).agent_version, "1.0.0")
  assert.ok(/^[a-zA-Z0-9 _-]+$/.test(M.AGENT_DISPLAY_NAME))
})

test("formats sizes and times", () => {
  assert.strictEqual(M.formatBytes(0), "0 B")
  assert.strictEqual(M.formatBytes(999), "999 B")
  assert.strictEqual(M.formatBytes(1500), "1.5 kB")
  assert.strictEqual(M.formatBytes(32000000), "32 MB")
  assert.strictEqual(M.formatBytes(999999), "1 MB")
  assert.strictEqual(M.formatBytes(1073741824), "1.1 GB")
  const now = Date.UTC(2026, 8, 29, 12, 0, 0)
  assert.strictEqual(M.timeAgo(now - 10000, now), "just now")
  assert.strictEqual(M.timeAgo(now - 5 * 60000, now), "5 min ago")
  assert.strictEqual(M.timeAgo(now - 3 * 3600000, now), "3 h ago")
  assert.strictEqual(M.timeAgo(now - 30 * 3600000, now), "yesterday")
  assert.strictEqual(M.timeAgo("2026-09-25T12:00:00Z", now), "4 d ago")
  assert.strictEqual(M.timeAgo(null, now), "")
  // VirusTotal reports use epoch seconds, sometimes as strings.
  assert.strictEqual(M.timeAgo(Math.floor((now - 2 * 3600000) / 1000), now), "2 h ago")
  assert.strictEqual(M.timeAgo(String(Math.floor((now - 2 * 86400000) / 1000)), now), "2 d ago")
  assert.strictEqual(M.toMillis("not a date"), 0)
  assert.strictEqual(M.formatDuration(90), "2 min")
})

test("polling and watcher backoff", () => {
  assert.strictEqual(M.pollDelayMs(0, 5), 5000)
  assert.strictEqual(M.pollDelayMs(0, 1), 5000)
  assert.strictEqual(M.pollDelayMs(0, null), 5000)
  assert.strictEqual(M.pollDelayMs(6, 5), 10000)
  assert.strictEqual(M.pollDelayMs(12, 5), 15000)
  let total = 0
  for (let i = 0; i < 24; i++) total += M.pollDelayMs(i, 5)
  assert.ok(total >= 240000 && total <= 330000, "24 polls should cover ~4-5 minutes, got " + total)
  assert.strictEqual(M.watchBackoffMs(1), 5000)
  assert.strictEqual(M.watchBackoffMs(99), 60000)
})

test("history dedupes and caps", () => {
  let h = []
  const r1 = M.resultFromReport("domain", "example.com", { id: "example.com", last_analysis_stats: { undetected: 1 }, detections: [] })
  h = M.addHistory(h, r1, 1000)
  h = M.addHistory(h, r1, 30000)
  assert.strictEqual(h.length, 1)
  h = M.addHistory(h, r1, 30000 + 61000)
  assert.strictEqual(h.length, 2)
  for (let i = 0; i < 60; i++) h = M.addHistory(h, M.resultFromReport("domain", "d" + i + ".com", { id: "x", last_analysis_stats: {}, detections: [] }), 200000 + i)
  assert.strictEqual(h.length, 50)
  assert.strictEqual(h[0].target, "d59.com")
})

test("found results replace the matching not-found entry", () => {
  const sha = "d".repeat(64)
  let h = M.addHistory([], M.notFoundResult("file", "/tmp/x", { path: "/tmp/x", name: "x", size: 5, sha256: sha }), 1000)
  const found = M.resultFromReport("file", "/tmp/x", { id: sha, last_analysis_stats: { undetected: 3 }, detections: [] }, { path: "/tmp/x", name: "x", size: 5 })
  h = M.addHistory(h, found, 500000)
  assert.strictEqual(h.length, 1)
  assert.strictEqual(h[0].status, "found")
  assert.strictEqual(M.findRecentBySha(h, sha, 600000, 86400000).status, "found")
  assert.strictEqual(M.findRecentBySha(h, sha, 500000 + 86400001, 86400000), null)
})

test("newer results for a file replace stale analyzing entries only", () => {
  const sha = "a".repeat(64)
  const extra = { path: "/tmp/y", name: "y", size: 5, sha256: sha }
  const base = M.notFoundResult("file", "/tmp/y", extra)
  let h = M.addHistory([], M.analyzingResult(base, "an_1", 0, 24, ""), 1000)
  h = M.addHistory(h, M.unknownSubmissionResult(base), 100000)
  assert.strictEqual(h.length, 1)
  assert.strictEqual(h[0].status, "unknown_submission")
  const done = M.resultFromAnalysis(M.analyzingResult(base, "an_1", 0, 24, ""), { status: "completed", stats: { undetected: 60 }, analysis_id: "an_1", sha256: sha }, 200000)
  h = M.addHistory(h, done, 200000)
  same(h.map(e => e.status), ["found"])
  // Two completed checks of the same file stay as separate entries.
  h = M.addHistory(h, done, 900000)
  assert.strictEqual(h.length, 2)
  // Other kinds that happen to carry no sha are untouched.
  h = M.addHistory(h, M.resultFromReport("domain", "example.com", { id: "example.com", last_analysis_stats: {}, detections: [] }), 950000)
  assert.strictEqual(h.length, 3)
})

test("parses the startup probe", () => {
  same(M.parseKeyValues("missing=\nauth=present\ndownloads=$HOME/Descargas\njunk\n=x\n"),
    { missing: "", auth: "present", downloads: "$HOME/Descargas" })
  same(M.parseKeyValues(""), {})
})

test("resolves the Downloads folder", () => {
  assert.strictEqual(M.resolveDownloadsDir("$HOME/Descargas", "/home/u", ""), "/home/u/Descargas")
  assert.strictEqual(M.resolveDownloadsDir("${HOME}/dl/", "/home/u/", ""), "/home/u/dl")
  assert.strictEqual(M.resolveDownloadsDir("/data/dl", "/home/u", ""), "/data/dl")
  // xdg-user-dirs writes $HOME to mean "disabled": never watch the whole home.
  assert.strictEqual(M.resolveDownloadsDir("$HOME", "/home/u", "/srv/dl"), "/srv/dl")
  assert.strictEqual(M.resolveDownloadsDir("$HOME/", "/home/u", ""), "/home/u/Downloads")
  assert.strictEqual(M.resolveDownloadsDir("relative/dir", "/home/u", ""), "/home/u/Downloads")
  assert.strictEqual(M.resolveDownloadsDir("", "/home/u", "$HOME/Env"), "/home/u/Env")
  assert.strictEqual(M.resolveDownloadsDir("", "", ""), "")
})

test("shortens paths under home", () => {
  assert.strictEqual(M.displayPath("/home/u/.config/vtai/auth.header", "/home/u"), "~/.config/vtai/auth.header")
  assert.strictEqual(M.displayPath("/home/u", "/home/u/"), "~")
  assert.strictEqual(M.displayPath("/home/user2/x", "/home/u"), "/home/user2/x")
  assert.strictEqual(M.displayPath("/etc/x", ""), "/etc/x")
})

test("explains a missing curl", () => {
  const e = M.apiError(0, null, 127)
  assert.strictEqual(e.kind, "missing_tool")
  assert.ok(/curl/.test(e.message))
})

test("truncates long AI analyses in history", () => {
  const r = M.resultFromReport("hash", "e".repeat(64), {
    id: "e".repeat(64), last_analysis_stats: { undetected: 1 }, detections: [],
    ai_insights: [{ verdict: "benign", source: "x", analysis: "y".repeat(2000) }]
  })
  assert.ok(r.insight.analysis.length <= 700)
  const h = M.addHistory([], r, 1)
  assert.ok(h[0].insight.analysis.length <= 400)
})

test("state and config round-trip", () => {
  const r = M.resultFromReport("ip", "8.8.8.8", { id: "8.8.8.8", ip: "8.8.8.8", last_analysis_stats: { undetected: 1 }, detections: [] })
  const text = M.serializeState([r], r, false)
  const s = M.parseState(text)
  assert.strictEqual(s.entries.length, 1)
  assert.strictEqual(s.alert.target, "8.8.8.8")
  assert.strictEqual(s.alertAcknowledged, false)
  same(JSON.parse(JSON.stringify(M.parseState("garbage"))), { entries: [], alert: null, alertAcknowledged: true })
  assert.strictEqual(M.parseState("[{\"kind\":\"url\",\"target\":\"x\"}, 5]").entries.length, 1)
  const defaults = { watcherEnabled: false, notifyAll: false, pluginScanEnabled: false, pluginAutoUpload: false,
                     pluginBackend: "vtai", maxParallel: 4, classicPerMin: 4, classicPerDay: 500 }
  same(M.parseConfig(M.serializeConfig({ watcherEnabled: true })), Object.assign({}, defaults, { watcherEnabled: true }))
  same(M.parseConfig("[]"), defaults)
  same(M.parseConfig(""), defaults)
  same(M.parseConfig(M.serializeConfig({ pluginScanEnabled: true, pluginAutoUpload: true, pluginBackend: "classic",
                                         maxParallel: 99, classicPerMin: 0, classicPerDay: "1000" })),
       Object.assign({}, defaults, { pluginScanEnabled: true, pluginAutoUpload: true, pluginBackend: "classic",
                                     maxParallel: 8, classicPerMin: 1, classicPerDay: 1000 }))
  assert.strictEqual(M.parseConfig("{\"pluginBackend\":\"evil\"}").pluginBackend, "vtai")
})

test("ignores temporary download files", () => {
  assert.strictEqual(M.isIgnoredDownload(".hidden"), true)
  assert.strictEqual(M.isIgnoredDownload("file.iso.crdownload"), true)
  assert.strictEqual(M.isIgnoredDownload("file.zip.part"), true)
  assert.strictEqual(M.isIgnoredDownload("notes.txt~"), true)
  assert.strictEqual(M.isIgnoredDownload("Unconfirmed 1234.crdownload"), true)
  assert.strictEqual(M.isIgnoredDownload(".part"), true)
  assert.strictEqual(M.isIgnoredDownload("setup.exe"), false)
  assert.strictEqual(M.isIgnoredDownload("party.pdf"), false)
})

test("download diff records a baseline, then reports new files", () => {
  const list1 = [{ name: "a.pdf", path: "/d/a.pdf" }, { name: "b.part", path: "/d/b.part" }]
  let d = M.diffDownloads(null, list1)
  same(d.added, [])
  assert.ok(d.seen["/d/a.pdf"])
  assert.ok(!d.seen["/d/b.part"])
  const list2 = list1.concat([{ name: "c.exe", path: "/d/c.exe" }, { name: ".x", path: "/d/.x" }])
  d = M.diffDownloads(d.seen, list2)
  same(d.added, [{ name: "c.exe", path: "/d/c.exe" }])
  d = M.diffDownloads(d.seen, list2)
  same(d.added, [])
  // Deleted and re-created files count as new again.
  d = M.diffDownloads(d.seen, [{ name: "a.pdf", path: "/d/a.pdf" }])
  d = M.diffDownloads(d.seen, list2)
  same(d.added, [{ name: "c.exe", path: "/d/c.exe" }])
})

test("download diff caps bulk additions", () => {
  const many = []
  for (let i = 0; i < 30; i++) many.push({ name: "f" + i, path: "/d/f" + i })
  const d = M.diffDownloads({}, many, { maxNew: 20 })
  assert.strictEqual(d.added.length, 20)
  assert.strictEqual(d.dropped, 10)
})

test("recent downloads are newest first without temp files", () => {
  const list = [
    { name: "old.txt", path: "/d/old.txt", size: 1, mtime: 1 },
    { name: "new.iso", path: "/d/new.iso", size: 10, mtime: 3 },
    { name: "partial.part", path: "/d/partial.part", size: 5, mtime: 4 },
    { name: "empty", path: "/d/empty", size: 0, mtime: 5 },
    { name: "mid.zip", path: "/d/mid.zip", size: 3, mtime: 2 }
  ]
  same(M.recentDownloads(list, 2).map(f => f.name), ["new.iso", "mid.zip"])
})

test("notifications and consent text", () => {
  const r = M.resultFromReport("file", "/d/x.exe", { id: "f".repeat(64), last_analysis_stats: { malicious: 5, undetected: 60 }, detections: [] }, { path: "/d/x.exe", name: "x.exe", size: 10, source: "watcher" })
  const n = M.notificationFor(r)
  assert.strictEqual(n.urgency, "critical")
  assert.strictEqual(n.title, "Flagged download: x.exe")
  assert.ok(/5 of 65/.test(n.body) && /malicious 5/.test(n.body))
  r.source = "manual"
  assert.strictEqual(M.notificationFor(r).title, "Flagged file: x.exe")
  const clean = M.resultFromReport("file", "/d/y.pdf", { id: "0".repeat(64), last_analysis_stats: { undetected: 60 }, detections: [] }, { path: "/d/y.pdf", name: "y.pdf", size: 10 })
  assert.strictEqual(M.notificationFor(clean).title, "No detections: y.pdf")
  assert.strictEqual(M.notificationFor(clean).urgency, "low")
  const msg = M.uploadConsentMessage({ name: "x.exe", size: 2048 })
  assert.ok(/x\.exe/.test(msg) && /2\.0 kB|2 kB/.test(msg) && /shared with the VirusTotal/.test(msg))
})

test("glyphs are single Nerd Font code points", () => {
  const names = Object.keys(M.Glyph)
  assert.ok(names.length > 20)
  for (const name of names) {
    const g = M.Glyph[name]
    assert.strictEqual(g.length, 2, name + " should be a surrogate pair")
    const cp = g.codePointAt(0)
    assert.ok(cp >= 0xF0000 && cp <= 0xF1AF0, name + " out of the nf-md range: " + cp.toString(16))
  }
})

console.log(passed + " passed, " + failed + " failed")
process.exit(failed ? 1 : 0)
