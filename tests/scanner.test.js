// Unit tests for Scanner.js (installed-plugin scanner logic).
// Run with: node tests/scanner.test.js
"use strict"

const assert = require("assert")
const fs = require("fs")
const path = require("path")
const vm = require("vm")

function load(file, context) {
  const src = fs.readFileSync(path.join(__dirname, "..", file), "utf8")
    .replace(/^\.pragma library\s*$/m, "")
    .replace(/^\.import .*$/mg, "")
  vm.runInContext(src, context, { filename: file })
}
const M = vm.createContext({})
load("Model.js", M)
const S = vm.createContext({ Model: M })
load("Scanner.js", S)

let passed = 0
let failed = 0
function test(name, fn) {
  try {
    fn()
    passed++
  } catch (e) {
    failed++
    console.error("FAIL " + name + "\n  " + (e && e.stack ? e.stack.split("\n").slice(0, 4).join("\n  ") : e))
  }
}
const same = (a, b, msg) => assert.deepStrictEqual(JSON.parse(JSON.stringify(a)), b, msg)
const sha = n => n.toString(16).padStart(64, "0")
const T0 = Date.UTC(2026, 8, 30, 10, 0, 0)

// --- limiter -----------------------------------------------------------------

test("vtai limiter: per-minute window per class", () => {
  const l = S.makeLimiter("vtai", null, null, T0)
  for (let i = 0; i < 48; i++) {
    assert.strictEqual(S.waitMs(l, "lookup", T0 + i), 0)
    S.take(l, "lookup", T0 + i)
  }
  const w = S.waitMs(l, "lookup", T0 + 100)
  assert.ok(w > 59000 && w <= 60000, "wait " + w)
  assert.strictEqual(S.waitMs(l, "upload", T0 + 100), 0, "uploads have their own bucket")
  assert.strictEqual(S.waitMs(l, "lookup", T0 + 60001), 0, "window slides")
})

test("classic limiter: one shared bucket with overrides", () => {
  const l = S.makeLimiter("classic", { perMin: 4, perDay: 6 }, null, T0)
  for (let i = 0; i < 3; i++) S.take(l, "lookup", T0)
  S.take(l, "upload", T0)
  assert.ok(S.waitMs(l, "upload", T0 + 1) > 0, "uploads share the lookup quota")
  assert.ok(S.waitMs(l, "lookup", T0 + 1) > 0)
  S.take(l, "lookup", T0 + 60000)
  S.take(l, "lookup", T0 + 60000)
  const w = S.waitMs(l, "lookup", T0 + 60001)
  assert.strictEqual(w, S.nextUtcMidnight(T0 + 60001) - (T0 + 60001), "daily cap waits for UTC midnight")
  assert.strictEqual(S.waitMs(l, "lookup", S.nextUtcMidnight(T0)), 0, "new UTC day resets")
})

test("limiter restores today's counters only", () => {
  const p = { backend: "classic", day: "2026-09-30", used: { any: 499 } }
  const l = S.makeLimiter("classic", { perMin: 4, perDay: 500 }, p, T0)
  S.take(l, "lookup", T0)
  assert.ok(S.waitMs(l, "lookup", T0 + 1) > 3600000)
  const other = S.makeLimiter("classic", null, { backend: "classic", day: "2026-09-29", used: { any: 499 } }, T0)
  assert.strictEqual(other.used.any, 0)
  const wrong = S.makeLimiter("vtai", null, p, T0)
  assert.strictEqual(wrong.used.lookup, 0)
  same(S.persistLimiter(l), { backend: "classic", day: "2026-09-30", used: { any: 500 } })
})

// --- dispatcher ----------------------------------------------------------------

function task(type, n, extra) {
  return Object.assign({ type: type, sha: sha(n), notBefore: 0, attempts: 0 }, extra || {})
}

test("dispatch honours maxParallel and priority", () => {
  const s = { queue: [task("upload", 1), task("lookup", 2), task("poll", 3), task("lookup", 4)],
              inFlight: 1, maxParallel: 3, pauseUntil: 0, limiter: S.makeLimiter("vtai", null, null, T0) }
  const d = S.dispatch(s, T0)
  same(d.start.map(t => t.type), ["poll", "lookup"])
  assert.strictEqual(s.queue.length, 2)
  assert.strictEqual(d.wakeAt, 0, "slots full: the next finished job pumps")
})

test("dispatch respects notBefore and pause", () => {
  const s = { queue: [task("lookup", 1, { notBefore: T0 + 5000 })], inFlight: 0, maxParallel: 4, pauseUntil: 0,
              limiter: S.makeLimiter("vtai", null, null, T0) }
  let d = S.dispatch(s, T0)
  assert.strictEqual(d.start.length, 0)
  assert.strictEqual(d.wakeAt, T0 + 5000)
  s.pauseUntil = T0 + 9000
  d = S.dispatch(s, T0 + 6000)
  assert.strictEqual(d.start.length, 0)
  assert.strictEqual(d.wakeAt, T0 + 9000)
  d = S.dispatch(s, T0 + 9000)
  assert.strictEqual(d.start.length, 1)
})

test("dispatch lets uploads run while lookups wait (vtai)", () => {
  const l = S.makeLimiter("vtai", null, null, T0)
  for (let i = 0; i < 48; i++) S.take(l, "lookup", T0)
  const s = { queue: [task("lookup", 1), task("upload", 2)], inFlight: 0, maxParallel: 4, pauseUntil: 0, limiter: l }
  const d = S.dispatch(s, T0 + 10)
  same(d.start.map(t => t.type), ["upload"])
  assert.strictEqual(d.wakeAt, T0 + 60000)
})

// --- parsing -------------------------------------------------------------------

test("parseProbe", () => {
  const head = "a".repeat(40)
  const out = S.parseProbe("io.github.x.clock\t" + head + "\t12 3400 1759000000\t1.2.0\tClock\tdir\n"
    + "local.dev\t-\t3 10 1759000001\t\t\tlink\n\nbad line\n")
  assert.strictEqual(out.length, 2)
  same(out[0], { id: "io.github.x.clock", head: head, stamp: head + "|12 3400 1759000000", version: "1.2.0", name: "Clock", link: false })
  assert.strictEqual(out[1].head, "")
  assert.strictEqual(out[1].link, true)
})

test("parseHashList keeps tabs in names and caps files", () => {
  const text = "#\t4\t1\n" + sha(1) + "\t10\tBarWidget.qml\n" + sha(2) + "\t5\tdir with\ttab.js\n"
    + "zz\t1\tbad\n" + sha(3) + "\t0\tempty\n" + sha(4) + "\t7\tthird\n"
  const r = S.parseHashList(text, 2)
  same(Object.keys(r.files).sort(), ["BarWidget.qml", "dir with\ttab.js"])
  assert.strictEqual(r.total, 4)
  assert.strictEqual(r.skipped, 1)
  assert.strictEqual(r.truncated, true)
})

// --- diff / tasks ----------------------------------------------------------------

const rec = (id, files) => ({ id: id, name: id, files: files })

test("diffPlugin added / updated / unchanged", () => {
  const a = { "a.qml": { sha: sha(1), size: 1 }, "b.js": { sha: sha(2), size: 2 } }
  same(S.diffPlugin(null, a), { kind: "added", changed: ["a.qml", "b.js"], removed: [] })
  same(S.diffPlugin(rec("p", a), a), { kind: "unchanged", changed: [], removed: [] })
  const b = { "a.qml": { sha: sha(9), size: 1 }, "c.sh": { sha: sha(3), size: 3 } }
  same(S.diffPlugin(rec("p", a), b), { kind: "updated", changed: ["a.qml", "c.sh"], removed: ["b.js"] })
})

test("tasksFor dedupes shared files and honours the cache", () => {
  const files = { "a.qml": { sha: sha(1), size: 10 }, "copy.qml": { sha: sha(1), size: 10 }, "b.js": { sha: sha(2), size: 20 },
                  "c.sh": { sha: sha(3), size: 30 }, "d.bin": { sha: sha(4), size: 40 } }
  const cache = {}
  cache[sha(2)] = { status: "found", time: T0 - 1000 }
  cache[sha(3)] = { status: "not_found", time: T0 - 1000 }
  cache[sha(4)] = { status: "found", time: T0 - 8 * 86400000 }
  const busy = {}
  let t = S.tasksFor(rec("p", files), "/plugins/p", cache, busy, T0, {})
  same(t.map(x => [x.type, x.sha]), [["lookup", sha(1)], ["lookup", sha(4)]])
  assert.strictEqual(t[0].path, "/plugins/p/a.qml")
  assert.strictEqual(t[0].name, "p/a.qml")
  t = S.tasksFor(rec("p", files), "/plugins/p", cache, busy, T0, { autoUpload: true })
  same(t.map(x => x.type), ["lookup", "upload", "lookup"], "fresh not_found + autoUpload -> upload")
  busy[sha(1)] = true
  t = S.tasksFor(rec("q", files), "/plugins/q", cache, busy, T0, {})
  same(t.map(x => x.sha), [sha(4)], "busy shas are skipped across plugins")
  t = S.tasksFor(rec("p", files), "/plugins/p", cache, {}, T0, { force: true })
  assert.strictEqual(t.length, 4)
})

test("auto-upload is not retried within 24 h and skips large files", () => {
  const files = { "a": { sha: sha(1), size: 10 }, "big": { sha: sha(2), size: 40000000 } }
  const cache = {}
  cache[sha(1)] = { status: "not_found", time: T0, uploadedAt: T0 - 3600000 }
  cache[sha(2)] = { status: "not_found", time: T0 }
  assert.strictEqual(S.tasksFor(rec("p", files), "/d", cache, {}, T0, { autoUpload: true }).length, 0)
})

// --- summaries: VirusTotal's numbers only -------------------------------------

function found(stats, insight) {
  return { status: "found", time: T0, stats: Object.assign({ malicious: 0, suspicious: 0, harmless: 0, undetected: 60 }, stats),
           engines: 60, insight: insight || null }
}

test("summarize counts engine detections and AI insight flags", () => {
  const files = { "clean.qml": { sha: sha(1), size: 1 }, "evil.sh": { sha: sha(2), size: 1 }, "ai.js": { sha: sha(3), size: 1 },
                  "sus.py": { sha: sha(4), size: 1 }, "new.bin": { sha: sha(5), size: 1 }, "wip": { sha: sha(6), size: 1 } }
  const cache = {}
  cache[sha(1)] = found({})
  cache[sha(2)] = found({ malicious: 3, undetected: 57 })
  cache[sha(3)] = found({}, { verdict: "malicious", rawVerdict: "malicious", source: "Code Insight" })
  cache[sha(4)] = found({ suspicious: 1, undetected: 59 })
  cache[sha(5)] = { status: "not_found", time: T0 }
  const busy = {}
  busy[sha(6)] = true
  const s = S.summarize(rec("p", files), cache, busy)
  assert.strictEqual(s.files, 6)
  assert.strictEqual(s.pending, 1)
  assert.strictEqual(s.flagged, 3)
  assert.strictEqual(s.engineFlagged, 2)
  assert.strictEqual(s.insightFlagged, 1)
  assert.strictEqual(s.withMalicious, 1)
  assert.strictEqual(s.notFound, 1)
  same(s.flaggedFiles.map(f => f.rel), ["evil.sh", "sus.py", "ai.js"])
  assert.strictEqual(S.flaggedFileLine(s.flaggedFiles[0]), "evil.sh: 3/60 flagged")
  assert.strictEqual(S.flaggedFileLine(s.flaggedFiles[2]), "ai.js: AI insight: malicious")
  assert.strictEqual(S.pluginStatus(s).label, "Checking 5/6 files")
  delete busy[sha(6)]
  cache[sha(6)] = found({})
  const done = S.summarize(rec("p", files), cache, busy)
  same(S.pluginStatus(done), { label: "3 of 6 files flagged \u00b7 1 unknown to VirusTotal", role: "danger" })
})

test("an AI insight that is not malicious/suspicious is not a flag", () => {
  const files = { "a": { sha: sha(1), size: 1 } }
  const cache = {}
  cache[sha(1)] = found({}, { verdict: "benign", rawVerdict: "benign", source: "Code Insight" })
  const s = S.summarize(rec("p", files), cache, {})
  assert.strictEqual(s.flagged, 0)
  same(S.pluginStatus(s), { label: "No detections in 1 file", role: "ok" })
  assert.strictEqual(S.summaryNotification(rec("p", files), s, false), null)
  assert.strictEqual(S.summaryNotification(rec("p", files), s, true).urgency, "low")
})

test("summary notification lists files with VirusTotal's counts", () => {
  const files = { "evil.sh": { sha: sha(2), size: 1 }, "sus.py": { sha: sha(4), size: 1 } }
  const cache = {}
  cache[sha(2)] = found({ malicious: 3, undetected: 57 })
  cache[sha(4)] = found({ suspicious: 1, undetected: 59 })
  const r = rec("io.x.p", files)
  r.name = "Plug"
  const n = S.summaryNotification(r, S.summarize(r, cache, {}), false)
  assert.strictEqual(n.urgency, "critical")
  assert.strictEqual(n.title, "VirusTotal flagged 2 files in Plug")
  assert.strictEqual(n.body, "evil.sh: 3/60 flagged\nsus.py: 1/60 flagged")
  delete cache[sha(2)]
  cache[sha(2)] = found({})
  assert.strictEqual(S.summaryNotification(r, S.summarize(r, cache, {}), false).urgency, "normal")
})

test("event notifications", () => {
  const r = rec("io.x.p", { a: { sha: sha(1), size: 1 }, b: { sha: sha(2), size: 1 } })
  assert.strictEqual(S.eventNotification("added", r).title, "New plugin: io.x.p")
  assert.ok(/2 files/.test(S.eventNotification("added", r).body))
  assert.ok(/1 changed file\./.test(S.eventNotification("updated", r, 1).body))
})

test("fileStatus and fileResult", () => {
  same(S.fileStatus(found({ malicious: 2, undetected: 58 })), { label: "2/60 flagged", role: "danger" })
  same(S.fileStatus(found({}, { verdict: "suspicious", rawVerdict: "Suspicious", source: "x" })),
       { label: "No detections \u00b7 AI insight: Suspicious", role: "warning" })
  same(S.fileStatus(null, true), { label: "Checking\u2026", role: "pending" })
  same(S.fileStatus({ status: "not_found" }), { label: "Unknown to VirusTotal", role: "muted" })
  const r0 = rec("p", { "x/y.sh": { sha: sha(7), size: 5 } })
  const cache = {}
  cache[sha(7)] = found({ malicious: 1, undetected: 59 })
  const fr = S.fileResult(r0, "/pl/p", "x/y.sh", cache)
  assert.strictEqual(fr.name, "p/x/y.sh")
  assert.strictEqual(fr.source, "plugins")
  assert.strictEqual(fr.verdict, "malicious")
  assert.ok(M.hasFlags(fr))
  assert.strictEqual(fr.reportUrl, "https://www.virustotal.com/gui/file/" + sha(7))
  assert.strictEqual(M.notificationFor(fr).title, "Flagged plugin file: p/x/y.sh")
})

// --- state -------------------------------------------------------------------

test("state round trip drops junk", () => {
  const st = { baselineDone: true, plugins: { p: { id: "p", name: "P", version: "1", head: "b".repeat(40), stamp: "s",
               files: { a: { sha: sha(1), size: 3 }, bad: { sha: "x", size: 1 } }, firstSeen: 1, changedAt: 2, lastScan: 3 } },
               cache: { [sha(1)]: found({}), nothex: { status: "found" } }, quota: { backend: "vtai", day: "d", used: {} } }
  const back = S.parseState(S.serializeState(st))
  assert.strictEqual(back.baselineDone, true)
  same(Object.keys(back.plugins.p.files), ["a"])
  same(Object.keys(back.cache), [sha(1)])
  same(S.parseState("garbage"), { version: 1, baselineDone: false, plugins: {}, cache: {}, quota: null })
})

test("cache pruning keeps the newest entries", () => {
  const cache = {}
  for (let i = 0; i < S.CACHE_LIMIT + 10; i++) cache[sha(i + 1)] = { status: "found", time: i }
  const kept = S.pruneCache(cache)
  assert.strictEqual(Object.keys(kept).length, S.CACHE_LIMIT)
  assert.ok(!kept[sha(1)] && kept[sha(S.CACHE_LIMIT + 10)])
})

// --- classic API v3 ----------------------------------------------------------

test("classicReport maps to the VTAI shape", () => {
  const data = { id: sha(5), type: "file", attributes: {
    sha256: sha(5), type_description: "Shell script", last_analysis_date: 1759000000,
    last_analysis_stats: { malicious: 2, suspicious: 0, undetected: 60, harmless: 0, "type-unsupported": 8 },
    last_analysis_results: { A: { category: "malicious", result: "Trojan.Sh.X" }, B: { category: "malicious", result: "Bash.Agent" },
                             C: { category: "undetected", result: null } },
    crowdsourced_ai_results: [{ category: "code_insight", source: "palm", verdict: "malicious", analysis: "Downloads and runs a payload." }]
  } }
  const r = M.resultFromReport("file", "/x", S.classicReport(data), { sha256: sha(5) })
  assert.strictEqual(r.status, "found")
  assert.strictEqual(r.stats.malicious, 2)
  assert.strictEqual(r.engines, 3)
  same(r.topDetections, ["Trojan.Sh.X", "Bash.Agent"])
  assert.strictEqual(r.insight.verdict, "malicious")
  assert.strictEqual(r.insight.source, "palm")
  assert.strictEqual(r.reportUrl, "https://www.virustotal.com/gui/file/" + sha(5))
  assert.strictEqual(r.typeDescription, "Shell script")
})

test("classicAnalysis and upload id", () => {
  const pending = S.classicAnalysis({ data: { id: "an1", attributes: { status: "queued" } }, meta: { file_info: { sha256: sha(6) } } })
  assert.strictEqual(pending.status, "pending")
  const done = S.classicAnalysis({ data: { id: "an1", attributes: { status: "completed", stats: { malicious: 0, undetected: 5 },
    results: { A: { category: "undetected" } } } }, meta: { file_info: { sha256: sha(6) } } })
  const r = M.resultFromAnalysis(M.baseResult("file", "/x", {}), done, T0)
  assert.strictEqual(r.status, "found")
  assert.strictEqual(r.sha256, sha(6))
  assert.strictEqual(M.verdictLabel(r), "No detections")
  assert.strictEqual(S.classicUploadId({ data: { type: "analysis", id: "YWJj" } }), "YWJj")
  assert.strictEqual(S.classicUploadId({ error: {} }), "")
})

test("classicError kinds", () => {
  assert.strictEqual(S.classicError(401, { error: { code: "WrongCredentialsError" } }).kind, "auth")
  assert.strictEqual(S.classicError(429, { error: { code: "QuotaExceededError" } }).kind, "rate_limit")
  assert.strictEqual(S.classicError(0, null, 7).kind, "network")
  assert.ok(/www\.virustotal\.com/.test(S.classicError(0, null, 7).message))
  assert.strictEqual(S.classicError(0, null, 28).kind, "timeout")
  assert.strictEqual(S.classicError(503, null).kind, "unavailable")
  assert.ok(/bad thing/.test(S.classicError(400, { error: { code: "BadRequestError", message: "bad thing" } }).message))
})

// --- simulation: parallel scan against a fake API --------------------------------

// Three plugins, 60 files, 20 shared: exactly 40 unique lookups, never more
// than maxParallel in flight and never more than the per-minute quota.
function simulate(backend, overrides, maxParallel, autoUpload) {
  const cache = {}
  const busy = {}
  const plugins = []
  for (let p = 0; p < 3; p++) {
    const files = {}
    for (let f = 0; f < 20; f++) {
      const n = f < 10 ? 1000 + f : p * 100 + f   // first 10 files shared by all plugins
      files["f" + f] = { sha: sha(n), size: 100 }
    }
    plugins.push(rec("p" + p, files))
  }
  const unknown = n => parseInt(n, 16) % 7 === 0
  const state = { queue: [], inFlight: 0, maxParallel: maxParallel, pauseUntil: 0,
                  limiter: S.makeLimiter(backend, overrides, null, T0) }
  let now = T0
  const running = []
  const log = { lookups: 0, uploads: 0, polls: 0, maxInFlight: 0, starts: [] }
  for (const p of plugins) {
    for (const t of S.tasksFor(p, "/pl/" + p.id, cache, busy, now, { autoUpload })) {
      busy[t.sha] = true
      state.queue.push(t)
    }
  }
  let guard = 0
  while ((state.queue.length || running.length) && guard++ < 100000) {
    const d = S.dispatch(state, now)
    for (const t of d.start) {
      state.inFlight++
      log.starts.push(now)
      running.push({ t: t, doneAt: now + 700 })
    }
    log.maxInFlight = Math.max(log.maxInFlight, state.inFlight)
    const nextDone = running.length ? Math.min.apply(null, running.map(r => r.doneAt)) : Infinity
    const next = Math.min(nextDone, d.wakeAt || Infinity)
    assert.ok(isFinite(next), "scheduler stalled")
    now = next
    for (let i = running.length - 1; i >= 0; i--) {
      if (running[i].doneAt > now) continue
      const t = running.splice(i, 1)[0].t
      state.inFlight--
      if (t.type === "lookup") {
        log.lookups++
        if (unknown(t.sha)) {
          cache[t.sha] = { status: "not_found", time: now }
          if (autoUpload) state.queue.push({ type: "upload", sha: t.sha, notBefore: now, attempts: 0 })
          else delete busy[t.sha]
        } else {
          cache[t.sha] = found({})
          delete busy[t.sha]
        }
      } else if (t.type === "upload") {
        log.uploads++
        state.queue.push({ type: "poll", sha: t.sha, notBefore: now + 5000, attempts: 0 })
      } else {
        log.polls++
        cache[t.sha] = found({})
        delete busy[t.sha]
      }
    }
  }
  log.duration = now - T0
  log.plugins = plugins.map(p => S.summarize(p, cache, busy))
  return log
}

function maxPerMinute(starts) {
  let best = 0
  for (let i = 0; i < starts.length; i++) {
    let n = 0
    for (let j = i; j < starts.length && starts[j] - starts[i] < 60000; j++) n++
    best = Math.max(best, n)
  }
  return best
}

test("simulation: vtai runs 4 in parallel within quota", () => {
  const log = simulate("vtai", null, 4, false)
  assert.strictEqual(log.lookups, 40, "one lookup per unique sha256")
  assert.strictEqual(log.uploads, 0)
  assert.ok(log.maxInFlight <= 4 && log.maxInFlight === 4)
  assert.ok(maxPerMinute(log.starts) <= 48)
  assert.ok(log.duration < 60000, "40 lookups fit in the first minute: " + log.duration)
  assert.ok(log.plugins.every(s => s.pending === 0))
})

test("simulation: classic public key does exactly 4 requests per minute", () => {
  const log = simulate("classic", { perMin: 4, perDay: 500 }, 4, true)
  assert.strictEqual(log.lookups, 40)
  assert.ok(log.uploads > 0 && log.polls === log.uploads, "unknown files uploaded and polled")
  assert.strictEqual(maxPerMinute(log.starts), 4)
  const total = log.lookups + log.uploads + log.polls
  assert.ok(log.duration >= (Math.ceil(total / 4) - 1) * 60000, "quota paces the scan")
  assert.ok(log.plugins.every(s => s.pending === 0 && s.notFound === 0))
})

test("simulation: daily cap stops the scan until the next UTC day", () => {
  const log = simulate("classic", { perMin: 100, perDay: 10 }, 8, false)
  assert.strictEqual(log.lookups, 40)
  assert.ok(log.duration >= S.nextUtcMidnight(T0) - T0, "continued only after midnight")
})

console.log(passed + " passed, " + failed + " failed")
process.exit(failed ? 1 : 0)
