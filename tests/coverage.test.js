'use strict'
const assert = require('assert')
const { Model, Scanner } = require('./helpers/qml')
const sha = 'a'.repeat(64), other = 'b'.repeat(64)
const rec = { id: 'p', name: 'Plugin', files: { 'one.js': { sha, size: 1 } } }
let passed = 0
function test(name, fn) { fn(); passed++; console.log('ok ' + name) }
function report(stats, engines = 0, insights = []) {
  return Model.resultFromReport('file', '/fake/one.js', { last_analysis_stats: stats, coverage: { engines }, ai_insights: insights })
}
for (const stats of [null, {}, { failure: 70 }, { timeout: 20, 'type-unsupported': 50 }]) {
  test('absent/failed/unsupported results never become no-detections evidence: ' + JSON.stringify(stats), () => {
    const r = report(stats, 70)
    assert.equal(Model.verdictLabel(r), 'No engine results')
    assert.equal(Model.verdictRole(r), 'muted')
    assert.equal(Model.notificationFor(r).title, 'Incomplete scan: one.js')
    const cache = { [sha]: Scanner.cacheEntry(r, Date.now()) }
    const summary = Scanner.summarize(rec, cache, {})
    assert.equal(summary.checked, 0); assert.equal(summary.noResults, 1)
    assert.equal(Scanner.summaryNotification(rec, summary, true).title, 'Incomplete scan: Plugin')
    assert.equal(Scanner.fileStatus(cache[sha]).role, 'muted')
  })
}
for (const entry of [{ status: 'error', message: 'offline' }, { status: 'not_found' }, { status: 'analyzing' }]) {
  test(entry.status + ' is visible in incomplete plugin notification', () => {
    const summary = Scanner.summarize(rec, { [sha]: entry }, {})
    const n = Scanner.summaryNotification(rec, summary, true)
    assert.equal(n.title, 'Incomplete scan: Plugin')
    assert.match(n.body, /error|unknown|analyzing/)
    assert.equal(Scanner.summaryNotification(rec, summary, false), null)
  })
}
test('partial scan reports missing coverage even when one file has no detections', () => {
  const r = { id: 'p', files: { one: { sha, size: 1 }, two: { sha: other, size: 1 } } }
  const s = Scanner.summarize(r, { [sha]: Scanner.cacheEntry(report({ undetected: 70 }), Date.now()), [other]: { status: 'error' } }, {})
  const n = Scanner.summaryNotification(r, s, true)
  assert.equal(n.title, 'Incomplete scan: p'); assert.match(n.body, /1 error/)
})
test('complete unflagged scan retains no-detections notification', () => {
  const r = report({ undetected: 70 })
  assert.equal(Model.notificationFor(r).title, 'No detections: one.js')
  const s = Scanner.summarize(rec, { [sha]: Scanner.cacheEntry(r, Date.now()) }, {})
  assert.equal(Scanner.summaryNotification(rec, s, true).title, 'No detections: Plugin')
})
test('engine and AI-only flags retain alert precedence', () => {
  for (const r of [report({ malicious: 1 }), report({}, 0, [{ verdict: 'malicious', source: 'Code Insight' }])]) {
    assert.match(Model.notificationFor(r).title, /^Flagged /)
    const s = Scanner.summarize(rec, { [sha]: Scanner.cacheEntry(r, Date.now()) }, {})
    assert.equal(s.flagged, 1); assert.match(Scanner.summaryNotification(rec, s, false).title, /^VirusTotal flagged/)
  }
})
test('normalizing cached stats does not double-count totals', () => {
  const original = Model.normalizeStats({ malicious: 1, undetected: 5, timeout: 4 })
  const cached = Model.normalizeStats(original)
  assert.equal(original.total, 10); assert.equal(cached.total, 10)
})
test('truncated and skipped file sets disclose incomplete coverage', () => {
  const s = Scanner.summarize(rec, { [sha]: Scanner.cacheEntry(report({ undetected: 70 }), Date.now()) }, {})
  for (const extra of [{ truncated: true }, { skipped: 1 }]) {
    const n = Scanner.summaryNotification(Object.assign({}, rec, extra), s, true)
    assert.equal(n.title, 'Incomplete scan: Plugin'); assert.match(n.body, /limit|skipped/)
  }
})
console.log(passed + ' coverage tests passed')
