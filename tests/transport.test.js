'use strict'
const assert = require('assert')
const http = require('http')
const cp = require('child_process')
const { Model, Scanner, methods } = require('./helpers/qml')
const sha = 'a'.repeat(64)
const now = Date.parse('2026-10-06T12:00:00Z')
let passed = 0
function test(name, fn) { fn(); passed++; console.log('ok ' + name) }
const task = type => ({ type, sha, size: 1, path: '/fake/file', name: 'file', attempts: 0 })
function controller(backend = 'vtai') {
  const root = { backend, _st: Scanner.parseState(''), _busy: { [sha]: true }, _queue: [], _scans: {}, pauseUntil: 0, scanDone: 0 }
  const timer = { restart() {}, stop() {} }
  methods('PluginScanner.qml', root, { folderDebounce: timer })
  root.scheduleSave = () => {}
  root.flaggedOutsideScan = () => {}
  return root
}
test('response trailer preserves JSON and both forms of Retry-After', () => {
  for (const [header, expected] of [['3600', 3600], ['Tue, 06 Oct 2026 13:00:00 GMT', 3600], ['', 0], ['nonsense', 0], ['-1', 0], ['Infinity', 0]]) {
    const parsed = Model.parseCurlOutput('{"detail":"quota"}\n429\nretry-after:' + header + '\n', now)
    assert.equal(parsed.http, 429); assert.equal(parsed.body, '{"detail":"quota"}'); assert.equal(parsed.retryAfter, expected)
  }
  assert.equal(Model.retryAfterSeconds('Tue, 06 Oct 2026 11:00:00 GMT', now), 0)
  assert.equal(Model.apiError(429, { detail: 'quota' }, 0, 3600).retryAfter, 3600)
  assert.equal(Model.apiError(503, { detail: { retry_after_seconds: 7200 } }, 0, 60).retryAfter, 7200)
  assert.equal(Scanner.classicError(429, {}, 0, 3600).retryAfter, 3600)
})
test('every analysis poll respects the server hint', () => {
  for (const n of [0, 5, 6, 11, 12, 23]) assert.equal(Model.pollDelayMs(n, 300), 300000)
})
test('Service API captures and propagates header-only rate limits', () => {
  const root = { missingTools: '', userAgent: 'test', authHeaderPath: '/fake/header', apiBase: 'https://example.invalid' }
  methods('Service.qml', root)
  root.runJob = (argv, timeout, cb) => {
    assert.equal(argv[argv.indexOf('-w') + 1], Model.CURL_WRITE_OUT)
    cb(0, '{"detail":"quota"}\n429\nretry-after:3600')
  }
  let response; root.api('GET', '/files/' + sha, {}, r => { response = r })
  assert.equal(response.retryAfter, 3600); assert.equal(response.json.detail, 'quota')
})
for (const backend of ['vtai', 'classic']) {
  for (const code of [0, 200, 502, 503, 504]) {
    test(backend + ' never replays an uncertain upload (' + code + ')', () => {
      const root = controller(backend)
      root.onUpload(task('upload'), { http: code, exitCode: code ? 0 : 28, json: null, retryAfter: 180 })
      assert.equal(root._queue.length, 1)
      assert.equal(root._queue[0].type, backend === 'vtai' ? 'receipt' : 'lookup')
      assert.ok(root._queue[0].notBefore >= Date.now() + 179000)
      assert.ok(root._st.cache[sha].uploadedAt > 0)
    })
  }
  test(backend + ' pauses queued work for a header-only 429', () => {
    const root = controller(backend)
    root.handleError(task('lookup'), { http: 429, exitCode: 0, json: { detail: 'quota' }, retryAfter: 3600 })
    assert.ok(root.pauseUntil >= Date.now() + 3599000)
    assert.equal(root._queue[0].type, 'lookup')
  })
  test(backend + ' respects Retry-After on GET 503', () => {
    const root = controller(backend)
    root.handleError(task('lookup'), { http: 503, exitCode: 0, json: null, retryAfter: 3600 })
    assert.ok(root._queue[0].notBefore >= Date.now() + 3599000)
  })
}
test('only explicit VTAI pre-admission rejection permits a POST retry', () => {
  const root = controller()
  root.onUpload(task('upload'), { http: 503, exitCode: 0, json: { detail: { code: 'capacity_exceeded', retry_after_seconds: 1 } } })
  assert.equal(root._queue[0].type, 'upload'); assert.equal(root._st.cache[sha], undefined)
})
test('receipt recovery follows the original analysis or falls back to lookup', () => {
  const root = controller()
  root.onReceipt(task('receipt'), { http: 200, exitCode: 0, json: { status: 'submitted', analysis_id: 'opaque/id', next_poll_after_seconds: 50 } })
  assert.equal(root._queue[0].type, 'poll'); assert.equal(root._queue[0].analysisId, 'opaque/id')
  root._queue = []
  root.onReceipt(task('receipt'), { http: 404, exitCode: 0, json: null })
  assert.equal(root._queue[0].type, 'lookup')
})
test('eight slots still start only one upload and allow parallel lookups', () => {
  const state = { queue: [task('upload'), task('upload'), task('lookup')], inFlight: 0, maxParallel: 8,
    limiter: Scanner.makeLimiter('vtai', {}, null, now) }
  const first = Scanner.dispatch(state, now)
  assert.deepEqual(Array.from(first.start, t => t.type), ['lookup', 'upload'])
  state.uploadsInFlight = 1
  assert.equal(Scanner.dispatch(state, now + 10000).start.length, 0)
  state.uploadsInFlight = 0
  assert.equal(Scanner.dispatch(state, now + 100).wakeAt, now + 3750)
  assert.equal(Scanner.dispatch(state, now + 3750).start.length, 1)
})
test('rebuilding the limiter preserves the recent window and upload spacing', () => {
  const l = Scanner.makeLimiter('vtai', {}, null, now)
  Scanner.take(l, 'upload', now)
  const restored = Scanner.makeLimiter('vtai', {}, Scanner.persistLimiter(l), now + 100)
  assert.equal(Scanner.waitMs(restored, 'upload', now + 100), 3650)
})
async function loopback() {
  const server = http.createServer((req, res) => { res.writeHead(429, { 'Retry-After': '3600', 'Content-Type': 'application/json' }); res.end('{"detail":"local fixture"}') })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    const out = await new Promise((resolve, reject) => cp.execFile('curl', ['-sS', '--noproxy', '*', '--max-time', '5', '-w', Model.CURL_WRITE_OUT,
      'http://127.0.0.1:' + server.address().port], (err, stdout) => err ? reject(err) : resolve(stdout)))
    const parsed = Model.parseCurlOutput(out)
    assert.equal(parsed.retryAfter, 3600); assert.equal(parsed.http, 429)
    assert.equal(JSON.parse(parsed.body).detail, 'local fixture')
    passed++; console.log('ok real curl write-out round trip against loopback fixture')
  } finally { await new Promise(resolve => server.close(resolve)) }
}
loopback().then(() => console.log(passed + ' transport tests passed')).catch(e => { console.error(e); process.exitCode = 1 })
