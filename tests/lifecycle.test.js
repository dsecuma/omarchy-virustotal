'use strict'
const assert = require('assert')
const { Model, Scanner, methods } = require('./helpers/qml')
const sha = 'a'.repeat(64)
function task(type = 'upload', hash = sha) {
  return { type, sha: hash, size: 1, path: '/fake/plugin.txt', name: 'plugin.txt', plugin: 'test' }
}
function setup() {
  const sent = [], hashes = []
  const root = { active: true, loaded: true, autoUpload: true, backend: 'vtai', _gen: 1, _uploadGen: 0,
    _queue: [], _busy: {}, _scans: {}, _st: Scanner.parseState(''), inFlight: 0, scanTotal: 0, scanDone: 0 }
  root.service = { hashFile: (p, q, m, cb) => hashes.push(cb), api: (...a) => sent.push(a), sh: (...a) => sent.push(a),
    apiKeyPath: '/fake/key', userAgent: 'test' }
  const timer = { stop() {}, restart() {} }
  methods('PluginScanner.qml', root, { pumpTimer: timer, saveTimer: timer, folderDebounce: timer,
    stateFile: { path: '/fake/state', setText() {} } })
  for (const n of ['updateCounters', 'scheduleUi', 'afterTask', 'refreshUi', 'probe', 'topUp']) root[n] = () => {}
  return { root, sent, hashes }
}
let passed = 0
function test(name, fn) { fn(); passed++; console.log('ok ' + name) }
for (const backend of ['vtai', 'classic']) {
  for (const change of ['permission', 'off-on', 'inactive', 'backend', 'auth']) {
    test(backend + ' rejects stale upload after ' + change, () => {
      const x = setup(); x.root.backend = backend
      let answer
      x.root.upload(task(), r => { answer = r })
      if (change === 'permission' || change === 'off-on') {
        x.root.autoUpload = false; x.root.uploadPermissionChanged()
        if (change === 'off-on') { x.root.autoUpload = true; x.root.uploadPermissionChanged() }
      }
      if (change === 'inactive') { x.root.active = false; x.root.restart() }
      if (change === 'backend') { x.root.backend = backend === 'vtai' ? 'classic' : 'vtai'; x.root.restart(true) }
      if (change === 'auth') x.root.stopWork('rejected')
      x.hashes[0](0, 1, sha)
      assert.equal(x.sent.length, 0); assert.equal(answer.cancelled, true)
    })
  }
  test(backend + ' allows an unchanged authorized upload', () => {
    const x = setup(); x.root.backend = backend; x.root.upload(task(), () => {})
    x.hashes[0](0, 1, sha); assert.equal(x.sent.length, 1)
  })
}
test('withdrawal drops only queued uploads and releases their busy hashes', () => {
  const x = setup(), b = 'b'.repeat(64), c = 'c'.repeat(64)
  x.root._queue = [task(), task('lookup', b), task('poll', c)]
  x.root._busy = { [sha]: true, [b]: true, [c]: true }
  x.root.autoUpload = false; x.root.uploadPermissionChanged()
  assert.deepEqual(Array.from(x.root._queue, t => t.type), ['lookup', 'poll'])
  assert.equal(x.root._busy[sha], undefined); assert.equal(x.root._busy[b], true)
  x.root.run(task()); assert.equal(x.hashes.length, 0); assert.equal(x.root.inFlight, 0)
})
test('cancelled preparation releases accounting without recording an upload or error', () => {
  const x = setup(); x.root._busy[sha] = true; x.root.run(task())
  x.root.autoUpload = false; x.root.uploadPermissionChanged(); x.hashes[0](0, 1, sha)
  assert.equal(x.root.inFlight, 0); assert.equal(x.root._busy[sha], undefined)
  assert.equal(x.root._st.cache[sha], undefined)
})
test('ready backend switch resumes from current state without another file load', () => {
  const x = setup(); x.root._st.cache[sha] = { status: 'not_found' }
  x.root.backend = 'classic'; let probes = 0; x.root.probe = () => probes++
  x.root.restart(true)
  assert.equal(x.root.loaded, true); assert.equal(x.root._limiter.backend, 'classic')
  assert.equal(x.root._st.cache[sha].status, 'not_found'); assert.equal(probes, 1)
})
test('deactivation still waits for the next state-file load', () => {
  const x = setup(); x.root.active = false; x.root.restart(true); assert.equal(x.root.loaded, false)
})
console.log(passed + ' lifecycle tests passed')
