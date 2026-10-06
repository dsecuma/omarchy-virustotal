'use strict'
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process'), crypto = require('crypto')
const { Model, Scripts, methods } = require('./helpers/qml')
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omarchy-vt-upload-test-'))
const snapshots = []
const digest = data => crypto.createHash('sha256').update(data).digest('hex')
let passed = 0
function test(name, fn) { fn(); passed++; console.log('ok ' + name) }
function run(shell, script, args, env) {
  return cp.spawnSync(shell, ['-c', script, 'sh'].concat(args), { encoding: 'utf8', env: Object.assign({ PATH: process.env.PATH }, env || {}) })
}
try {
  const original = path.join(tmp, 'original ; $(touch nope),with\ttab')
  for (const shell of ['sh', 'bash', 'dash']) {
    let snapshot
    test(shell + ': prepare private bounded bytes matching the consented hash', () => {
      fs.writeFileSync(original, 'approved sample\n')
      const prepared = run(shell, Scripts.prepareUpload, [original, digest('approved sample\n')])
      assert.equal(prepared.status, 0, prepared.stderr)
      const m = /^(\d+)\t(.+)\n$/.exec(prepared.stdout)
      assert.ok(m); snapshot = m[2]; snapshots.push(snapshot)
      assert.equal(Number(m[1]), 16)
      assert.equal(fs.statSync(snapshot).mode & 0o777, 0o600)
      assert.equal(fs.statSync(path.dirname(snapshot)).mode & 0o777, 0o700)
      fs.writeFileSync(original, 'changed original')
      assert.equal(fs.readFileSync(snapshot, 'utf8'), 'approved sample\n')
    })
    test(shell + ': classic sends the snapshot even after the original is replaced', () => {
      const bin = path.join(tmp, shell + '-bin'); fs.mkdirSync(bin)
      const capture = path.join(tmp, shell + '-body')
      fs.writeFileSync(bin + '/curl', '#!/bin/sh\ncat > "$CAPTURE"\nprintf \'{"data":{"type":"analysis","id":"test"}}\\n200\\nretry-after:\'\n', { mode: 0o755 })
      const sent = run(shell, Scripts.classicUpload, [snapshot, '/fake/key', 'https://example.invalid', 'test', '5'], { PATH: bin + ':' + process.env.PATH, CAPTURE: capture })
      assert.equal(sent.status, 0); assert.equal(fs.readFileSync(capture, 'utf8'), 'approved sample\n')
      assert.equal(Model.parseCurlOutput(sent.stdout).http, 200)
      assert.equal(run(shell, Scripts.removeUpload, [snapshot]).status, 0)
      assert.equal(fs.existsSync(path.dirname(snapshot)), false)
    })
    test(shell + ': rejects changed bytes, symlinks, empty and oversize files before sending', () => {
      const before = fs.readdirSync('/tmp').filter(n => /^omarchy-vt-upload\.[A-Za-z0-9]{8}$/.test(n)).sort()
      fs.writeFileSync(original, 'different')
      assert.equal(run(shell, Scripts.prepareUpload, [original, digest('approved sample\n')]).status, 6)
      const link = path.join(tmp, shell + '-link'); fs.symlinkSync(original, link)
      assert.equal(run(shell, Scripts.prepareUpload, [link, digest('different')]).status, 3)
      fs.writeFileSync(original, '')
      assert.equal(run(shell, Scripts.prepareUpload, [original, digest('')]).status, 7)
      fs.truncateSync(original, 32000001)
      assert.equal(run(shell, Scripts.prepareUpload, [original, digest('irrelevant')]).status, 8)
      const after = fs.readdirSync('/tmp').filter(n => /^omarchy-vt-upload\.[A-Za-z0-9]{8}$/.test(n)).sort()
      assert.deepEqual(after, before, 'failed preparations clean their private directories')
    })
    test(shell + ': cleanup refuses unrelated files', () => {
      assert.equal(run(shell, Scripts.removeUpload, [original]).status, 2)
      assert.ok(fs.existsSync(original))
    })
  }
  test('manual upload uses the verified copy and cleans it on an uncertain response', () => {
    const sha = digest('approved'), snapshot = '/tmp/omarchy-vt-upload.Fake1234/sample'
    const root = { connected: true, busy: false, accountBusy: false, _scanSeq: 0,
      result: { canUpload: true, path: '/fake/original', sha256: sha, name: 'original' } }
    methods('Service.qml', root)
    let prepare, respond, removed, handled
    root.prepareUploadFile = (p, h, cb) => { assert.equal(h, sha); prepare = cb }
    root.api = (method, url, opts, cb) => { assert.equal(opts.file, snapshot); assert.equal(url, '/submissions/' + sha); respond = cb }
    root.removeUploadFile = p => { removed = p }
    root.handleSubmission = (base, res) => { handled = res }
    root.confirmUpload(); prepare(0, 8, snapshot); respond({ http: 0, exitCode: 28 })
    assert.equal(removed, snapshot); assert.equal(handled.http, 0); assert.equal(root.busy, false)
  })
  test('manual preparation cancelled by a changed scan or connection never sends', () => {
    for (const reason of ['scan', 'connection']) {
      const root = { connected: true, busy: false, accountBusy: false, _scanSeq: 0,
        result: { canUpload: true, path: '/fake/original', sha256: digest('approved') } }
      methods('Service.qml', root)
      let prepare, removed = false
      root.prepareUploadFile = (p, h, cb) => { prepare = cb }
      root.api = () => assert.fail('unexpected upload')
      root.removeUploadFile = () => { removed = true }
      root.confirmUpload()
      if (reason === 'scan') root._scanSeq++; else root.connected = false
      prepare(0, 8, '/tmp/omarchy-vt-upload.Fake1234/sample'); assert.equal(removed, true)
    }
  })
  test('VTAI transport opens the provided snapshot, never the original path', () => {
    const snapshot = '/tmp/omarchy-vt-upload.Fake1234/sample'
    const root = { missingTools: '', userAgent: 'test', authHeaderPath: '/fake/header', apiBase: 'https://example.invalid' }
    methods('Service.qml', root)
    root.runJob = (argv, timeout, cb) => {
      assert.equal(argv[argv.indexOf('--data-binary') + 1], '@' + snapshot)
      cb(0, '{"status":"submitted"}\n202\nretry-after:')
    }
    root.api('POST', '/submissions/' + digest('approved'), { file: snapshot }, r => assert.equal(r.http, 202))
  })
  console.log(passed + ' upload snapshot tests passed')
} finally {
  for (const snapshot of snapshots) if (fs.existsSync(snapshot)) run('sh', Scripts.removeUpload, [snapshot])
  fs.rmSync(tmp, { recursive: true, force: true })
}
