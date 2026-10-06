// A checked URL can carry a private token in its path, query or fragment.
// Other local users can read process arguments, so such a URL must never be
// part of any command line the plugin starts: the lookup body goes to curl on
// stdin, and notifications / agent hand-offs only carry scheme + host.
'use strict'
const test = require('node:test')
const assert = require('node:assert/strict')
const { Model, methods } = require('./helpers/qml')
const fs = require('fs')
const path = require('path')
const vm = require('vm')

const SECRET = 'rst_5f0c1d2e3a4b'
const URL = 'https://accounts.example.com/reset/' + SECRET + '?token=' + SECRET + '#access_token=' + SECRET
const ID = 'a'.repeat(64)

function service() {
  const root = { missingTools: '', userAgent: 'test', authHeaderPath: '/fake/header', apiKeyPath: '/fake/key',
                 apiBase: 'https://ai.virustotal.invalid/api/v3', classicApiBase: 'https://www.virustotal.invalid/api/v3',
                 omarchyPath: '/fake/omarchy', pluginId: 'io.github.dsecuma.virustotal', standalone: false }
  methods('Service.qml', root)
  return root
}

function argvLeaks(argv) {
  return argv.some(a => String(a).indexOf(SECRET) >= 0)
}

test('URL lookup body travels on stdin, never in curl argv', () => {
  const root = service()
  const req = Model.requestFor('url', URL)
  let seen = null
  root.runJob = (argv, timeout, cb, stdinText) => {
    seen = { argv, stdinText }
    cb(0, '{"data":{}}\n200\n')
  }
  let response
  root.api(req.method, req.path, { json: req.json }, r => { response = r })
  assert.ok(seen, 'curl was started')
  assert.equal(argvLeaks(seen.argv), false, 'no part of the URL is in argv')
  assert.equal(seen.argv.indexOf('--data-raw'), -1)
  assert.equal(seen.argv[seen.argv.indexOf('--data-binary') + 1], '@-')
  assert.deepEqual(JSON.parse(seen.stdinText), { url: URL })
  assert.equal(response.http, 200)
})

test('requests without a body still send no stdin', () => {
  const root = service()
  let stdin = 'unset'
  root.runJob = (argv, timeout, cb, stdinText) => { stdin = stdinText; cb(0, '{}\n200\n') }
  root.api('GET', '/files/' + ID, {}, () => {})
  assert.equal(stdin, '')
})

test('the only --data-raw left is the token-free registration body', () => {
  // Guard against new argv request bodies sneaking back in.
  const base = path.join(__dirname, '..')
  for (const file of ['Service.qml', 'PluginScanner.qml', 'AgentsManager.qml', 'Scripts.js']) {
    const src = fs.readFileSync(path.join(base, file), 'utf8')
    const hits = src.split('\n').filter(l => /--data-raw/.test(l))
    if (file === 'Scripts.js') {
      assert.equal(hits.length, 1, 'only Scripts.register uses --data-raw')
      assert.match(hits[0], /\$body/)
    } else {
      assert.equal(hits.length, 0, file + ' must not pass request bodies in argv')
    }
  }
  assert.doesNotMatch(Model.registerBody('1.1.9'), /token|secret/i)
})

test('redactUrl keeps only scheme and host', () => {
  assert.equal(Model.redactUrl(URL), 'https://accounts.example.com/\u2026')
  assert.equal(Model.redactUrl('http://example.com'), 'http://example.com')
  assert.equal(Model.redactUrl('http://example.com/'), 'http://example.com')
  assert.equal(Model.redactUrl('HTTP://Example.com:8080?q=1'), 'http://Example.com:8080/\u2026')
  assert.equal(Model.redactUrl('https://example.com#frag'), 'https://example.com/\u2026')
  assert.equal(Model.redactUrl('https://user:pw@example.com/x'), 'https://example.com/\u2026')
  assert.equal(Model.redactUrl('not a url'), '')
})

test('URL notifications passed to notify-send carry no path, query or fragment', () => {
  const root = service()
  let argv = null
  const Quickshell = { execDetached: a => { argv = a } }
  // notifyMessage calls Quickshell.execDetached; rebind with that global.
  const src = fs.readFileSync(path.join(__dirname, '..', 'Service.qml'), 'utf8')
  const block = /^  function notifyMessage\([^\n]*\) \{[\s\S]*?^  \}/m.exec(src)[0]
  const ctx = vm.createContext({ root, Scripts: {}, Quickshell })
  vm.runInContext(block, ctx)
  const found = Model.resultFromReport('url', URL, { id: ID, last_analysis_stats: { malicious: 2, harmless: 60 } }, { source: 'manual' })
  const unknown = Model.notFoundResult('url', URL, { source: 'manual' })
  const clean = Model.resultFromReport('url', URL, { id: ID, last_analysis_stats: { harmless: 60 } }, { source: 'manual' })
  for (const r of [found, unknown, clean]) {
    const n = Model.notificationFor(r)
    ctx.notifyMessage(n)
    assert.ok(argv, 'notification started')
    assert.equal(argvLeaks(argv), false, n.title)
    assert.match(n.title, /accounts\.example\.com\/\u2026$/)
  }
})

test('URL report links identify the URL by its VirusTotal ID only', () => {
  const leaky = 'https://www.virustotal.com/gui/search/' + encodeURIComponent(URL)
  let r = Model.resultFromReport('url', URL, { id: ID, report_url: leaky, last_analysis_stats: { harmless: 1 } }, {})
  assert.equal(r.reportUrl, 'https://www.virustotal.com/gui/url/' + ID)
  r = Model.resultFromReport('url', URL, { id: ID, report_url: 'https://www.virustotal.com/gui/url/' + ID + '/detection', last_analysis_stats: {} }, {})
  assert.equal(r.reportUrl, 'https://www.virustotal.com/gui/url/' + ID + '/detection')
  r = Model.resultFromReport('url', URL, { id: 'not-an-id', report_url: leaky, last_analysis_stats: {} }, {})
  assert.equal(r.reportUrl, '')
  assert.equal(Model.notFoundResult('url', URL, {}).reportUrl, '')
  // Domains, IPs and files keep their usual links.
  assert.equal(Model.resultFromReport('domain', 'example.com', { id: 'example.com', last_analysis_stats: {} }, {}).reportUrl,
               'https://www.virustotal.com/gui/domain/example.com')
})
