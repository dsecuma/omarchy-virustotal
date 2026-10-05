'use strict'
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process')
const { Scanner, Scripts } = require('./helpers/qml')
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omarchy-vt-files-'))
let passed = 0
function test(name, fn) { fn(); passed++; console.log('ok ' + name) }
try {
  for (const shell of ['sh', 'bash', 'dash']) {
    const base = path.join(tmp, shell), dir = path.join(base, '-plugin')
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(dir + '/old', 'old'); fs.writeFileSync(dir + '/new', 'new')
    fs.utimesSync(dir + '/old', 1000, 1000); fs.utimesSync(dir + '/new', 2000, 2000)
    const stamp = () => cp.execFileSync(shell, ['-c', Scripts.probePlugins, 'sh', base], { encoding: 'utf8' }).split('\t')[2]
    test(shell + ': unchanged tree is stable, including a leading-dash directory', () => {
      assert.match(stamp(), /^[a-f0-9]{64}$/); assert.equal(stamp(), stamp())
    })
    test(shell + ': same-size rewrite below the newest mtime changes the stamp', () => {
      const before = stamp(); fs.writeFileSync(dir + '/old', 'BAD'); fs.utimesSync(dir + '/old', 1500, 1500)
      assert.notEqual(stamp(), before)
    })
    test(shell + ': subsecond mtime changes are preserved', () => {
      const before = stamp(); fs.utimesSync(dir + '/old', 1500.25, 1500.25); assert.notEqual(stamp(), before)
    })
    test(shell + ': rename with unchanged size/time changes the stamp', () => {
      const before = stamp(); fs.renameSync(dir + '/old', dir + '/renamed'); assert.notEqual(stamp(), before)
    })
    test(shell + ': .git and symlink target changes do not affect the stamp', () => {
      fs.mkdirSync(dir + '/.git'); fs.writeFileSync(dir + '/.git/config', 'old')
      fs.writeFileSync(base + '/outside', 'old'); fs.symlinkSync(base + '/outside', dir + '/link')
      const before = stamp(); fs.writeFileSync(dir + '/.git/config', 'new'); fs.writeFileSync(base + '/outside', 'new')
      assert.equal(stamp(), before)
    })
    test(shell + ': tabs and newlines cannot split metadata records', () => {
      const before = stamp(); fs.writeFileSync(dir + '/a\tb\nc', 'x')
      assert.notEqual(stamp(), before); assert.equal(stamp(), stamp())
    })
  }
  test('prototype-like filenames survive parsing, persistence, diff and scheduling', () => {
    const names = ['__proto__', 'constructor', 'toString']
    const text = names.map((name, i) => String(i + 1).repeat(64) + '\t1\t' + name).join('\n')
    const parsed = Scanner.parseHashList(text)
    assert.deepEqual(Object.keys(parsed.files).sort(), names.sort()); assert.equal(parsed.count, 3)
    const state = Scanner.parseState('')
    state.plugins.__proto__ = { id: '__proto__', files: parsed.files }
    const restored = Scanner.parseState(Scanner.serializeState(state))
    assert.deepEqual(Object.keys(restored.plugins), ['__proto__'])
    assert.deepEqual(Object.keys(restored.plugins.__proto__.files).sort(), names)
    const tasks = Scanner.tasksFor(restored.plugins.__proto__, '/fake', {}, {}, Date.now(), {})
    assert.equal(tasks.length, 3)
    assert.equal(Scanner.diffPlugin(null, restored.plugins.__proto__.files).changed.length, 3)
  })
  console.log(passed + ' filesystem tests passed')
} finally { fs.rmSync(tmp, { recursive: true, force: true }) }
