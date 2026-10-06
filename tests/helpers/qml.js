// Execute the actual root QML JavaScript methods with injected services/timers.
// This exercises async orchestration, not QML bindings or desktop rendering.
'use strict'
const fs = require('fs')
const path = require('path')
const vm = require('vm')
const base = path.join(__dirname, '..', '..')
function library(file, imports) {
  const context = vm.createContext(imports || {})
  vm.runInContext(fs.readFileSync(path.join(base, file), 'utf8').replace(/^\.(pragma|import).*$/mg, ''), context, { filename: file })
  return context
}
const Model = library('Model.js')
const Scanner = library('Scanner.js', { Model })
const Scripts = library('Scripts.js')
function methods(file, root, globals) {
  const context = vm.createContext(Object.assign({ root, Model, Scanner, Scripts, console }, globals || {}))
  const source = fs.readFileSync(path.join(base, file), 'utf8')
  // Root methods have two-space indentation; nested QML component methods do not.
  const blocks = source.match(/^  function \w+\([^\n]*\) \{[\s\S]*?^  \}/gm) || []
  if (!blocks.length) throw new Error('No root methods found in ' + file)
  for (const block of blocks) {
    const name = /function (\w+)/.exec(block)[1]
    vm.runInContext(block, context, { filename: file + ':' + name })
    root[name] = context[name]
  }
  return root
}
module.exports = { Model, Scanner, Scripts, methods }
